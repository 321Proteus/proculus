#include "sim_network.hpp"

#include <algorithm>
#include <random>

#include "proculus/netutil/ipset.hpp"
#include "proculus/netutil/portset.hpp"

namespace proculus {

namespace {

uint64_t mix(uint64_t x) { // splitmix64
	x += 0x9E3779B97F4A7C15ULL;
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
	x = (x ^ (x >> 27)) * 0x944049BB133111EBULL;
	return x ^ (x >> 31);
}

double unit(uint64_t h) {
	return static_cast<double>(h >> 11) / 9007199254740992.0;
} // [0, 1)

struct ServiceTemplate {
	uint16_t port;
	const char* name;
	const char* product;
	const char* old_version;
	const char* new_version;
	const char* extrainfo;
};

struct Role {
	const char* name;
	double weight;
	std::vector<ServiceTemplate> services;
};

const std::vector<Role>& roles() {
	static const std::vector<Role> r = {
		{ "web", 30,
			{ { 80, "http", "nginx", "1.24.0", "1.25.3", "" },
				{ 443, "https", "nginx", "1.24.0", "1.25.3", "" } } },
		{ "apache", 14,
			{ { 80, "http", "Apache httpd", "2.4.41", "2.4.58", "(Ubuntu)" },
				{ 443, "https", "Apache httpd", "2.4.41", "2.4.58",
					"(Ubuntu)" } } },
		{ "app", 12,
			{ { 8080, "http-proxy", "Apache Tomcat", "9.0.65", "10.1.18", "" },
				{ 22, "ssh", "OpenSSH", "8.2p1", "9.6p1",
					"Ubuntu Linux; protocol 2.0" } } },
		{ "ssh", 16,
			{ { 22, "ssh", "OpenSSH", "8.2p1", "9.6p1",
				"Ubuntu Linux; protocol 2.0" } } },
		{ "mysql", 6, { { 3306, "mysql", "MySQL", "5.7.42", "8.0.35", "" } } },
		{ "postgres", 4,
			{ { 5432, "postgresql", "PostgreSQL DB", "13.12", "15.5", "" } } },
		{ "mail", 5,
			{ { 25, "smtp", "Postfix smtpd", "3.4.13", "3.8.4", "" },
				{ 993, "imaps", "Dovecot imapd", "2.3.7", "2.3.21", "" } } },
		{ "camera", 8,
			{ { 80, "http", "GoAhead-Webs", "2.5.0", "2.5.0", "" },
				{ 554, "rtsp", "Hikvision rtspd", "1.0", "1.0", "" } } },
		{ "staging", 5,
			{ { 80, "http", "nginx", "1.18.0", "1.25.3", "" },
				{ 8443, "https-alt", "Jetty", "9.4.53", "11.0.18", "" } } },
	};
	return r;
}

// Admin / extra services that sometimes get exposed on a host later on.
const std::vector<ServiceTemplate>& extras() {
	static const std::vector<ServiceTemplate> e = {
		{ 8080, "http-proxy", "Jenkins", "2.426.1", "2.426.1", "admin panel" },
		{ 8443, "https-alt", "Grafana", "10.2.2", "10.2.2", "admin panel" },
	};
	return e;
}

bool has_port(const SimHost& h, uint16_t port) {
	return std::any_of(h.services.begin(), h.services.end(),
		[&](const SimService& s) { return s.port == port; });
}

} // namespace

SimNetwork SimNetwork::generate(
	uint64_t seed, const std::string& networks, double density) {
	SimNetwork net;
	net.seed_ = seed;

	IpSet space;
	space.add_list(networks);
	std::mt19937_64 rng(seed);
	std::uniform_real_distribution<double> dist(0.0, 1.0);

	double total_weight = 0;
	for (const Role& r : roles())
		total_weight += r.weight;

	int counter = 0;
	const size_t n = pc_ipset_range_count(space.raw());
	for (size_t i = 0; i < n; i++) {
		const pc_range r = pc_ipset_range_at(space.raw(), i);
		for (uint64_t ip = r.lo; ip <= r.hi; ip++) {
			if ((ip & 0xff) == 0 || (ip & 0xff) == 0xff)
				continue; // network / broadcast
			if (dist(rng) >= density) continue;

			// role
			double pick = dist(rng) * total_weight;
			const Role* role = &roles().back();
			for (const Role& cand : roles()) {
				if ((pick -= cand.weight) < 0) {
					role = &cand;
					break;
				}
			}

			SimHost h;
			h.ip = static_cast<uint32_t>(ip);
			h.role = role->name;
			h.hostname =
				std::string(role->name) + "-" + std::to_string(++counter);

			// behaviour over time
			const double b = dist(rng);
			if (b < 0.80) {
				h.availability = SimAvailability::Always;
			} else if (b < 0.88) {
				h.availability = SimAvailability::Flapping;
			} else if (b < 0.94) {
				h.availability = SimAvailability::FromRound;
				h.edge_round = 2 + static_cast<int>(dist(rng) * 2); // 2 or 3
			} else {
				h.availability = SimAvailability::UntilRound;
				h.edge_round = 1 + static_cast<int>(dist(rng) * 2); // 1 or 2
			}

			// services; sometimes one is upgraded in a later round
			const bool upgrade = dist(rng) < 0.15;
			const int upgrade_round = 2 + static_cast<int>(dist(rng) * 2);
			bool upgraded_one = false;
			for (const ServiceTemplate& t : role->services) {
				SimService s;
				s.port = t.port;
				s.name = t.name;
				s.product = t.product;
				s.version = t.old_version;
				s.extrainfo = t.extrainfo;
				if (upgrade && !upgraded_one &&
					std::string(t.old_version) != t.new_version) {
					s.upgrade_round = upgrade_round;
					s.upgraded_version = t.new_version;
					upgraded_one = true;
				}
				h.services.push_back(std::move(s));
			}

			// sometimes an extra admin service is exposed later
			if (dist(rng) < 0.07) {
				const ServiceTemplate& t =
					extras()[static_cast<size_t>(dist(rng) * extras().size()) %
						extras().size()];
				if (!has_port(h, t.port)) {
					SimService s;
					s.port = t.port;
					s.name = t.name;
					s.product = t.product;
					s.version = t.old_version;
					s.extrainfo = t.extrainfo;
					s.from_round = 2 + static_cast<int>(dist(rng) * 2);
					h.services.push_back(std::move(s));
				}
			}
			net.hosts_.push_back(std::move(h));
		}
	}
	return net;
}

const SimHost* SimNetwork::find(uint32_t ip) const {
	auto it = std::lower_bound(hosts_.begin(), hosts_.end(), ip,
		[](const SimHost& h, uint32_t v) { return h.ip < v; });
	return (it != hosts_.end() && it->ip == ip) ? &*it : nullptr;
}

bool SimNetwork::is_up(uint32_t ip, int round, int attempt) const {
	const SimHost* h = find(ip);
	if (!h) return false;
	switch (h->availability) {
	case SimAvailability::Always: return true;
	case SimAvailability::Flapping:
		return unit(mix(seed_ ^ mix(ip) ^
				   mix(static_cast<uint64_t>(round) * 1000003ULL +
					   static_cast<uint64_t>(attempt)))) < 0.5;
	case SimAvailability::FromRound:  return round >= h->edge_round;
	case SimAvailability::UntilRound: return round <= h->edge_round;
	}
	return false;
}

std::vector<SimService> SimNetwork::services(uint32_t ip, int round) const {
	std::vector<SimService> out;
	const SimHost* h = find(ip);
	if (!h) return out;
	for (const SimService& s : h->services) {
		if (round < s.from_round || round > s.until_round) continue;
		SimService v = s;
		if (s.upgrade_round > 0 && round >= s.upgrade_round)
			v.version = s.upgraded_version;
		out.push_back(std::move(v));
	}
	return out;
}

std::vector<uint32_t> SimNetwork::existing_hosts(int round) const {
	std::vector<uint32_t> out;
	for (const SimHost& h : hosts_) {
		const bool exists = h.availability == SimAvailability::FromRound
			? round >= h.edge_round
			: h.availability == SimAvailability::UntilRound
			? round <= h.edge_round
			: true;
		if (exists) out.push_back(h.ip);
	}
	return out;
}

// ------------------------------------------------------------------ backend

NmapResult SimBackend::run(const NmapCommand& cmd, const ScanJob& job) {
	IpSet targets;
	targets.add_list(cmd.targets);

	PortSet ports;
	if (job.stage == Stage::Services && !cmd.ports.empty())
		ports.add_list(cmd.ports);

	NmapResult res;
	res.nmap_version = "sim";

	uint64_t scanned = 0, silent = 0;
	const size_t n = pc_ipset_range_count(targets.raw());
	for (size_t i = 0; i < n; i++) {
		const pc_range r = pc_ipset_range_at(targets.raw(), i);
		for (uint64_t ip64 = r.lo; ip64 <= r.hi; ip64++) {
			const uint32_t ip = static_cast<uint32_t>(ip64);
			scanned++;
			if (!net_.is_up(ip, round_)) {
				res.hosts_down++;
				silent++;
				continue;
			}
			res.hosts_up++;

			HostResult h;
			char buf[PC_IP_STR_MAX];
			pc_ip_format(ip, buf);

			h.address = buf;
			h.state = "up";
			h.reason = job.stage == Stage::Discovery ? "syn-ack" : "user-set";

			if (const SimHost* host = net_.find(ip))
				h.hostnames.push_back(host->hostname);

			if (job.stage == Stage::Services) {
				for (const SimService& s : net_.services(ip, round_)) {
					if (!ports.contains(s.port)) continue;
					PortResult p;

					p.port = s.port;
					p.protocol = "tcp";
					p.state = "open";
					p.reason = "syn-ack";
					p.has_service = true;
					p.service.name = s.name;
					p.service.method = "probed";

					if (job.version_detect) {
						p.service.product = s.product;
						p.service.version = s.version;
						p.service.extrainfo = s.extrainfo;
						p.service.confidence = 10;
					}

					h.ports.push_back(std::move(p));
				}
			}

			res.hosts.push_back(std::move(h));
		}
	}

	// Modelled duration, with a repeatable +-20% variation per command.
	const double jitter = 0.8 +
		0.4 *
			unit(mix(std::hash<std::string>{}(cmd.targets) ^
				static_cast<uint64_t>(round_)));
	double seconds;
	if (job.stage == Stage::Discovery) {
		seconds =
			static_cast<double>(scanned) / speed_.discovery_addresses_per_sec;
	} else {
		seconds = static_cast<double>(res.hosts_up) *
				speed_.service_seconds_per_host +
			static_cast<double>(silent) * speed_.silent_seconds_per_host;
	}
	res.elapsed_seconds = seconds * jitter;
	return res;
}

} // namespace proculus
