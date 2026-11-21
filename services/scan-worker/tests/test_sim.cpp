#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <set>

#include "proculus/netutil/ipset.hpp"
#include "sim_network.hpp"

using namespace proculus;

static uint32_t ip(const char* s) {
	uint32_t v;
	assert(pc_ip_parse(s, &v) == 0);
	return v;
}

static const char* kNet = "10.50.0.0/22";

static JobLimits limits() {
	JobLimits l;
	l.scope = "10.50.0.0/16";
	l.allowed_ports = "22,25,80,443,554,993,3306,5432,8080,8443";
	return l;
}

static void test_generation() {
	SimNetwork a = SimNetwork::generate(7, kNet, 0.2), b = SimNetwork::generate(7, kNet, 0.2);
	SimNetwork c = SimNetwork::generate(8, kNet, 0.2);

	// same seed -> same network, different seed -> different one
	assert(a.host_count() == b.host_count() && a.host_count() > 100 && a.host_count() < 300);
	for (size_t i = 0; i < a.host_count(); i++) {
		assert(a.hosts()[i].ip == b.hosts()[i].ip && a.hosts()[i].hostname == b.hosts()[i].hostname);
		assert(a.hosts()[i].services.size() == b.hosts()[i].services.size());
	}
	bool differs = a.host_count() != c.host_count();
	for (size_t i = 0; !differs && i < a.host_count(); i++) differs = a.hosts()[i].ip != c.hosts()[i].ip;
	assert(differs);

	// hosts lie inside the ranges, sorted and unique, never on .0 / .255
	IpSet space;
	space.add_list(kNet);
	uint32_t prev = 0;
	for (const SimHost& h : a.hosts()) {
		assert(space.contains(h.ip) && h.ip > prev && (h.ip & 0xff) != 0 && (h.ip & 0xff) != 0xff);
		assert(!h.services.empty() && !h.hostname.empty());
		prev = h.ip;
		assert(a.find(h.ip) == &h);
	}
	assert(a.find(ip("10.50.0.0")) == nullptr && a.find(ip("8.8.8.8")) == nullptr);

	// density 0 -> nothing; scale: a /20 at 3% is a few hundred hosts
	assert(SimNetwork::generate(1, kNet, 0.0).host_count() == 0);
	size_t big = SimNetwork::generate(1, "10.20.0.0/20,10.30.0.0/20,172.16.8.0/20", 0.03).host_count();
	assert(big > 250 && big < 500);
}

static void test_availability() {
	SimNetwork n = SimNetwork::generate(11, "10.50.0.0/20", 0.3);
	int always = 0, flapping = 0, from = 0, until = 0;
	std::vector<const SimHost*> flappers;
	for (const SimHost& h : n.hosts()) {
		switch (h.availability) {
		case SimAvailability::Always:
			always++;
			for (int r = 1; r <= 5; r++) assert(n.is_up(h.ip, r));
			break;
		case SimAvailability::FromRound:
			from++;
			assert(h.edge_round >= 2);
			assert(!n.is_up(h.ip, h.edge_round - 1) && n.is_up(h.ip, h.edge_round) && n.is_up(h.ip, h.edge_round + 3));
			break;
		case SimAvailability::UntilRound:
			until++;
			assert(n.is_up(h.ip, 1) && n.is_up(h.ip, h.edge_round) && !n.is_up(h.ip, h.edge_round + 1));
			break;
		case SimAvailability::Flapping:
			flapping++;
			flappers.push_back(&h);
			break;
		}
	}
	assert(always > flapping && flapping > 0 && from > 0 && until > 0);

	// flapping: repeatable per (round, attempt), about half up, differs between rounds and attempts
	int up = 0, total = 0, round_varies = 0, attempt_varies = 0;
	for (const SimHost* h : flappers) {
		for (int r = 1; r <= 8; r++) {
			assert(n.is_up(h->ip, r, 1) == n.is_up(h->ip, r, 1));
			up += n.is_up(h->ip, r, 1);
			total++;
			attempt_varies += n.is_up(h->ip, r, 1) != n.is_up(h->ip, r, 2);
		}
		round_varies += n.is_up(h->ip, 1) != n.is_up(h->ip, 2) || n.is_up(h->ip, 2) != n.is_up(h->ip, 3);
	}
	assert(up > total * 0.35 && up < total * 0.65);
	assert(round_varies > 0 && attempt_varies > 0);

	assert(!n.is_up(ip("8.8.8.8"), 1)); // not a host at all
	assert(n.existing_hosts(1).size() <= n.existing_hosts(3).size() + static_cast<size_t>(until));
}

static void test_services_change_over_time() {
	SimNetwork n = SimNetwork::generate(5, "10.50.0.0/20", 0.3);
	int upgraded = 0, exposed = 0, plain = 0;
	for (const SimHost& h : n.hosts()) {
		for (const SimService& s : h.services) {
			if (s.upgrade_round > 0) {
				upgraded++;
				auto before = n.services(h.ip, s.upgrade_round - 1), after = n.services(h.ip, s.upgrade_round);
				auto find = [&](const std::vector<SimService>& v) {
					return std::find_if(v.begin(), v.end(), [&](const SimService& x) { return x.port == s.port; });
				};
				assert(find(before) != before.end() && find(after) != after.end());
				assert(find(before)->version == s.version && find(after)->version == s.upgraded_version);
				assert(s.version != s.upgraded_version);
			} else if (s.from_round > 1) {
				exposed++;
				auto has = [&](int round) {
					auto v = n.services(h.ip, round);
					return std::any_of(v.begin(), v.end(), [&](const SimService& x) { return x.port == s.port; });
				};
				assert(!has(s.from_round - 1) && has(s.from_round));
			} else {
				plain++;
			}
		}
		// no duplicate ports on a host
		std::set<uint16_t> ports;
		for (const SimService& s : h.services) assert(ports.insert(s.port).second);
	}
	assert(upgraded > 0 && exposed > 0 && plain > upgraded);
	assert(n.services(ip("8.8.8.8"), 1).empty());
}

static void test_backend_discovery_and_services() {
	SimNetwork net = SimNetwork::generate(3, kNet, 0.2);
	SimBackend be(net);
	be.set_round(2);

	ScanJob job;
	job.targets = "10.50.0.0/22";
	NmapCommand cmd = build_command(job, limits());
	NmapResult r = be.run(cmd, job);

	size_t expect_up = 0;
	for (const SimHost& h : net.hosts()) expect_up += net.is_up(h.ip, 2);
	assert(r.hosts.size() == expect_up && static_cast<size_t>(r.hosts_up) == expect_up);
	assert(static_cast<uint64_t>(r.hosts_up + r.hosts_down) == cmd.target_count);
	assert(r.elapsed_seconds > 0);
	for (const HostResult& h : r.hosts) {
		assert(h.state == "up" && h.ports.empty()); // discovery lists hosts, not ports
		uint32_t a;
		assert(pc_ip_parse(h.address.c_str(), &a) == 0 && net.is_up(a, 2));
	}

	// services stage: open ports of the hosts that answer
	ScanJob sj;
	sj.stage = Stage::Services;
	sj.targets = "10.50.0.0/22";
	NmapResult s = be.run(build_command(sj, limits()), sj);
	assert(s.hosts.size() == expect_up);
	size_t open = 0;
	for (const HostResult& h : s.hosts) {
		uint32_t a;
		assert(pc_ip_parse(h.address.c_str(), &a) == 0);
		assert(h.ports.size() == net.services(a, 2).size());
		for (const PortResult& p : h.ports) {
			assert(p.state == "open" && p.has_service && !p.service.product.empty() && !p.service.name.empty());
			open++;
		}
	}
	assert(open > 0);

	// only requested ports are reported
	sj.ports = "22";
	for (const HostResult& h : be.run(build_command(sj, limits()), sj).hosts)
		for (const PortResult& p : h.ports) assert(p.port == 22);

	// without version detection the product stays unknown
	sj.ports = "";
	sj.version_detect = false;
	for (const HostResult& h : be.run(build_command(sj, limits()), sj).hosts)
		for (const PortResult& p : h.ports) assert(p.service.product.empty() && !p.service.name.empty());
}

static void test_backend_time_model_and_rounds() {
	SimNetwork net = SimNetwork::generate(3, kNet, 0.2);
	SimSpeed speed;
	speed.discovery_addresses_per_sec = 100;
	SimBackend be(net, speed);

	ScanJob big, small;
	big.targets = "10.50.0.0/22";
	small.targets = "10.50.0.0/24";
	double t_big = be.run(build_command(big, limits()), big).elapsed_seconds;
	double t_small = be.run(build_command(small, limits()), small).elapsed_seconds;
	assert(t_big > 2.5 * t_small && t_big < 6.5 * t_small); // ~4x the addresses, +-20% jitter on each
	assert(t_big > 1024 / 100.0 * 0.7 && t_big < 1024 / 100.0 * 1.3);
	assert(be.run(build_command(small, limits()), small).elapsed_seconds == t_small); // repeatable

	// different rounds see different networks (appearing / disappearing / flapping hosts)
	be.set_round(1);
	std::set<std::string> r1, r3;
	for (const auto& h : be.run(build_command(big, limits()), big).hosts) r1.insert(h.address);
	be.set_round(3);
	for (const auto& h : be.run(build_command(big, limits()), big).hosts) r3.insert(h.address);
	assert(r1 != r3);
}

static void test_safety_gate_applies_to_simulation() {
	SimNetwork net = SimNetwork::generate(3, kNet, 0.2);
	SimBackend be(net);
	ScanJob job;
	job.targets = "10.51.0.0/24"; // outside the scope
	JobLimits tight = limits();
	tight.scope = "10.50.0.0/16";
	bool rejected = false;
	try { be.run(build_command(job, tight), job); } catch (const JobRejected&) { rejected = true; }
	assert(rejected);

	job.stage = Stage::Services;
	job.targets = "10.50.0.0/24";
	job.ports = "23"; // not allowed
	rejected = false;
	try { be.run(build_command(job, tight), job); } catch (const JobRejected&) { rejected = true; }
	assert(rejected);
}

int main() {
	test_generation();
	test_availability();
	test_services_change_over_time();
	test_backend_discovery_and_services();
	test_backend_time_model_and_rounds();
	test_safety_gate_applies_to_simulation();
	return 0;
}
