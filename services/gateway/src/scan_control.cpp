#include "scan_control.hpp"

#include <algorithm>
#include <fstream>
#include <filesystem>
#include <set>
#include <sstream>
#include <streambuf>
#include <thread>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>

#include "planner.hpp"
#include "proculus/netutil/ipset.hpp"
#include "proculus/netutil/portset.hpp"
#include "proculus/netutil/target.h"

namespace proculus {

namespace {

constexpr size_t kMaxTargets = 200, kMaxExclusions = 100, kMaxSpecLength = 200, kLogLines = 200, kLogLineLength = 300;

[[noreturn]] void bad(const std::string& why) { throw ApiError(400, why); }

std::string trim(const std::string& s) {
	const size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
	return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

std::vector<std::string> string_list(const Json& body, const char* key, size_t max) {
	std::vector<std::string> out;
	auto it = body.find(key);
	if (it == body.end()) return out;
	if (!it->is_array()) bad(std::string("\"") + key + "\" must be a list");
	if (it->size() > max) bad(std::string("\"") + key + "\" has more than " + std::to_string(max) + " entries");
	for (const Json& e : *it) {
		if (!e.is_string()) bad(std::string("\"") + key + "\" must hold strings");
		const std::string s = trim(e.get<std::string>());
		if (s.empty()) continue;
		if (s.size() > kMaxSpecLength) bad("an entry in \"" + std::string(key) + "\" is too long");
		for (unsigned char c : s)
			if (c < 0x20 || c == 0x7f) bad("an entry in \"" + std::string(key) + "\" has control characters");
		out.push_back(s);
	}
	return out;
}

long long whole(const Json& body, const char* key, long long fallback, long long lo, long long hi) {
	auto it = body.find(key);
	if (it == body.end()) return fallback;
	if (!it->is_number_integer()) bad(std::string("\"") + key + "\" must be a whole number");
	const long long v = it->get<long long>();
	if (v < lo || v > hi) bad(std::string("\"") + key + "\" must be " + std::to_string(lo) + ".." + std::to_string(hi));
	return v;
}

bool flag(const Json& body, const char* key) {
	auto it = body.find(key);
	if (it == body.end()) return false;
	if (!it->is_boolean()) bad(std::string("\"") + key + "\" must be true or false");
	return it->get<bool>();
}

// A std::ostream that keeps the last lines written to it.
class LineLog : public std::streambuf {
public:
	std::vector<std::string> tail() const {
		std::lock_guard<std::mutex> l(m_);
		return {lines_.begin(), lines_.end()};
	}
	void clear() {
		std::lock_guard<std::mutex> l(m_);
		lines_.clear();
		partial_.clear();
		total_ = 0;
	}
	// lines written since the last clear(): lets a reader fetch only what is new
	size_t total() const {
		std::lock_guard<std::mutex> l(m_);
		return total_;
	}

protected:
	int_type overflow(int_type ch) override {
		if (ch == traits_type::eof()) return ch;
		std::lock_guard<std::mutex> l(m_);
		if (ch == '\n') {
			lines_.push_back(partial_.substr(0, kLogLineLength));
			total_++;
			if (lines_.size() > kLogLines) lines_.pop_front();
			partial_.clear();
		} else if (partial_.size() < 4 * kLogLineLength) {
			partial_.push_back(static_cast<char>(ch));
		}
		return ch;
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		for (std::streamsize i = 0; i < n; i++) overflow(static_cast<unsigned char>(s[i]));
		return n;
	}

private:
	mutable std::mutex m_;
	std::deque<std::string> lines_;
	std::string partial_;
	size_t total_ = 0;
};

Json request_json(const ScanRequest& r) {
	return {{"targets", r.targets}, {"exclusions", r.exclusions}, {"ports", r.ports}, {"workers", r.workers}, {"rate", r.rate}, {"timing", r.timing},
		{"web", r.web}, {"privileged", r.privileged}};
}

// Throws std::invalid_argument saying what is wrong with an enabled policy.
void check_policy(const ScanPolicy& p) {
	if (!p.enabled) return;
	if (p.scope.empty()) throw std::invalid_argument("give the scope: the addresses scans may touch");
	if (p.allowed_ports.empty()) throw std::invalid_argument("give the ports scans may probe");
	if (p.max_workers < 1 || p.max_workers > 64) throw std::invalid_argument("workers must be 1..64");
	if (p.max_rate < 1 || p.max_rate > 100000) throw std::invalid_argument("the packet rate must be 1..100000");
	IpSet scope;
	PortSet ports;
	try {
		scope.add_list(p.scope);
	} catch (const std::invalid_argument&) {
		throw std::invalid_argument("the scope is not a list of IPs, CIDRs or ranges");
	}
	try {
		ports.add_list(p.allowed_ports);
	} catch (const std::invalid_argument&) {
		throw std::invalid_argument("the allowed ports are not a port list such as 22,80,443");
	}
	if (!p.ceiling.empty()) {
		IpSet ceiling;
		ceiling.add_list(p.ceiling); // checked at start-up
		scope.subtract(ceiling);
		if (scope.count() > 0) throw std::invalid_argument("the scope goes beyond what this server allows (" + p.ceiling + ")");
	}
}

Json preset_json(const ScanPreset& pr) {
	Json j = request_json(pr.request);
	j["name"] = pr.name;
	return j;
}

Json settings_json(const ScanPolicy& p) {
	return {{"enabled", p.enabled}, {"scope", p.scope}, {"allowed_ports", p.allowed_ports}, {"max_workers", p.max_workers}, {"max_rate", p.max_rate},
		{"allow_privileged", p.allow_privileged}, {"allow_web", p.allow_web}, {"allow_reserved", p.allow_reserved}};
}

std::string text_setting(const Json& v, const char* key) {
	if (!v.is_string()) bad(std::string("\"") + key + "\" must be text");
	const std::string s = trim(v.get<std::string>());
	if (s.size() > 500) bad(std::string("\"") + key + "\" is too long");
	for (unsigned char c : s)
		if (c < 0x20 || c == 0x7f) bad(std::string("\"") + key + "\" has control characters");
	return s;
}

bool bool_setting(const Json& v, const char* key) {
	if (!v.is_boolean()) bad(std::string("\"") + key + "\" must be true or false");
	return v.get<bool>();
}

// The policy with the keys present in `body` applied (nothing is validated here).
ScanPolicy apply_settings(ScanPolicy p, const Json& body) {
	if (!body.is_object()) bad("the settings must be a JSON object");
	static const std::set<std::string> known = {"enabled", "scope", "allowed_ports", "max_workers", "max_rate", "allow_privileged", "allow_web", "allow_reserved"};
	for (auto it = body.begin(); it != body.end(); ++it)
		if (!known.count(it.key())) bad("unknown setting \"" + it.key().substr(0, 40) + "\"");
	if (auto it = body.find("enabled"); it != body.end()) p.enabled = bool_setting(*it, "enabled");
	if (auto it = body.find("scope"); it != body.end()) p.scope = text_setting(*it, "scope");
	if (auto it = body.find("allowed_ports"); it != body.end()) p.allowed_ports = text_setting(*it, "allowed_ports");
	if (body.contains("max_workers")) p.max_workers = static_cast<unsigned>(whole(body, "max_workers", p.max_workers, 1, 64));
	if (body.contains("max_rate")) p.max_rate = static_cast<int>(whole(body, "max_rate", p.max_rate, 1, 100000));
	if (auto it = body.find("allow_privileged"); it != body.end()) p.allow_privileged = bool_setting(*it, "allow_privileged");
	if (auto it = body.find("allow_web"); it != body.end()) p.allow_web = bool_setting(*it, "allow_web");
	if (auto it = body.find("allow_reserved"); it != body.end()) p.allow_reserved = bool_setting(*it, "allow_reserved");
	return p;
}

} // namespace

ScanRequest parse_scan_request(const Json& body) {
	if (!body.is_object()) bad("the request must be a JSON object");
	static const std::set<std::string> known = {"targets", "exclusions", "ports", "workers", "rate", "timing", "web", "privileged"};
	for (auto it = body.begin(); it != body.end(); ++it)
		if (!known.count(it.key())) bad("unknown setting \"" + it.key().substr(0, 40) + "\"");

	ScanRequest r;
	r.targets = string_list(body, "targets", kMaxTargets);
	r.exclusions = string_list(body, "exclusions", kMaxExclusions);
	if (auto it = body.find("ports"); it != body.end()) {
		if (!it->is_string() || it->get<std::string>().size() > 200) bad("\"ports\" must be a port list such as \"22,80,443\"");
		r.ports = trim(it->get<std::string>());
	}
	r.workers = static_cast<unsigned>(whole(body, "workers", 2, 1, 64));
	r.rate = static_cast<int>(whole(body, "rate", 100, 1, 100000));
	r.timing = static_cast<int>(whole(body, "timing", 3, 0, 4));
	r.web = flag(body, "web");
	r.privileged = flag(body, "privileged");
	return r;
}

struct ScanController::Impl {
	ScanPolicy policy; // guarded by m (an administrator can change it while requests are validated)
	std::filesystem::path persist_file;
	ScanPolicy snapshot() const {
		std::lock_guard<std::mutex> l(m);
		return policy;
	}
	ResultStore* store;
	RunnerDeps base;
	SystemClock own_clock;
	LineLog log_buffer;
	std::ostream log{&log_buffer};

	mutable std::mutex m;
	std::thread worker;
	bool running = false, stopping = false;
	Runner* runner = nullptr; // valid while running
	ScanProgress progress;
	TimePoint started;
	ScanRequest current;
	Json last = nullptr;

	RunnerConfig validate(const ScanRequest& r) const { return validate(r, snapshot()); }
	RunnerConfig validate(const ScanRequest& r, const ScanPolicy& policy) const {
		if (!policy.enabled) throw ApiError(403, "scans are not enabled on this server");
		if (r.targets.empty()) bad("give at least one target");
		if (r.workers > policy.max_workers) bad("at most " + std::to_string(policy.max_workers) + " workers are allowed");
		if (r.rate > policy.max_rate) bad("the packet rate is limited to " + std::to_string(policy.max_rate) + " per second");
		if (r.privileged && !policy.allow_privileged) bad("privileged (raw socket) scans are not allowed on this server");
		if (r.web && !policy.allow_web) bad("web probing is not allowed on this server");

		IpSet scope;
		scope.add_list(policy.scope); // checked in the constructor
		for (const std::string& t : r.targets) {
			pc_target target;
			if (pc_target_parse(t.c_str(), &target) != 0) bad("not an IP, CIDR, range or domain: " + t);
			if (target.kind == PC_TARGET_DOMAIN) continue; // its addresses are checked against the scope when it is resolved
			IpSet one;
			one.add(target.range);
			one.subtract(scope);
			if (one.count() > 0) bad(t + " is outside the allowed scope (" + policy.scope + ")");
		}
		for (const std::string& x : r.exclusions) {
			IpSet probe;
			try {
				probe.add_spec(x);
			} catch (const std::invalid_argument&) {
				bad("not an IP, CIDR or range to exclude: " + x);
			}
		}
		if (!r.ports.empty()) {
			PortSet allowed, wanted;
			allowed.add_list(policy.allowed_ports);
			try {
				wanted.add_list(r.ports);
			} catch (const std::invalid_argument&) {
				bad("not a port list: " + r.ports);
			}
			const uint32_t want = wanted.count();
			wanted.intersect(allowed);
			if (wanted.count() != want) bad("ports outside the allowed list (" + policy.allowed_ports + ") were requested");
		}

		RunnerConfig c;
		c.scope = policy.scope;
		c.allowed_ports = policy.allowed_ports;
		c.targets = r.targets;
		c.exclusions = r.exclusions;
		c.ports = r.ports;
		c.allow_reserved = policy.allow_reserved;
		c.workers = r.workers;
		c.rate = r.rate;
		c.timing = r.timing;
		c.privileged = r.privileged;
		c.nmap_path = policy.nmap_path;
		c.web.enabled = r.web;
		if (policy.simulated) c.web.requests_per_second = 500; // made-up servers: no reason to be gentle
		c.web.signature_paths = policy.signature_paths;
		if (!policy.custom_signatures.empty()) {
			std::error_code ec;
			if (std::filesystem::is_regular_file(policy.custom_signatures, ec)) c.web.signature_paths.push_back(policy.custom_signatures);
		}
		return c;
	}

	void run(RunnerConfig cfg) {
		Json result;
		Runner* local = nullptr;
		try {
			RunnerDeps deps = base;
			if (!deps.clock) deps.clock = &own_clock;
			deps.store = store;
			deps.log = &log;
			deps.on_progress = [this](const ScanProgress& p) {
				std::lock_guard<std::mutex> l(m);
				progress = p;
			};
			Runner r(std::move(cfg), deps);
			{
				std::lock_guard<std::mutex> l(m);
				runner = local = &r;
				if (stopping) r.request_stop(); // stop was asked for before the runner existed
			}
			const RoundReport rep = r.run_round();
			result = {{"ok", true}, {"message", "finished"}, {"run_id", rep.run_id}, {"hosts", rep.live_hosts}, {"services", rep.services},
				{"web_responding", rep.web_responding}, {"detections", rep.detections}, {"pauses", rep.pauses}, {"warnings", rep.warnings}};
		} catch (const RunAborted&) {
			result = {{"ok", false}, {"message", "stopped; nothing was saved"}};
		} catch (const ScanError& e) {
			result = {{"ok", false}, {"message", std::string("scan failed: ") + e.what() + " (nothing was saved)"}};
		} catch (const std::exception& e) {
			result = {{"ok", false}, {"message", std::string("error: ") + e.what()}};
		}
		std::lock_guard<std::mutex> l(m);
		result["finished"] = format_time(std::chrono::system_clock::now());
		last = std::move(result);
		runner = nullptr;
		running = stopping = false;
		progress.stage = "idle";
	}
};

ScanController::ScanController(ScanPolicy policy, ResultStore* store, RunnerDeps base) : impl_(std::make_unique<Impl>()) {
	Impl& i = *impl_;
	i.policy = std::move(policy);
	i.store = store;
	i.base = std::move(base);
	if (!i.policy.ceiling.empty()) {
		IpSet probe;
		try {
			probe.add_list(i.policy.ceiling);
		} catch (const std::invalid_argument&) {
			throw std::invalid_argument("the scan ceiling is not a list of IPs, CIDRs or ranges");
		}
	}
	if (i.policy.enabled && !i.store) throw std::invalid_argument("scans need a result store");
	check_policy(i.policy);
}

ScanController::~ScanController() {
	{
		std::lock_guard<std::mutex> l(impl_->m);
		impl_->stopping = true;
		if (impl_->runner) impl_->runner->request_stop();
	}
	if (impl_->worker.joinable()) impl_->worker.join();
}

bool ScanController::enabled() const { return impl_->snapshot().enabled; }

namespace {

// Ready-made presets from this machine's own addresses.
std::vector<ScanPreset> make_builtin_presets() {
	std::vector<ScanPreset> out;
	ScanPreset local;
	local.name = "localhost";
	local.request.targets = {"127.0.0.1"};
	local.request.ports = "22,80,443,3000,5000,8000,8080,8443";
	out.push_back(local);
	ifaddrs* list = nullptr;
	if (getifaddrs(&list) != 0) return out;
	auto dotted = [](uint32_t v) { return std::to_string(v >> 24) + "." + std::to_string((v >> 16) & 255) + "." + std::to_string((v >> 8) & 255) + "." + std::to_string(v & 255); };
	std::set<std::string> seen;
	for (ifaddrs* a = list; a; a = a->ifa_next) {
		if (!a->ifa_addr || !a->ifa_netmask || a->ifa_addr->sa_family != AF_INET || !(a->ifa_flags & IFF_UP) || (a->ifa_flags & IFF_LOOPBACK)) continue;
		const uint32_t ip = ntohl(reinterpret_cast<sockaddr_in*>(a->ifa_addr)->sin_addr.s_addr);
		const uint32_t mask = ntohl(reinterpret_cast<sockaddr_in*>(a->ifa_netmask)->sin_addr.s_addr);
		int prefix = 0;
		for (uint32_t m = mask; m & 0x80000000u; m <<= 1) prefix++;
		if (prefix < 16 || prefix > 30 || (ip >> 24) == 169) continue; // very large networks and link-local addresses are not offered
		const std::string cidr = dotted(ip & mask) + "/" + std::to_string(prefix);
		if (!seen.insert(cidr).second) continue;
		ScanPreset hosts, net;
		hosts.name = "local hosts (" + cidr + ")"; // this machine and the usual address of the router; the user edits the list
		hosts.request.targets = {dotted(ip), dotted((ip & mask) + 1)};
		hosts.request.ports = "22,80,443,8080,8443";
		net.name = "whole local network (" + cidr + ")";
		net.request.targets = {cidr};
		net.request.ports = "22,80,443,8080,8443";
		out.push_back(hosts);
		out.push_back(net);
	}
	freeifaddrs(list);
	return out;
}

} // namespace

Json ScanController::builtin_presets() {
	static std::mutex m; // the status is polled every second: look at the interfaces only now and then
	static Json cached;
	static std::chrono::steady_clock::time_point at;
	std::lock_guard<std::mutex> l(m);
	const auto now = std::chrono::steady_clock::now();
	if (cached.is_null() || now - at > std::chrono::seconds(30)) {
		cached = Json::array();
		for (const ScanPreset& pr : make_builtin_presets()) cached.push_back(preset_json(pr));
		at = now;
	}
	return cached;
}

Json ScanController::settings() const {
	const ScanPolicy p = impl_->snapshot();
	Json j = settings_json(p);
	j["presets"] = builtin_presets();
	j["ceiling"] = p.ceiling;
	return j;
}

void ScanController::configure(const Json& body) {
	Impl& i = *impl_;
	ScanPolicy next = apply_settings(i.snapshot(), body);
	if (next.enabled && !i.store) bad("scans need a result store");
	try {
		check_policy(next);
	} catch (const std::invalid_argument& e) {
		bad(e.what());
	}
	std::lock_guard<std::mutex> l(i.m);
	if (!i.persist_file.empty()) {
		try {
			std::filesystem::create_directories(i.persist_file.parent_path());
			const std::filesystem::path tmp = i.persist_file.string() + ".tmp";
			{
				std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
				if (!out) throw std::runtime_error("cannot write " + tmp.string());
				::chmod(tmp.c_str(), 0600);
				out << settings_json(next).dump(2) << "\n";
				out.flush();
				if (!out) throw std::runtime_error("cannot write " + tmp.string());
			}
			std::filesystem::rename(tmp, i.persist_file);
		} catch (const std::exception& e) {
			throw ApiError(500, std::string("the settings could not be saved: ") + e.what());
		}
	}
	i.policy = std::move(next);
}

void ScanController::persist_to(std::filesystem::path file) {
	std::lock_guard<std::mutex> l(impl_->m);
	impl_->persist_file = std::move(file);
}

void ScanController::set_custom_signatures(const std::filesystem::path& file) {
	std::lock_guard<std::mutex> l(impl_->m);
	impl_->policy.custom_signatures = file.string();
}

bool ScanController::load_settings(std::string* problem) {
	Impl& i = *impl_;
	std::filesystem::path file;
	{
		std::lock_guard<std::mutex> l(i.m);
		file = i.persist_file;
	}
	std::error_code ec;
	if (file.empty() || !std::filesystem::exists(file, ec)) return false;
	try {
		std::ifstream in(file, std::ios::binary);
		std::stringstream text;
		text << in.rdbuf();
		ScanPolicy next = apply_settings(i.snapshot(), Json::parse(text.str()));
		check_policy(next);
		std::lock_guard<std::mutex> l(i.m);
		i.policy = std::move(next);
		return true;
	} catch (const std::exception& e) { // ApiError, invalid_argument or a JSON error: keep what we have, scans stay as they were (off)
		if (problem) *problem = std::string(e.what());
		return false;
	}
}

Json ScanController::status() const {
	const Impl& i = *impl_;
	const ScanPolicy policy = i.snapshot();
	Json j = {{"enabled", policy.enabled}, {"simulated", policy.simulated}};
	if (!policy.enabled) return j;
	j["policy"] = {{"scope", policy.scope}, {"allowed_ports", policy.allowed_ports}, {"max_workers", policy.max_workers}, {"max_rate", policy.max_rate},
		{"allow_privileged", policy.allow_privileged}, {"allow_web", policy.allow_web}};
	j["policy"]["presets"] = builtin_presets();
	std::lock_guard<std::mutex> l(i.m);
	j["state"] = i.stopping ? "stopping" : i.running ? "running" : "idle";
	if (i.running) {
		const double elapsed = std::chrono::duration<double>(std::chrono::system_clock::now() - i.started).count();
		j["current"] = {{"started", format_time(i.started)}, {"elapsed_seconds", static_cast<long long>(elapsed)}, {"stage", i.progress.stage},
			{"chunks_done", i.progress.chunks_done}, {"chunks_total", i.progress.chunks_total}, {"hosts_found", i.progress.hosts_found},
			{"pauses", i.progress.pauses}, {"request", request_json(i.current)}};
		Json recent = Json::array();
		for (const LiveHost& h : i.progress.recent) recent.push_back({{"ip", h.ip}, {"ports", h.ports}, {"ports_total", h.ports_total}, {"ports_done", h.ports_done}, {"explored", h.explored}});
		j["current"]["recent_hosts"] = std::move(recent);
	}
	j["last"] = i.last;
	j["log"] = i.log_buffer.tail();
	j["log_total"] = i.log_buffer.total();
	return j;
}

Json ScanController::plan(const ScanRequest& r) const {
	const RunnerConfig cfg = impl_->validate(r);
	PlannerConfig pc;
	pc.exclusions = cfg.exclusions;
	pc.workers = cfg.workers;
	pc.chunk_seconds = cfg.chunk_seconds;
	pc.rate_hosts_per_sec = cfg.assumed_discovery_rate;
	pc.allow_reserved = cfg.allow_reserved;
	std::string text;
	for (const std::string& t : cfg.targets) text += t + "\n";
	std::istringstream in(text);
	const Plan p = make_plan(in, pc);
	Json warnings = Json::array();
	for (const LineError& e : p.errors) warnings.push_back("ignored (" + e.reason + "): " + e.text);
	return {{"addresses", p.total_addresses}, {"domains", p.domains.size()}, {"chunks", p.chunks.size()}, {"chunk_size", p.chunk_size},
		{"excluded", p.excluded_addresses}, {"reserved_removed", p.reserved_addresses}, {"discovery_estimate_seconds", static_cast<long long>(p.estimated_seconds)},
		{"workers", cfg.workers}, {"rate", cfg.rate}, {"warnings", warnings}};
}

void ScanController::start(const ScanRequest& r) {
	Impl& i = *impl_;
	RunnerConfig cfg = i.validate(r);
	std::lock_guard<std::mutex> l(i.m);
	if (i.running) throw ApiError(409, "a scan is already running");
	if (i.worker.joinable()) i.worker.join(); // the previous one has finished
	i.running = true;
	i.stopping = false;
	i.current = r;
	i.started = std::chrono::system_clock::now();
	i.progress = ScanProgress();
	i.progress.stage = "starting";
	i.log_buffer.clear();
	i.log << "scan requested: " << r.targets.size() << " target(s), " << r.workers << " worker(s), " << r.rate << " packets/s" << (r.web ? ", web" : "") << std::endl;
	i.worker = std::thread([&i, c = std::move(cfg)]() mutable { i.run(std::move(c)); });
}

void ScanController::stop() {
	std::lock_guard<std::mutex> l(impl_->m);
	if (!impl_->running) return;
	impl_->stopping = true;
	if (impl_->runner) impl_->runner->request_stop();
}

void ScanController::wait_idle() {
	for (;;) {
		{
			std::lock_guard<std::mutex> l(impl_->m);
			if (!impl_->running) break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	std::lock_guard<std::mutex> l(impl_->m);
	if (impl_->worker.joinable()) impl_->worker.join();
}

} // namespace proculus
