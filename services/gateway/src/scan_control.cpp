#include "scan_control.hpp"

#include <algorithm>
#include <set>
#include <sstream>
#include <streambuf>
#include <thread>

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
	ScanPolicy policy;
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

	RunnerConfig validate(const ScanRequest& r) const {
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
		c.web.signature_paths = policy.signature_paths;
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
	if (i.policy.enabled) {
		if (!i.store) throw std::invalid_argument("scans need a result store");
		if (i.policy.scope.empty() || i.policy.allowed_ports.empty()) throw std::invalid_argument("scans need a scope and allowed ports");
		if (i.policy.max_workers < 1 || i.policy.max_rate < 1) throw std::invalid_argument("scan ceilings must be at least 1");
		IpSet scope;
		PortSet ports;
		try {
			scope.add_list(i.policy.scope);
			ports.add_list(i.policy.allowed_ports);
		} catch (const std::invalid_argument&) {
			throw std::invalid_argument("the scan scope or allowed ports are invalid");
		}
	}
}

ScanController::~ScanController() {
	{
		std::lock_guard<std::mutex> l(impl_->m);
		impl_->stopping = true;
		if (impl_->runner) impl_->runner->request_stop();
	}
	if (impl_->worker.joinable()) impl_->worker.join();
}

bool ScanController::enabled() const { return impl_->policy.enabled; }

Json ScanController::status() const {
	const Impl& i = *impl_;
	Json j = {{"enabled", i.policy.enabled}};
	if (!i.policy.enabled) return j;
	j["policy"] = {{"scope", i.policy.scope}, {"allowed_ports", i.policy.allowed_ports}, {"max_workers", i.policy.max_workers}, {"max_rate", i.policy.max_rate},
		{"allow_privileged", i.policy.allow_privileged}, {"allow_web", i.policy.allow_web}};
	std::lock_guard<std::mutex> l(i.m);
	j["state"] = i.stopping ? "stopping" : i.running ? "running" : "idle";
	if (i.running) {
		const double elapsed = std::chrono::duration<double>(std::chrono::system_clock::now() - i.started).count();
		j["current"] = {{"started", format_time(i.started)}, {"elapsed_seconds", static_cast<long long>(elapsed)}, {"stage", i.progress.stage},
			{"chunks_done", i.progress.chunks_done}, {"chunks_total", i.progress.chunks_total}, {"hosts_found", i.progress.hosts_found},
			{"pauses", i.progress.pauses}, {"request", request_json(i.current)}};
		Json recent = Json::array();
		for (const LiveHost& h : i.progress.recent) recent.push_back({{"ip", h.ip}, {"ports", h.ports}});
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
