#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <mutex>
#include <set>
#include <thread>

#include "proculus/netutil/ipset.hpp"
#include "runner.hpp"
#include "sim_network.hpp"

using namespace proculus;
namespace fs = std::filesystem;

// ----------------------------------------------------------------- virtual time

class VirtualClock : public Clock {
public:
	explicit VirtualClock(TimePoint start) : now_(start) {}
	TimePoint now() override {
		std::lock_guard<std::mutex> l(m_);
		return now_;
	}
	bool sleep_until(TimePoint t, const std::atomic<bool>& stop) override {
		if (stop.load()) return false;
		advance_to(t);
		return true;
	}
	void advance_to(TimePoint t) {
		std::lock_guard<std::mutex> l(m_);
		if (t > now_) now_ = t;
	}

private:
	std::mutex m_;
	TimePoint now_;
};

// The simulated network on the virtual clock: a scan takes its modelled time, and
// is cut off when it would run past the window (what the real watchdog does).
// Meant for one worker.
class ClockedSim : public ScanBackend {
public:
	ClockedSim(const SimNetwork& net, VirtualClock& clock, Runner*& runner, SimSpeed speed = {}) : sim_(net, speed), clock_(clock), runner_(runner) {}
	NmapResult run(const NmapCommand& cmd, const ScanJob& job) override {
		const TimePoint start = clock_.now();
		NmapResult r = sim_.run(cmd, job);
		const TimePoint end = start + std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::duration<double>(r.elapsed_seconds));
		const auto dl = runner_ ? runner_->deadline() : std::nullopt;
		if (dl && end > *dl) {
			clock_.advance_to(*dl);
			throw ScanFailed("cut off by the closing window", false, true);
		}
		clock_.advance_to(end);
		return r;
	}

private:
	SimBackend sim_;
	VirtualClock& clock_;
	Runner*& runner_;
};

static TimePoint t0() { return parse_time("2026-11-21T21:00:00Z"); }

static RunnerConfig base_config(const std::string& networks) {
	RunnerConfig c;
	c.scope = networks;
	c.allowed_ports = "22,25,80,443,554,993,3306,5432,8080,8443";
	c.targets = {networks};
	c.workers = 3;
	c.chunk_seconds = 60;
	return c;
}

static fs::path scratch(const char* name) {
	fs::path d = fs::temp_directory_path() / ("proculus_runner_" + std::string(name) + "_" + std::to_string(getpid()));
	fs::remove_all(d);
	return d;
}

template <class Fn>
static bool throws_invalid(Fn fn, const char* needle = "") {
	try {
		fn();
	} catch (const std::invalid_argument& e) {
		return std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

// ------------------------------------------------------------------------ tests

static void test_config_checks() {
	VirtualClock clock(t0());
	RunnerDeps deps;
	deps.clock = &clock;
	RunnerConfig ok = base_config("10.20.0.0/24");
	Runner fine(ok, deps); // does not throw

	RunnerConfig c = ok;
	c.scope.clear();
	assert(throws_invalid([&] { Runner r(c, deps); }, "no scope"));
	c = ok;
	c.allowed_ports.clear();
	assert(throws_invalid([&] { Runner r(c, deps); }, "no allowed ports"));
	c = ok;
	c.targets.clear();
	assert(throws_invalid([&] { Runner r(c, deps); }, "no targets"));
	c = ok;
	c.workers = 0;
	assert(throws_invalid([&] { Runner r(c, deps); }, "workers"));
	c = ok;
	c.rate = 0;
	assert(throws_invalid([&] { Runner r(c, deps); }, "rate"));
	assert(throws_invalid([&] { Runner r(ok, RunnerDeps{}); }, "clock"));
	c = ok;
	Schedule bad;
	bad.interval = Seconds(0);
	c.schedule = bad;
	assert(throws_invalid([&] { Runner r(c, deps); }));
	c = ok;
	c.web.enabled = true;
	c.web.signature_paths = {"/nonexistent/signatures.json"};
	assert(throws_invalid([&] { Runner r(c, deps); }, "signatures"));
}

static void test_round_without_window() {
	const std::string networks = "10.20.0.0/22";
	SimNetwork net = SimNetwork::generate(7, networks, 0.05);
	const fs::path dir = scratch("plain");
	FileResultStore store(dir);

	VirtualClock clock(t0());
	RunnerDeps deps;
	deps.clock = &clock;
	deps.store = &store;
	deps.deadline_watchdog = false;
	deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };

	RunnerConfig cfg = base_config(networks);
	cfg.exclusions = {"10.20.1.0/25"};
	cfg.targets = {networks, "# a comment is not a target", "not a target at all"};
	Runner runner(cfg, deps);
	const RoundReport r = runner.run_round();

	assert(r.run_id == 1 && r.chunks > 0 && r.pauses == 0 && r.cancelled_chunks == 0);
	assert(r.warnings.size() == 1 && r.warnings[0].find("not a target at all") != std::string::npos);
	const RunRecord run = *store.load(1);
	assert(run.source == "nmap" && run.hosts.size() == r.live_hosts && r.services > 0);

	IpSet excluded;
	excluded.add_list("10.20.1.0/25");
	const auto existing = net.existing_hosts(1);
	const std::set<uint32_t> exists(existing.begin(), existing.end());
	size_t found_existing = 0;
	for (const HostRecord& h : run.hosts) {
		uint32_t ip;
		assert(pc_ip_parse(h.ip.c_str(), &ip) == 0);
		assert(exists.count(ip) && !excluded.contains(ip)); // only real hosts, none of the excluded range
		found_existing++;
		// what was found on the host is what the network exposes
		std::set<uint16_t> want, got;
		for (const SimService& s : net.services(ip, 1)) want.insert(s.port);
		for (const ServiceRecord& s : h.services) got.insert(s.port);
		assert(got == want);
	}
	size_t expected = 0;
	for (uint32_t ip : existing) expected += !excluded.contains(ip);
	assert(found_existing * 10 >= expected * 8); // flapping hosts may miss a round, most are found
	assert(r.discovery_rate > 0 && r.services_rate > 0);
	fs::remove_all(dir);
}

static void test_targets_scope_and_domains() {
	const std::string networks = "10.20.0.0/24";
	SimNetwork net = SimNetwork::generate(3, networks, 0.2);
	VirtualClock clock(t0());
	RunnerDeps deps;
	deps.clock = &clock;
	deps.deadline_watchdog = false;
	deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };

	// outside the scope: refused before anything is scanned
	RunnerConfig out = base_config(networks);
	out.targets = {"10.20.0.0/24", "10.99.0.5"};
	Runner outside(out, deps);
	assert(throws_invalid([&] { outside.run_round(); }, "outside the allowed scope"));

	// only reserved space: nothing to scan
	RunnerConfig reserved = base_config("127.0.0.0/8");
	reserved.targets = {"127.0.0.1"};
	Runner loop(reserved, deps);
	assert(throws_invalid([&] { loop.run_round(); }, "nothing to scan"));

	// domains: resolved, checked against the scope, kept as the host name
	const uint32_t first = net.hosts().front().ip;
	char buf[PC_IP_STR_MAX];
	pc_ip_format(first, buf);
	const std::string host_ip = buf;
	RunnerConfig dom = base_config(networks);
	dom.targets = {"web.example.org", "elsewhere.example.org", "gone.example.org"};
	RunnerDeps dd = deps;
	dd.resolver = [&](const std::string& d) -> std::vector<std::string> {
		if (d == "web.example.org") return {host_ip};
		if (d == "elsewhere.example.org") return {"8.8.8.8"}; // outside the scope
		return {};
	};
	FileResultStore store(scratch("dom"));
	dd.store = &store;
	Runner with_domains(dom, dd);
	const RoundReport r = with_domains.run_round();
	bool saw_outside = false, saw_gone = false;
	for (const std::string& w : r.warnings) {
		saw_outside |= w.find("elsewhere.example.org") != std::string::npos && w.find("outside the allowed scope") != std::string::npos;
		saw_gone |= w.find("gone.example.org") != std::string::npos && w.find("does not resolve") != std::string::npos;
	}
	assert(saw_outside && saw_gone);
	const RunRecord run = *store.load(1);
	// scanning stayed on the one resolved address; the domain is its host name when the host answered
	assert(run.hosts.size() <= 1);
	if (!run.hosts.empty()) assert(run.hosts[0].ip == host_ip && run.hosts[0].hostname == "web.example.org");
}

static void test_window_pause_and_resume() {
	const std::string networks = "10.20.0.0/20";
	SimNetwork net = SimNetwork::generate(11, networks, 0.05);

	// without a window: the baseline
	std::set<std::string> baseline;
	{
		VirtualClock clock(t0());
		RunnerDeps deps;
		deps.clock = &clock;
		deps.deadline_watchdog = false;
		FileResultStore store(scratch("base"));
		deps.store = &store;
		deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
		Runner r(base_config(networks), deps);
		r.run_round();
		const RunRecord base_run = *store.load(1);
		for (const HostRecord& h : base_run.hosts) baseline.insert(h.ip);
	}
	assert(!baseline.empty());

	// a 3 minute window: far too short for the round, so it pauses and resumes on later nights
	VirtualClock clock(t0());
	Runner* rp = nullptr;
	RunnerDeps deps;
	deps.clock = &clock;
	deps.deadline_watchdog = false;
	FileResultStore store(scratch("windowed"));
	deps.store = &store;
	deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<ClockedSim>(net, clock, rp); };

	RunnerConfig cfg = base_config(networks);
	cfg.workers = 1; // one worker keeps the virtual clock deterministic
	Schedule sch;
	parse_window("22:00-22:03", sch);
	sch.min_start_remaining = Seconds(10);
	cfg.schedule = sch;
	Runner runner(cfg, deps);
	rp = &runner;
	const RoundReport r = runner.run_round();

	assert(r.pauses >= 1);                                     // the window closed on the round at least once
	assert(r.started >= parse_time("2026-11-21T22:00:00Z"));   // it waited for the window to open
	assert(r.finished > parse_time("2026-11-22T22:00:00Z"));   // and needed a later night to finish
	const RunRecord run = *store.load(1);
	assert(run.pauses == r.pauses && run.cancelled_chunks == r.cancelled_chunks);
	std::set<std::string> found;
	for (const HostRecord& h : run.hosts) found.insert(h.ip);
	assert(found == baseline); // pausing and resuming loses nothing and finds nothing extra
}

static void test_failures_and_stop() {
	const std::string networks = "10.20.0.0/24";
	SimNetwork net = SimNetwork::generate(5, networks, 0.1);
	VirtualClock clock(t0());

	// a chunk that fails once is retried
	{
		std::atomic<int> calls{0};
		struct Flaky : ScanBackend {
			Flaky(const SimNetwork& n, std::atomic<int>& c) : sim(n), calls(c) {}
			NmapResult run(const NmapCommand& cmd, const ScanJob& job) override {
				if (calls++ == 0) throw ScanFailed("nmap failed (exit 1)");
				return sim.run(cmd, job);
			}
			SimBackend sim;
			std::atomic<int>& calls;
		};
		RunnerDeps deps;
		deps.clock = &clock;
		deps.deadline_watchdog = false;
		deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<Flaky>(net, calls); };
		RunnerConfig cfg = base_config(networks);
		cfg.workers = 1;
		Runner runner(cfg, deps);
		const RoundReport r = runner.run_round();
		assert(r.retries == 1 && r.chunks >= 1);
	}

	// a chunk that always fails ends the round, and nothing is saved
	{
		struct Broken : ScanBackend {
			NmapResult run(const NmapCommand&, const ScanJob&) override { throw ScanFailed("nmap failed (exit 1)"); }
		};
		FileResultStore store(scratch("broken"));
		RunnerDeps deps;
		deps.clock = &clock;
		deps.store = &store;
		deps.deadline_watchdog = false;
		deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<Broken>(); };
		RunnerConfig cfg = base_config(networks);
		cfg.workers = 1;
		Runner runner(cfg, deps);
		bool failed = false;
		try {
			runner.run_round();
		} catch (const ScanError& e) {
			failed = std::string(e.what()).find("failed 3 times") != std::string::npos;
		}
		assert(failed && store.list().empty());
	}

	// a stop request ends the round without saving
	{
		Runner* rp = nullptr;
		struct Stopper : ScanBackend {
			Stopper(const SimNetwork& n, Runner*& r) : sim(n), runner(r) {}
			NmapResult run(const NmapCommand& cmd, const ScanJob& job) override {
				NmapResult r = sim.run(cmd, job);
				if (runner) runner->request_stop();
				return r;
			}
			SimBackend sim;
			Runner*& runner;
		};
		FileResultStore store(scratch("stopped"));
		RunnerDeps deps;
		deps.clock = &clock;
		deps.store = &store;
		deps.deadline_watchdog = false;
		deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<Stopper>(net, rp); };
		RunnerConfig cfg = base_config(networks);
		cfg.workers = 1;
		cfg.chunk_seconds = 1; // several chunks, so the stop lands mid-round
		cfg.assumed_discovery_rate = 10;
		Runner runner(cfg, deps);
		rp = &runner;
		bool aborted = false;
		try {
			runner.run_round();
		} catch (const RunAborted&) {
			aborted = true;
		}
		assert(aborted && store.list().empty());
		// a stopped runner refuses further rounds
		bool again = false;
		try {
			runner.run_round();
		} catch (const RunAborted&) {
			again = true;
		}
		assert(again);
	}
}

// answers every web request on every address with a WordPress front page
class WordPressTransport : public HttpTransport {
public:
	Exchange get(const Endpoint&, const std::string& path, const TransportLimits&) override {
		Exchange ex;
		HttpResponse r;
		r.version = "HTTP/1.1";
		r.headers = {{"Content-Type", "text/html"}, {"Server", "nginx/1.24.0"}, {"Set-Cookie", "wordpress_test_cookie=secret-value; path=/"}};
		if (path == "/") {
			r.status = 200;
			r.reason = "OK";
			r.body = "<html><head><title>Blog</title><meta name=\"generator\" content=\"WordPress 6.4.2\"></head><body>hi</body></html>";
		} else {
			r.status = 404;
			r.reason = "Not Found";
			r.body = "not found";
		}
		ex.response = r;
		return ex;
	}
};

static void test_web_stage() {
	const std::string networks = "10.20.0.0/22";
	SimNetwork net = SimNetwork::generate(7, networks, 0.05);
	VirtualClock clock(t0());
	FileResultStore store(scratch("web"));
	WordPressTransport transport;
	RunnerDeps deps;
	deps.clock = &clock;
	deps.store = &store;
	deps.transport = &transport;
	deps.deadline_watchdog = false;
	deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };

	RunnerConfig cfg = base_config(networks);
	cfg.web.enabled = true;
	cfg.web.requests_per_second = 100000;
	cfg.web.workers = 3;
	Runner runner(cfg, deps);
	const RoundReport r = runner.run_round();

	const RunRecord run = *store.load(1);
	assert(run.source == "nmap+web");
	assert(r.web_probed > 0 && r.web_responding == r.web_probed && r.detections >= r.web_responding);
	size_t with_web = 0;
	for (const HostRecord& h : run.hosts)
		for (const ServiceRecord& s : h.services) {
			if (!s.web) continue;
			with_web++;
			assert(s.web->title == "Blog" && s.web->status == 200);
			bool wordpress = false;
			for (const DetectionRecord& d : s.web->detections) wordpress |= d.id == "wordpress" && d.version == "6.4.2";
			assert(wordpress);
			for (const auto& [name, value] : s.web->headers) assert(value.find("secret-value") == std::string::npos); // cookie values stay out of the run
		}
	assert(with_web == r.web_responding);
}

static void test_progress_reporting() {
	const std::string networks = "10.20.0.0/22";
	SimNetwork net = SimNetwork::generate(7, networks, 0.05);
	VirtualClock clock(t0());
	std::mutex m;
	std::vector<ScanProgress> seen;
	RunnerDeps deps;
	deps.clock = &clock;
	deps.deadline_watchdog = false;
	deps.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
	deps.on_progress = [&](const ScanProgress& p) {
		std::lock_guard<std::mutex> l(m);
		seen.push_back(p);
	};
	Runner runner(base_config(networks), deps);
	const RoundReport r = runner.run_round();

	std::lock_guard<std::mutex> l(m);
	assert(!seen.empty() && seen.front().stage == "starting" && seen.back().stage == "done");
	std::vector<std::string> stages;
	for (const ScanProgress& p : seen)
		if (stages.empty() || stages.back() != p.stage) stages.push_back(p.stage);
	assert((stages == std::vector<std::string>{"starting", "discovery", "services", "saving", "done"}));
	size_t most = 0;
	bool ports_seen = false;
	for (const ScanProgress& p : seen) {
		most = std::max(most, p.recent.size());
		assert(p.recent.size() <= 8 && p.chunks_done <= p.chunks_total);
		for (const LiveHost& h : p.recent) ports_seen |= !h.ports.empty();
	}
	assert(most == 8 && ports_seen);            // a live view of the latest hosts, with the ports found on them
	assert(seen.back().hosts_found == r.live_hosts);
}

int main() {
	test_progress_reporting();
	test_config_checks();
	test_round_without_window();
	test_targets_scope_and_domains();
	test_window_pause_and_resume();
	test_failures_and_stop();
	test_web_stage();
	return 0;
}
