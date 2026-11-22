#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <thread>

#include "scan_control.hpp"
#include "sim_network.hpp"
#include "token_guard.hpp"

using namespace proculus;
namespace fs = std::filesystem;

static fs::path scratch(const char* name) {
	fs::path d = fs::temp_directory_path() / ("proculus_scanctl_" + std::string(name) + "_" + std::to_string(getpid()));
	fs::remove_all(d);
	return d;
}

static bool api_error(int status, const std::function<void()>& fn, const char* needle = "") {
	try {
		fn();
	} catch (const ApiError& e) {
		return e.status == status && std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

static ScanRequest req(std::vector<std::string> targets) {
	ScanRequest r;
	r.targets = std::move(targets);
	return r;
}

static void test_parse_request() {
	const ScanRequest r = parse_scan_request(Json::parse(R"({"targets":["10.20.0.0/24"," 10.20.1.5 ",""],"exclusions":["10.20.0.1"],"workers":3,"rate":150,"timing":2,"web":true,"ports":"22,80"})"));
	assert((r.targets == std::vector<std::string>{"10.20.0.0/24", "10.20.1.5"}) && r.exclusions.size() == 1 && r.workers == 3 && r.rate == 150 && r.timing == 2 && r.web && !r.privileged && r.ports == "22,80");
	const ScanRequest d = parse_scan_request(Json::parse(R"({"targets":["10.0.0.1"]})"));
	assert(d.workers == 2 && d.rate == 100 && d.timing == 3 && !d.web && d.ports.empty());

	for (const char* bad : {R"([])", R"("x")", R"({"targets":"10.0.0.1"})", R"({"targets":[1]})", R"({"targets":["a"],"scope":"0.0.0.0/0"})", R"({"targets":["a"],"workers":0})",
	                         R"({"targets":["a"],"workers":65})", R"({"targets":["a"],"workers":"3"})", R"({"targets":["a"],"workers":2.5})", R"({"targets":["a"],"rate":0})",
	                         R"({"targets":["a"],"timing":5})", R"({"targets":["a"],"web":"yes"})", R"({"targets":["a"],"privileged":1})", R"({"targets":["a"],"ports":5})",
	                         R"({"targets":["a\u0007b"]})"}) {
		assert(api_error(400, [&] { parse_scan_request(Json::parse(bad)); }));
	}
	std::string many = R"({"targets":[)";
	for (int i = 0; i < 201; i++) many += (i ? ",\"10.0.0.1\"" : "\"10.0.0.1\"");
	many += "]}";
	assert(api_error(400, [&] { parse_scan_request(Json::parse(many)); }, "more than"));
}

static void test_token_guard() {
	std::chrono::steady_clock::time_point now{};
	TokenGuard g("secret-token-0123456789", [&] { return now; });
	using R = TokenGuard::Result;
	assert(g.check("secret-token-0123456789") == R::Ok);
	assert(g.check("") == R::Denied && g.check("secret-token-012345678") == R::Denied && g.check("secret-token-01234567890") == R::Denied);
	assert(g.check("secret-token-0123456789") == R::Ok); // a right token resets the count
	for (int i = 0; i < 5; i++) assert(g.check("wrong") == R::Denied);
	assert(g.check("secret-token-0123456789") == R::Locked); // locked, even for the right one
	now += std::chrono::seconds(30);
	assert(g.check("secret-token-0123456789") == R::Locked);
	now += std::chrono::seconds(31);
	assert(g.check("secret-token-0123456789") == R::Ok);
	// failures spread over more than the window do not add up
	for (int i = 0; i < 4; i++) {
		assert(g.check("wrong") == R::Denied);
		now += std::chrono::seconds(20);
	}
	assert(g.check("secret-token-0123456789") == R::Ok);

	TokenGuard off("");
	assert(off.check("") == R::Disabled && off.check("anything") == R::Disabled);

	const std::string a = TokenGuard::generate(), b = TokenGuard::generate();
	assert(a.size() == 32 && b.size() == 32 && a != b && a.find_first_not_of("0123456789abcdef") == std::string::npos);
}

namespace {
struct Blocking : ScanBackend {
	explicit Blocking(std::atomic<bool>* c) : cancel(c) {}
	NmapResult run(const NmapCommand&, const ScanJob&) override {
		while (!cancel->load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
		throw ScanFailed("cancelled", false, true);
	}
	std::atomic<bool>* cancel;
};
} // namespace

static void test_controller() {
	const std::string networks = "10.20.0.0/22";
	SimNetwork net = SimNetwork::generate(7, networks, 0.05);
	FileResultStore store(scratch("main"));

	// disabled: nothing can start
	{
		ScanController off(ScanPolicy{}, &store);
		assert(!off.enabled() && off.status()["enabled"] == false);
		assert(api_error(403, [&] { off.start(req({"10.20.0.1"})); }, "not enabled"));
		assert(api_error(403, [&] { off.plan(req({"10.20.0.1"})); }));
		off.stop(); // harmless
	}
	// an enabled policy must be usable
	{
		ScanPolicy p;
		p.enabled = true;
		bool threw = false;
		try { ScanController c(p, &store); } catch (const std::invalid_argument&) { threw = true; }
		assert(threw); // no scope
		p.scope = "10.20.0.0/22";
		p.allowed_ports = "22,80";
		threw = false;
		try { ScanController c(p, nullptr); } catch (const std::invalid_argument&) { threw = true; }
		assert(threw); // no store
	}

	ScanPolicy policy;
	policy.enabled = true;
	policy.scope = networks;
	policy.allowed_ports = "22,25,80,443,554,993,3306,5432,8080,8443";
	policy.max_workers = 3;
	policy.max_rate = 150;
	RunnerDeps base;
	base.deadline_watchdog = false;
	base.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
	ScanController ctl(policy, &store, base);

	// ---- the form can only go under the operator's limits
	assert(ctl.enabled());
	const Json st0 = ctl.status();
	assert(st0["state"] == "idle" && st0["policy"]["scope"] == networks && st0["policy"]["max_workers"] == 3 && st0["policy"]["allow_privileged"] == false);
	assert(api_error(400, [&] { ctl.start(req({})); }, "at least one target"));
	assert(api_error(400, [&] { ctl.start(req({"10.99.0.1"})); }, "outside the allowed scope"));
	assert(api_error(400, [&] { ctl.start(req({"10.20.0.0/22", "10.20.4.0/24"})); }, "10.20.4.0/24"));
	assert(api_error(400, [&] { ctl.start(req({"10.20.0.1-10.20.9.9"})); }, "outside"));
	assert(api_error(400, [&] { ctl.start(req({"banana !"})); }, "not an IP"));
	ScanRequest r = req({"10.20.0.0/24"});
	r.workers = 4;
	assert(api_error(400, [&] { ctl.start(r); }, "at most 3 workers"));
	r.workers = 2;
	r.rate = 151;
	assert(api_error(400, [&] { ctl.start(r); }, "limited to 150"));
	r.rate = 100;
	r.privileged = true;
	assert(api_error(400, [&] { ctl.start(r); }, "privileged"));
	r.privileged = false;
	r.ports = "22,23";
	assert(api_error(400, [&] { ctl.start(r); }, "outside the allowed list"));
	r.ports = "ssh";
	assert(api_error(400, [&] { ctl.start(r); }, "not a port list"));
	r.ports.clear();
	r.exclusions = {"not-an-address"};
	assert(api_error(400, [&] { ctl.start(r); }, "exclude"));
	assert(ctl.status()["state"] == "idle" && store.list().empty()); // refused requests start nothing

	// ---- a domain is accepted (its addresses are checked when it is resolved)
	assert(ctl.plan(req({"intranet.example.org"}))["domains"] == 1);

	// ---- the plan
	r = req({"10.20.0.0/22"});
	r.exclusions = {"10.20.1.0/24"};
	const Json plan = ctl.plan(r);
	assert(plan["addresses"] == 768 && plan["excluded"] == 256 && plan["chunks"].get<int>() >= 1 && plan["workers"] == 2);

	// ---- a scan runs in the background and is saved
	ctl.start(req({"10.20.0.0/22"}));
	assert(api_error(409, [&] { ctl.start(req({"10.20.0.0/22"})); }, "already running") || ctl.status()["state"] == "idle"); // (it may already be done)
	ctl.wait_idle();
	const Json done = ctl.status();
	assert(done["state"] == "idle" && done["last"]["ok"] == true && done["last"]["run_id"] == 1 && done["last"]["hosts"].get<int>() > 0);
	assert(done["log_total"].get<size_t>() == done["log"].size()); // nothing was dropped from the short log, so the running count matches
	assert(done["log"].is_array() && !done["log"].empty() && done["last"]["finished"].get<std::string>().size() == 20);
	assert(store.list().size() == 1 && store.load(1)->hosts.size() == done["last"]["hosts"].get<size_t>());
	ctl.start(req({"10.20.0.0/24"})); // and another can follow
	ctl.wait_idle();
	assert(store.list().size() == 2);
}

static void test_stop_and_one_at_a_time() {
	FileResultStore store(scratch("stop"));
	ScanPolicy policy;
	policy.enabled = true;
	policy.scope = "10.20.0.0/22";
	policy.allowed_ports = "22,80";
	RunnerDeps base;
	base.deadline_watchdog = false;
	base.make_backend = [](std::atomic<bool>& cancel) { return std::make_unique<Blocking>(&cancel); };
	ScanController ctl(policy, &store, base);

	ctl.start(req({"10.20.0.0/24"}));
	// it is running: a second start is refused, and the status says what it is doing
	for (int i = 0; i < 400 && ctl.status()["current"]["stage"] != "discovery"; i++) std::this_thread::sleep_for(std::chrono::milliseconds(5));
	const Json running = ctl.status();
	assert(running["state"] == "running" && running["current"]["stage"] == "discovery" && running["current"]["chunks_total"].get<int>() >= 1);
	assert(running["current"]["request"]["targets"][0] == "10.20.0.0/24");
	assert(api_error(409, [&] { ctl.start(req({"10.20.0.0/24"})); }, "already running"));

	ctl.stop();
	ctl.wait_idle();
	const Json stopped = ctl.status();
	assert(stopped["state"] == "idle" && stopped["last"]["ok"] == false && stopped["last"]["message"].get<std::string>().find("stopped") == 0);
	assert(store.list().empty()); // nothing saved

	// destroying the controller while a scan runs stops it
	ctl.start(req({"10.20.0.0/24"}));
}

// A real scan (no test backend) without nmap is refused with a clear message, not retried to death.
void test_missing_nmap() {
	FileResultStore store(scratch("nmap"));
	ScanPolicy policy;
	policy.enabled = true;
	policy.scope = "127.0.0.1";
	policy.allowed_ports = "80";
	policy.allow_reserved = true;
	policy.nmap_path = "/nonexistent/dir/nmap";
	ScanController ctl(policy, &store); // no backend given: it would run the real nmap
	assert(api_error(400, [&] { ctl.start(req({"127.0.0.1"})); }, "nmap was not found"));
	assert(ctl.status()["state"] == "idle");
	ScanPolicy by_name = policy;
	by_name.nmap_path = "definitely-not-a-program-zzz";
	ScanController ctl2(by_name, &store);
	assert(api_error(400, [&] { ctl2.start(req({"127.0.0.1"})); }, "PATH"));
}

// Scan settings: changed at run time, kept under the operator's ceiling, saved to a file.
void test_settings() {
	FileResultStore store(scratch("settings"));
	const fs::path file = scratch("settings-file") / "scan-config.json";
	ScanPolicy p;
	p.ceiling = "10.20.0.0/16";
	ScanController ctl(p, &store);
	ctl.persist_to(file);

	// off by default; the settings say what the ceiling is
	assert(!ctl.enabled() && ctl.settings()["enabled"] == false && ctl.settings()["ceiling"] == "10.20.0.0/16");
	assert(!ctl.load_settings()); // no file yet

	// switching on needs a scope and ports, and nothing changes when it is refused
	assert(api_error(400, [&] { ctl.configure(Json{{"enabled", true}}); }, "scope"));
	assert(api_error(400, [&] { ctl.configure(Json{{"enabled", true}, {"scope", "10.20.0.0/24"}}); }, "ports"));
	assert(api_error(400, [&] { ctl.configure(Json{{"scope", "not an address"}, {"allowed_ports", "22"}, {"enabled", true}}); }));
	assert(api_error(400, [&] { ctl.configure(Json{{"enabled", true}, {"scope", "10.20.0.0/24"}, {"allowed_ports", "x"}}); }, "port"));
	assert(!ctl.enabled() && !fs::exists(file));
	// the ceiling can not be exceeded, not even by a little
	assert(api_error(400, [&] { ctl.configure(Json{{"enabled", true}, {"scope", "10.20.0.0/24,10.21.0.1"}, {"allowed_ports", "22"}}); }, "beyond"));
	assert(api_error(400, [&] { ctl.configure(Json{{"enabled", true}, {"scope", "0.0.0.0/0"}, {"allowed_ports", "22"}}); }, "beyond"));
	// unknown keys and wrong types are refused (the ceiling is not a setting)
	assert(api_error(400, [&] { ctl.configure(Json{{"ceiling", "0.0.0.0/0"}}); }, "unknown"));
	assert(api_error(400, [&] { ctl.configure(Json{{"enabled", "yes"}}); }, "true or false"));
	assert(api_error(400, [&] { ctl.configure(Json{{"max_workers", 0}}); }));
	assert(api_error(400, [&] { ctl.configure(Json{{"max_rate", 100001}}); }));
	assert(api_error(400, [&] { ctl.configure(Json::array()); }));
	assert(!ctl.enabled());

	// a valid change takes effect at once and is saved with 0600
	ctl.configure(Json{{"enabled", true}, {"scope", "10.20.0.0/24"}, {"allowed_ports", "22,80"}, {"max_workers", 2}, {"max_rate", 150}});
	assert(ctl.enabled() && ctl.status()["policy"]["scope"] == "10.20.0.0/24" && ctl.status()["policy"]["max_rate"] == 150);
	assert(api_error(400, [&] { ctl.plan(req({"10.20.1.1"})); }, "outside the allowed scope"));
	assert(ctl.plan(req({"10.20.0.0/28"}))["addresses"].get<int>() > 0);
	assert(fs::exists(file) && (fs::status(file).permissions() & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none);

	// the built-in presets are the same for everyone: localhost first, then the local networks; they
	// only fill in the form, the scope still decides
	{
		const Json all = ctl.settings();
		assert(all["presets"].size() >= 1 && all["presets"][0]["name"] == "localhost" && all["presets"][0]["targets"][0] == "127.0.0.1");
		assert(ctl.status()["policy"]["presets"] == all["presets"] && !all.contains("suggestions"));
		for (const Json& pr : all["presets"]) assert(!pr["targets"].empty() && !pr["ports"].get<std::string>().empty());
		ScanRequest r; // localhost is outside this scope, so the preset "just does not work"
		r.targets = all["presets"][0]["targets"].get<std::vector<std::string>>();
		assert(api_error(400, [&] { ctl.plan(r); }, "outside the allowed scope"));
		assert(api_error(400, [&] { ctl.configure(Json{{"presets", Json::array()}}); }, "unknown")); // presets are not a setting
	}

	// a partial change keeps the rest
	ctl.configure(Json{{"max_rate", 170}});
	assert(ctl.settings()["scope"] == "10.20.0.0/24" && ctl.settings()["max_rate"] == 170 && ctl.settings()["allow_reserved"] == false);

	// a new controller (a restart) reads the file back, under its own ceiling
	{
		ScanPolicy q;
		q.ceiling = "10.20.0.0/16";
		ScanController again(q, &store);
		again.persist_to(file);
		assert(again.load_settings() && again.enabled() && again.settings()["max_rate"] == 170);
	}
	// ... and ignores it, with a reason, when the ceiling no longer allows it; scans stay off
	{
		ScanPolicy q;
		q.ceiling = "192.168.0.0/16";
		ScanController again(q, &store);
		again.persist_to(file);
		std::string problem;
		assert(!again.load_settings(&problem) && !again.enabled() && problem.find("beyond") != std::string::npos);
	}
	// a damaged file is ignored too
	{
		std::ofstream(file) << "{not json";
		ScanController again(ScanPolicy{}, &store);
		again.persist_to(file);
		std::string problem;
		assert(!again.load_settings(&problem) && !again.enabled() && !problem.empty());
	}
	// a bad ceiling stops the start-up
	{
		ScanPolicy q;
		q.ceiling = "nonsense";
		bool threw = false;
		try { ScanController c(q, &store); } catch (const std::invalid_argument&) { threw = true; }
		assert(threw);
	}
}

int main() {
	test_parse_request();
	test_token_guard();
	test_controller();
	test_stop_and_one_at_a_time();
	test_settings();
	test_missing_nmap();
	return 0;
}
