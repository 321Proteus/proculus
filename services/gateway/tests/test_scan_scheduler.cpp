#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <thread>

#include "scan_scheduler.hpp"
#include "sim_network.hpp"

using namespace proculus;
namespace fs = std::filesystem;

namespace {
struct Blocking : ScanBackend {
	explicit Blocking(std::atomic<bool>* c) : cancel(c) {}
	NmapResult run(const NmapCommand&, const ScanJob&) override {
		while (!cancel->load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
		throw ScanFailed("cancelled", false, true);
	}
	std::atomic<bool>* cancel;
};
// The time the tests say it is: the runner checks its window against this clock, as the scheduler does against the time it is given.
struct TestClock : Clock {
	std::atomic<long long> seconds{0};
	void set(TimePoint t) { seconds = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count(); }
	TimePoint now() override { return TimePoint(std::chrono::seconds(seconds.load())); }
	bool sleep_until(TimePoint t, const std::atomic<bool>&) override {
		set(t);
		return true;
	}
};
} // namespace

static fs::path scratch(const char* name) {
	fs::path d = fs::temp_directory_path() / ("proculus_sched_" + std::string(name) + "_" + std::to_string(getpid()));
	fs::remove_all(d);
	return d;
}

static ScanPolicy policy() {
	ScanPolicy p;
	p.enabled = true;
	p.scope = "10.20.0.0/22";
	p.allowed_ports = "22,25,80,443,554,993,3306,5432,8080,8443";
	return p;
}

static const TimePoint kNow = parse_time("2026-11-22T10:00:00Z");
static const Seconds kMin(60);

// A schedule that is open all day, every 5 minutes.
static Json always(const char* targets = R"(["10.20.0.0/24"])") {
	return Json::parse(std::string(R"({"name":"always","request":{"targets":)") + targets + R"(},"window":"00:00-00:00","interval":"5m"})");
}

static void test_due_and_interval() {
	SimNetwork net = SimNetwork::generate(7, "10.20.0.0/22", 0.05);
	FileResultStore results(scratch("results"));
	RunnerDeps base;
	base.deadline_watchdog = false;
	base.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
	ScanController ctl(policy(), &results, base);
	ScheduleStore store;
	ScanScheduler sched(store, ctl);
	std::vector<std::string> events;
	sched.set_event_sink([&](const std::string& a, const std::string& d) { events.push_back(a + " | " + d); });

	store.add(always(), kNow);
	assert(sched.next_run(*store.get("s1"), kNow) == kNow); // never run, window open: due now

	assert(sched.tick(kNow) == "s1");
	ctl.wait_idle();
	ScanSchedule s = *store.get("s1");
	assert(s.last_status == "ok" && s.last_run_id == 1 && *s.last_started == kNow && !s.last_finished.empty());
	assert(results.list().size() == 1);
	assert(events.size() == 2 && events[0].find("scheduled scan started | always (s1)") == 0 && events[1].find("scheduled scan finished") == 0);

	// not due again until the interval has passed
	assert(sched.tick(kNow + kMin) == "" && sched.tick(kNow + 4 * kMin) == "");
	assert(sched.next_run(s, kNow + kMin) == kNow + 5 * kMin);
	assert(sched.tick(kNow + 5 * kMin) == "s1");
	ctl.wait_idle();
	assert(results.list().size() == 2 && store.get("s1")->last_run_id == 2);

	// disabled schedules do not run, and have no next run
	store.update("s1", Json::parse(R"({"enabled":false})"));
	assert(sched.tick(kNow + 60 * kMin) == "" && !sched.next_run(*store.get("s1"), kNow));
	assert(results.list().size() == 2);
	const Json shown = sched.describe(*store.get("s1"), kNow);
	assert(shown["next_run"].is_null() && shown["running"] == false && shown["last"]["status"] == "ok");
}

static void test_window_closed_and_missed_runs() {
	SimNetwork net = SimNetwork::generate(7, "10.20.0.0/22", 0.05);
	FileResultStore results(scratch("results2"));
	TestClock clock;
	RunnerDeps base;
	base.clock = &clock;
	base.deadline_watchdog = false;
	base.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
	ScanController ctl(policy(), &results, base);
	ScheduleStore store;
	ScanScheduler sched(store, ctl);
	auto tick = [&](TimePoint t) {
		clock.set(t);
		return sched.tick(t);
	};

	// 01:00-02:00 UTC; it is 10:00
	store.add(Json::parse(R"({"name":"early","request":{"targets":["10.20.0.0/24"]},"window":"01:00-02:00","utc_offset":"+00:00","interval":"1d"})"), kNow);
	assert(tick(kNow) == "");
	assert(*sched.next_run(*store.get("s1"), kNow) == parse_time("2026-11-23T01:00:00Z"));
	assert(tick(parse_time("2026-11-23T00:59:00Z")) == "");
	assert(tick(parse_time("2026-11-23T01:30:00Z")) == "s1"); // inside the window
	ctl.wait_idle();
	// the interval counts from the start: the next one is due the following day, in its window
	assert(tick(parse_time("2026-11-23T01:40:00Z")) == "");
	assert(*sched.next_run(*store.get("s1"), parse_time("2026-11-23T01:40:00Z")) == parse_time("2026-11-24T01:30:00Z"));
	// a run that was missed (gateway down) happens once when a window is open, not once per missed day
	assert(tick(parse_time("2026-11-28T01:10:00Z")) == "s1");
	ctl.wait_idle();
	assert(results.list().size() == 2);
	assert(tick(parse_time("2026-11-28T01:20:00Z")) == "");

	const Json windows = ScanScheduler::upcoming(*store.get("s1"), kNow, 3);
	assert(windows.size() == 3 && windows[0]["start"] == "2026-11-23T01:00:00Z" && windows[0]["end"] == "2026-11-23T02:00:00Z");
}

static void test_busy_and_policy() {
	FileResultStore results(scratch("results3"));
	RunnerDeps base;
	base.deadline_watchdog = false;
	base.make_backend = [](std::atomic<bool>& cancel) { return std::make_unique<Blocking>(&cancel); };
	ScanController ctl(policy(), &results, base);
	ScheduleStore store;
	ScanScheduler sched(store, ctl);
	std::vector<std::string> events;
	sched.set_event_sink([&](const std::string& a, const std::string& d) { events.push_back(a + " | " + d); });
	store.add(always(), kNow);

	// a scan started by hand is running: the schedule waits and is untouched
	ScanRequest manual;
	manual.targets = {"10.20.1.0/24"};
	ctl.start(manual);
	assert(sched.tick(kNow) == "");
	assert(!store.get("s1")->last_started && store.get("s1")->last_status.empty());
	ctl.stop();
	ctl.wait_idle();
	assert(store.get("s1")->last_status.empty()); // a scan of someone else is not the schedule's

	// run it, then stop it: recorded as stopped
	assert(sched.tick(kNow) == "s1");
	for (int i = 0; i < 400 && ctl.status()["current"]["stage"] != "discovery"; i++) std::this_thread::sleep_for(std::chrono::milliseconds(5));
	assert(sched.describe(*store.get("s1"), kNow)["running"] == true && store.get("s1")->last_status == "running");
	ctl.stop();
	ctl.wait_idle();
	assert(store.get("s1")->last_status == "stopped" && sched.describe(*store.get("s1"), kNow)["running"] == false);

	// the administrator narrows the scope: the schedule is refused, not run with old limits, and tried again after its interval
	ctl.configure(Json::parse(R"({"scope":"10.20.2.0/24"})"));
	assert(sched.tick(kNow + 10 * kMin) == "");
	ScanSchedule s = *store.get("s1");
	assert(s.last_status == "refused" && s.last_message.find("outside the allowed scope") != std::string::npos && *s.last_started == kNow + 10 * kMin);
	assert(events.back().find("scheduled scan refused | always (s1)") == 0);
	const size_t seen = events.size();
	assert(sched.tick(kNow + 11 * kMin) == "" && events.size() == seen); // not at every look
	// and scans that are switched off start nothing
	ctl.configure(Json::parse(R"({"enabled":false})"));
	assert(sched.tick(kNow + 60 * kMin) == "" && events.size() == seen);
}

static void test_run_now_and_thread() {
	SimNetwork net = SimNetwork::generate(7, "10.20.0.0/22", 0.05);
	FileResultStore results(scratch("results4"));
	RunnerDeps base;
	base.deadline_watchdog = false;
	base.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
	ScanController ctl(policy(), &results, base);
	ScheduleStore store;
	{
		ScanScheduler sched(store, ctl);
		// outside its window, a person can still run it
		store.add(Json::parse(R"({"name":"early","request":{"targets":["10.20.0.0/24"]},"window":"01:00-01:30","utc_offset":"+00:00"})"), kNow);
		sched.run_now("s1", kNow);
		ctl.wait_idle();
		assert(store.get("s1")->last_status == "ok" && results.list().size() == 1);
		bool threw = false;
		try { sched.run_now("s9", kNow); } catch (const ApiError& e) { threw = e.status == 404; }
		assert(threw);

		// the thread starts a due schedule by itself
		store.add(always(), std::chrono::system_clock::now());
		sched.start(std::chrono::seconds(1));
		for (int i = 0; i < 400 && store.get("s2")->last_status != "ok"; i++) std::this_thread::sleep_for(std::chrono::milliseconds(10));
		assert(store.get("s2")->last_status == "ok" && results.list().size() == 2);
		sched.stop();
	}
	// the controller outlives the scheduler: its callback is gone, nothing dangles
	ScanRequest r;
	r.targets = {"10.20.0.0/24"};
	ctl.start(r);
	ctl.wait_idle();
}

int main() {
	test_due_and_interval();
	test_window_closed_and_missed_runs();
	test_busy_and_policy();
	test_run_now_and_thread();
	return 0;
}
