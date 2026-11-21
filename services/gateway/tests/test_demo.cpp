#undef NDEBUG
#include <cassert>
#include <sstream>

#include "demo.hpp"

using namespace proculus;

static DemoConfig small() {
	DemoConfig c;
	c.networks = "10.20.0.0/22,10.30.0.0/22";
	c.density = 0.1;
	c.quiet = true;
	c.window = "00:00-00:00"; // open all day: nothing is cut off
	return c;
}

static std::vector<RoundReport> run(const DemoConfig& c) {
	std::ostringstream sink;
	return run_demo(c, sink);
}

static void test_rounds_and_ground_truth() {
	DemoConfig c = small();
	auto reports = run(c);
	assert(reports.size() == 3);

	SimNetwork net = SimNetwork::generate(c.seed, c.networks, c.density);
	for (const RoundReport& r : reports) {
		// the scan finds exactly the hosts that answered this round, with all their open services
		size_t up = 0, services = 0;
		for (const SimHost& h : net.hosts()) {
			if (!net.is_up(h.ip, r.round)) continue;
			up++;
			services += net.services(h.ip, r.round).size();
		}
		assert(r.hosts_found == up && r.services_found == services);
		assert(r.hosts_found <= r.existing_hosts && r.hosts_found > 50);
		assert(r.pauses == 0 && r.cancelled_chunks == 0 && r.chunks > 0);
		assert(r.addresses == 2048 + r.hosts_found); // every address once for discovery, every live host once for services
		assert(r.finished > r.started);
	}

	// runs start on schedule: one per day at 00:00, never before the interval has passed
	for (size_t i = 1; i < reports.size(); i++)
		assert(reports[i].started - reports[i - 1].started >= Seconds(24 * 3600));
}

static void test_changes_between_rounds() {
	auto reports = run(small());
	assert(reports[0].new_hosts == 0 && reports[0].gone_hosts == 0); // nothing to compare with yet
	const RoundReport& r2 = reports[1];
	assert(r2.new_hosts + r2.gone_hosts + r2.new_services + r2.changed_services > 0);
	assert(r2.new_hosts > 0 && r2.gone_hosts > 0);
	assert(reports[2].changed_services + reports[2].new_services > 0);
}

static void test_learns_scan_speed() {
	DemoConfig c = small();
	c.assumed_discovery_rate = 10; // far too pessimistic: real speed is 200/s
	auto r = run(c);
	assert(r[0].discovery_rate > 150 && r[0].discovery_rate < 250);
	assert(r[2].discovery_rate > 150 && r[2].discovery_rate < 250);
	assert(r[0].services_rate > 0.4 && r[0].services_rate < 1.0); // real: 1/1.5 hosts/s
}

static void test_window_pauses_and_resumes() {
	DemoConfig c = small();
	c.window = "22:00-22:03";
	c.speed.service_seconds_per_host = 6; // ~140 hosts x 6 s / 3 workers: several windows
	auto reports = run(c);
	assert(reports.size() == 3);
	int pauses = 0;
	for (const RoundReport& r : reports) {
		pauses += r.pauses;
		// whatever the interruptions, the same hosts and services come out
		SimNetwork net = SimNetwork::generate(c.seed, c.networks, c.density);
		size_t up = 0;
		for (const SimHost& h : net.hosts()) up += net.is_up(h.ip, r.round);
		assert(r.hosts_found == up);
		assert(r.finished - r.started > Seconds(3600)); // spans nights, not minutes
	}
	assert(pauses > 0);

	// a round that spans nights delays the next one, but runs are still a day apart at least
	for (size_t i = 1; i < reports.size(); i++)
		assert(reports[i].started >= reports[i - 1].finished);
}

static void test_deterministic() {
	DemoConfig c = small();
	auto a = run(c), b = run(c);
	for (size_t i = 0; i < a.size(); i++) {
		assert(a[i].hosts_found == b[i].hosts_found && a[i].services_found == b[i].services_found);
		assert(a[i].finished == b[i].finished && a[i].chunks == b[i].chunks);
	}
	c.seed = 43;
	assert(run(c)[0].hosts_found != a[0].hosts_found);
}

static void test_errors() {
	auto throws = [](DemoConfig c) {
		try { run(c); } catch (const std::invalid_argument&) { return true; } catch (const std::runtime_error&) { return true; }
		return false;
	};
	DemoConfig c = small();
	c.rounds = 0;
	assert(throws(c));
	c = small();
	c.workers = 0;
	assert(throws(c));
	c = small();
	c.window = "nonsense";
	assert(throws(c));
	c = small();
	c.start = "yesterday";
	assert(throws(c));

	// a window far too short for even one chunk can never make progress: fail clearly
	c = small();
	c.window = "22:00-22:01";
	c.speed.service_seconds_per_host = 600;
	assert(throws(c));
}

static void test_narration() {
	DemoConfig c = small();
	c.quiet = false;
	c.rounds = 2;
	std::ostringstream out;
	run_demo(c, out);
	const std::string s = out.str();
	assert(s.find("=== round 1 ===") != std::string::npos && s.find("=== round 2 ===") != std::string::npos);
	assert(s.find("changes since round 1") != std::string::npos);
}

int main() {
	test_rounds_and_ground_truth();
	test_changes_between_rounds();
	test_learns_scan_speed();
	test_window_pauses_and_resumes();
	test_deterministic();
	test_errors();
	test_narration();
	return 0;
}
