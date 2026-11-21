#ifndef PROCULUS_DEMO_HPP
#define PROCULUS_DEMO_HPP

// End-to-end demonstration of the scanning pipeline against an emulated network.
//
// Each round: wait for the scan window (scheduler), plan chunks (planner),
// scan them with several virtual workers (scan-worker, simulated backend,
// same safety checks as a real scan), time them (timing) and learn the real
// scan speed, pause when the window closes and resume in the next one, then
// compare what was found with the previous round.
//
// Time is virtual: a "20 minute" scan finishes instantly.

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "schedule.hpp"
#include "sim_network.hpp"

namespace proculus {

struct DemoConfig {
	uint64_t seed = 42;
	std::string networks = "10.20.0.0/20,10.30.0.0/20,172.16.8.0/20"; // 12,288 addresses
	double density = 0.03;
	std::string allowed_ports = "22,25,80,443,554,993,3306,5432,8080,8443";

	int rounds = 3;
	unsigned workers = 3;

	// Scan window. The default is deliberately shorter than a whole round, so the
	// demo shows a pause at the end of the window and a resume the next night.
	std::string window = "22:00-22:03";
	std::string start = "2026-11-21T21:00:00Z";
	Seconds interval{24 * 3600};

	// What the planner assumes before it has measured anything (addresses/s
	// per worker for discovery, hosts/s per worker for the services stage).
	double assumed_discovery_rate = 50;
	double assumed_services_rate = 0.5;
	double chunk_seconds = 60;

	SimSpeed speed;
	bool quiet = false; // suppress the narration (tests)
};

struct RoundReport {
	int round = 0;
	TimePoint started, finished;
	int pauses = 0;            // times the window closed mid-round
	int cancelled_chunks = 0;  // chunks cut off by the window and retried
	int splits = 0;            // chunks halved because a whole window was too short for them
	int chunks = 0;            // chunks completed
	uint64_t addresses = 0;
	size_t existing_hosts = 0; // ground truth: hosts that exist this round
	size_t hosts_found = 0;
	size_t services_found = 0;
	// compared with the previous round (all zero for round 1)
	size_t new_hosts = 0, gone_hosts = 0;
	size_t new_services = 0, gone_services = 0, changed_services = 0;
	double discovery_rate = 0; // measured addresses/s per worker after the round
	double services_rate = 0;  // measured hosts/s per worker after the round
};

// Runs the demo, narrating to `out` unless config.quiet. Throws
// std::invalid_argument for a bad configuration and std::runtime_error if a
// chunk can never fit in a scan window.
std::vector<RoundReport> run_demo(const DemoConfig& config, std::ostream& out);

} // namespace proculus

#endif // PROCULUS_DEMO_HPP
