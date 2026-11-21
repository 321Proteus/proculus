#ifndef PROCULUS_JOB_HPP
#define PROCULUS_JOB_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace proculus {

enum class Stage {
	Discovery, // which hosts answer? (nmap -sn)
	Services, // which allowed ports are open, and what runs there? (-sT/-sS +
			  // -sV)
};

// Hard limits the worker enforces regardless of what a job asks for.
struct JobLimits {
	std::string
		scope; // targets that may be scanned at all (IP/CIDR/range list)
	std::string allowed_ports; // ports that may be probed
	int max_rate = 1000; // packets per second ceiling (nmap --max-rate)
	int max_timeout_s = 3600; // ceiling for the whole run
	bool allow_reserved = false;
};

struct ScanJob {
	Stage stage = Stage::Discovery;
	std::string targets; // IP/CIDR/range list, usually one planner chunk
	std::string ports; // Services stage; empty = all allowed ports
	std::string probe_ports =
		"80,443"; // Discovery TCP probes, narrowed to allowed ports
	int rate = 100; // packets per second
	int retries = 1;
	int host_timeout_s = 60;
	int timeout_s = 600; // wall clock for the whole run
	int timing = 3; // nmap -T level, 0..4
	bool version_detect = true;
	bool privileged = false; // raw-socket scans (-sS, ICMP); needs root
};

// A job the worker refuses to run; what() says why.
struct JobRejected : std::runtime_error {
	using std::runtime_error::runtime_error;
};

struct NmapCommand {
	std::vector<std::string> argv; // argv[0] is the nmap binary
	uint64_t target_count = 0; // addresses that will be scanned
	uint64_t reserved_stripped = 0; // addresses dropped for being reserved
	int timeout_s = 0; // effective wall-clock limit
};

// Validates `job` against `limits` and builds the nmap command line.
// Targets must lie inside limits.scope, ports inside limits.allowed_ports,
// and the rate / timing must respect the ceilings; otherwise JobRejected is
// thrown. Reserved addresses (loopback, multicast, ...) are removed from the
// targets unless limits.allow_reserved is set. Every value that reaches the
// command line is re-generated from parsed data, never passed through.
NmapCommand build_command(const ScanJob& job, const JobLimits& limits,
	const std::string& nmap_path = "nmap");

} // namespace proculus

#endif // PROCULUS_JOB_HPP
