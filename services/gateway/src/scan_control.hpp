#ifndef PROCULUS_GATEWAY_SCAN_CONTROL_HPP
#define PROCULUS_GATEWAY_SCAN_CONTROL_HPP

// Starting and stopping scans from the web UI.
//
// Scans started this way are the first thing the API does to a network, so the
// rules are strict and set by the operator when the gateway is started, not by
// whoever uses the form:
//  * the policy fixes the scope, the allowed ports and the ceilings for workers
//    and packet rate; a request can only choose targets inside the scope and
//    values under the ceilings;
//  * one scan at a time;
//  * scans are off unless the operator enabled them.
// A scan runs on a background thread through the same Runner as the command
// line, so it has the same safety checks (validated nmap commands, scope and
// port gates). The controller keeps its progress and a short log for the UI.

#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "api.hpp"
#include "runner.hpp"

namespace proculus {

struct ScanPolicy {
	bool enabled = false;
	std::string scope;          // required when enabled
	std::string allowed_ports;  // required when enabled
	unsigned max_workers = 4;
	int max_rate = 200;         // packets per second per nmap process
	bool allow_privileged = false;
	bool allow_web = true;
	bool allow_reserved = false; // loopback etc. (for tests and local labs)
	std::string nmap_path = "nmap";
	std::vector<std::string> signature_paths; // custom signatures for the web stage
};

struct ScanRequest {
	std::vector<std::string> targets;    // IP, CIDR, range or domain
	std::vector<std::string> exclusions;
	std::string ports;                   // services stage; empty = every allowed port
	unsigned workers = 2;
	int rate = 100;
	int timing = 3;
	bool web = false;
	bool privileged = false;
};

// From the UI's JSON; ApiError(400) for anything malformed. Unknown keys are refused.
ScanRequest parse_scan_request(const Json& body);

class ScanController {
public:
	// Throws std::invalid_argument for an enabled policy that is unusable.
	// `base` may supply a clock, backend, resolver or transport (tests).
	ScanController(ScanPolicy policy, ResultStore* store, RunnerDeps base = {});
	~ScanController(); // stops a running scan and waits for it

	bool enabled() const;
	Json status() const;
	// What a scan of this request would involve (validates it too); scans nothing.
	Json plan(const ScanRequest& request) const;
	// Throws ApiError: 403 scans disabled, 400 invalid request, 409 a scan is already running.
	void start(const ScanRequest& request);
	// Asks a running scan to stop; its round is not saved. No effect when idle.
	void stop();
	// Waits until no scan is running (tests).
	void wait_idle();

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_SCAN_CONTROL_HPP
