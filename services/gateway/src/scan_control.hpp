#ifndef PROCULUS_GATEWAY_SCAN_CONTROL_HPP
#define PROCULUS_GATEWAY_SCAN_CONTROL_HPP

// Starting and stopping scans from the web UI.
//
// Scans started this way are the first thing the API does to a network, so the
// rules are strict and are not set by whoever uses the form:
//  * the policy fixes the scope, the allowed ports and the ceilings for workers
//    and packet rate; a request can only choose targets inside the scope and
//    values under the ceilings;
//  * the policy is changed by an administrator (config.manage) at run time and
//    kept in a file; the operator's only fixed limit is the optional `ceiling`
//    (--scan-ceiling), which no setting can go beyond;
//  * one scan at a time;
//  * scans are off until an administrator enables them.
// A scan runs on a background thread through the same Runner as the command
// line, so it has the same safety checks (validated nmap commands, scope and
// port gates). The controller keeps its progress and a short log for the UI.

#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "api.hpp"
#include "runner.hpp"

namespace proculus {

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

// A named, ready-made scan request. The built-in ones (ScanController::builtin_presets) are
// the same for every user; users keep their own in the browser. A preset only fills in the form:
// what a scan may touch is decided by the administrator's scope and ports, whatever the preset says.
struct ScanPreset {
	std::string name;
	ScanRequest request;
};

struct ScanPolicy {
	bool enabled = false;
	bool simulated = false;     // scans run against an emulated network (gateway serve --simulate); shown in the status
	std::string ceiling;        // set at start-up by the operator: the scope can never go beyond it (empty: no limit)
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

	// The settings an administrator may change (also what is saved): enabled, scope,
	// allowed_ports, max_workers, max_rate, allow_privileged, allow_web, allow_reserved,
	// plus the read-only `ceiling` and the built-in `presets`.
	Json settings() const;
	// The ready-made presets, built from this machine's addresses: [{name, targets, exclusions, ports,
	// workers, rate, timing, web, privileged}]: localhost ports, a few hosts of the local network, the whole network.
	static Json builtin_presets();
	// Applies the keys present in `body` (unknown keys are refused), validates the result
	// against the ceiling and saves it. Throws ApiError 400 when invalid.
	// A scan that is already running keeps the settings it started with.
	void configure(const Json& body);
	// Keeps the settings in this file: written (0600) by every configure(); load_settings()
	// reads it at start-up. A file that is unusable is ignored with a message and scans stay off.
	void persist_to(std::filesystem::path file);
	bool load_settings(std::string* problem = nullptr);
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
