#ifndef PROCULUS_RUNNER_HPP
#define PROCULUS_RUNNER_HPP

// Runs a real scan round, in real time, through the same stages the demo
// shows on a virtual clock:
//
//   targets -> resolve domains (scope-checked) -> plan chunks (planner)
//   -> discovery (which addresses answer?) -> services (what runs there?)
//   -> optionally web probing + signatures -> save the run.
//
// Chunks are scanned by a pool of workers, every nmap command passing through
// build_command() (scope, ports, rate and timing limits). If a scan window is
// configured, chunks are only started when they are expected to finish inside
// it; when the window closes, running nmap processes are cancelled, their
// chunks go back to the queue, and the round resumes in the next window.
// A chunk too big for any window is split. Time, the scan backend, DNS and
// the HTTP transport are injected, so all of this can be tested deterministically.

#include <atomic>
#include <functional>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "backend.hpp"
#include "clock.hpp"
#include "job.hpp"
#include "planner.hpp"
#include "proculus/results/results.hpp"
#include "proculus/sig/signature.hpp"
#include "proculus/timing/rate.hpp"
#include "prober.hpp"
#include "resolver.hpp"
#include "schedule.hpp"

namespace proculus {

struct WebStageConfig {
	bool enabled = false;
	double requests_per_second = 10; // in total, over all web workers
	unsigned workers = 4;
	size_t max_paths = 8;            // extra signature paths per service (0: none)
	bool builtin_signatures = true;
	std::vector<std::string> signature_paths; // files or directories of custom signatures
};

struct RunnerConfig {
	// ---- what to scan (hard limits first: nothing outside them is ever touched)
	std::string scope;           // required
	std::string allowed_ports;   // required
	std::vector<std::string> targets;    // IP, CIDR, range or domain, one per entry
	std::vector<std::string> exclusions; // never scanned
	std::string ports;           // services stage; empty = every allowed port
	bool allow_reserved = false; // loopback, multicast, ...

	// ---- how hard
	unsigned workers = 2;        // nmap processes at once
	int rate = 100;              // packets per second per nmap process (total = workers x rate)
	int timing = 3;              // nmap -T, 0..4
	int retries = 1;
	int host_timeout_s = 60;
	bool privileged = false;     // raw sockets (SYN scan, ICMP ping): needs root or CAP_NET_RAW
	bool version_detect = true;
	std::string nmap_path = "nmap";
	double chunk_seconds = 120;  // aimed duration of one chunk
	double assumed_discovery_rate = 50;  // addresses/s per worker, until measured
	double assumed_services_rate = 0.5;  // hosts/s per worker, until measured
	int max_attempts = 3;        // tries per chunk before the round fails

	// ---- when
	std::optional<Schedule> schedule; // unset: run now, with no window

	// ---- web probing of the web services found
	WebStageConfig web;
};

struct RoundReport {
	int64_t run_id = 0; // 0 if not saved
	TimePoint started, finished;
	uint64_t addresses = 0;
	int chunks = 0, pauses = 0, cancelled_chunks = 0, splits = 0, retries = 0;
	size_t live_hosts = 0, services = 0;
	size_t web_probed = 0, web_responding = 0, detections = 0;
	double discovery_rate = 0, services_rate = 0; // measured, per worker
	std::vector<std::string> warnings;            // invalid lines, domains that do not resolve or leave the scope, ...
};

// A fatal problem: a chunk that keeps failing, an impossible schedule, ...
struct ScanError : std::runtime_error {
	using std::runtime_error::runtime_error;
};
// The round was stopped on request; nothing was saved.
struct RunAborted : std::runtime_error {
	RunAborted() : std::runtime_error("scan stopped") {}
};

// Where a round is, for a status display. Reported after every change; the
// callback runs on a worker thread, under a lock, so it must return quickly.
struct LiveHost {
	std::string ip;
	std::vector<int> ports; // open ports found so far (the services stage fills them in)
};

struct ScanProgress {
	std::string stage;         // starting, waiting for the window, discovery, services, web, saving, done
	std::vector<LiveHost> recent; // the most recent hosts that answered (at most 8), oldest first, for a live view
	size_t chunks_done = 0;    // in the current stage
	size_t chunks_total = 0;   // grows when a chunk is split
	size_t hosts_found = 0;
	int pauses = 0;
};

struct RunnerDeps {
	Clock* clock = nullptr; // required
	// Makes the scan backend; the given flag is the runner's cancel switch (the
	// nmap backend watches it). Default: the real nmap.
	std::function<std::unique_ptr<ScanBackend>(std::atomic<bool>& cancel)> make_backend;
	Resolver resolver;                 // default: system_resolve
	HttpTransport* transport = nullptr; // web stage; default: real sockets
	ResultStore* store = nullptr;      // unset: the round is not saved
	std::ostream* log = nullptr;
	std::function<void(const ScanProgress&)> on_progress;
	// Cancel running scans when the window closes (a real clock needs it; tests
	// with a virtual clock let their fake backend report the cut-off instead).
	bool deadline_watchdog = true;
};

class Runner {
public:
	// Throws std::invalid_argument for an unusable configuration (no scope, no
	// allowed ports, bad schedule, bad custom signatures, ...).
	Runner(RunnerConfig config, RunnerDeps deps);
	~Runner();

	// One round. Throws std::invalid_argument for targets outside the scope,
	// ScanError, RunAborted. Callable repeatedly (rounds are spaced by the schedule).
	RoundReport run_round();

	// Safe from another thread or a signal handler.
	void request_stop();

	// The end of the current scan window, if there is a schedule.
	std::optional<TimePoint> deadline() const;

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace proculus

#endif // PROCULUS_RUNNER_HPP
