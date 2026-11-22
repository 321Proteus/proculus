#ifndef PROCULUS_PROCESS_HPP
#define PROCULUS_PROCESS_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace proculus {

struct RunOptions {
	std::chrono::seconds timeout{ 600 };
	size_t max_output = 64u
		<< 20; // bytes of stdout kept before the child is killed
	std::atomic<bool>* cancel = nullptr; // set to true to abort the run
	std::chrono::milliseconds kill_grace{ 2000 };
	// Called after output arrived, with all of stdout so far (on the calling thread, so keep it short).
	std::function<void(const std::string&)> on_output;
};

struct RunResult {
	int exit_code = -1; // -1 if it did not exit normally; 127 if exec failed
	int term_signal = 0; // signal that ended the child, if any
	bool timed_out = false;
	bool cancelled = false;
	bool output_truncated = false;
	std::string out;
	std::string err;
};

// Runs argv[0] with the given arguments (no shell), capturing stdout/stderr.
// The child gets its own process group; on timeout, cancel or output overflow
// the whole group receives SIGTERM, then SIGKILL after `kill_grace`.
// Throws std::runtime_error if the process cannot be created.
RunResult run_process(
	const std::vector<std::string>& argv, const RunOptions& opts = {});

} // namespace proculus

#endif // PROCULUS_PROCESS_HPP
