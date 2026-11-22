#ifndef PROCULUS_RUNNER_WEB_STAGE_HPP
#define PROCULUS_RUNNER_WEB_STAGE_HPP

#include <atomic>
#include <functional>
#include <iosfwd>
#include <map>
#include <string>
#include <vector>

#include "proculus/results/results.hpp"
#include "proculus/sig/signature.hpp"
#include "runner.hpp"

namespace proculus {

struct WebStageResult {
	size_t probed = 0, responding = 0, detections = 0;
	std::vector<std::string> warnings;
};

// Probes the web services in `run` (with the prober's own scope and port gates)
// and attaches the results and signature detections to them. `hostnames` maps
// an address to the domain it was resolved from (used as Host / SNI).
WebStageResult run_web_stage(RunRecord& run, const RunnerConfig& cfg, HttpTransport& transport, const sig::SignatureSet& signatures,
	const std::map<std::string, std::string>& hostnames, const std::atomic<bool>& stop, std::ostream* log,
	const std::function<void(const std::string& ip, uint16_t port)>& on_probed = {});

} // namespace proculus

#endif // PROCULUS_RUNNER_WEB_STAGE_HPP
