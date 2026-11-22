#ifndef PROCULUS_INSIGHT_DASHBOARD_HPP
#define PROCULUS_INSIGHT_DASHBOARD_HPP

// What the main dashboard shows about a run: how big it is, what changed since
// the previous one, and the most interesting services.

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "proculus/insight/interest.hpp"
#include "proculus/results/results.hpp"

namespace proculus {

// One service of one host with its score: a row of the findings table.
// One technology detected on a service, for showing and filtering by category (cms, framework, server, iot, admin, staging, other, or a custom signature's own).
struct Technology {
	std::string name, version, category;
};

struct Finding {
	std::string ip, hostname;
	uint16_t port = 0;
	std::string protocol, service; // service: "nginx 1.24.0", or the nmap name
	std::string title;             // web page title, if probed
	int score = 0;
	std::string level;
	std::vector<std::string> reasons;
	std::vector<std::string> detections; // "WordPress 6.4.2"
	std::vector<Technology> technologies; // the same, split into name, version and category
};

// Every service of the run, most interesting first (then by address, port).
std::vector<Finding> list_findings(const RunRecord& run);

struct ChangeCounts {
	size_t new_hosts = 0, gone_hosts = 0, new_services = 0, gone_services = 0, changed_services = 0, web_changes = 0;
};

struct Dashboard {
	RunSummary run;
	std::optional<RunSummary> previous;
	std::optional<ChangeCounts> changes; // against `previous`
	size_t web_services = 0;             // services with web results
	size_t detections = 0;
	std::vector<std::pair<std::string, size_t>> levels;     // high, medium, low, info (always all four)
	std::vector<std::pair<std::string, size_t>> categories; // detections by category, most frequent first
	std::vector<std::pair<std::string, size_t>> technologies; // detected names (without versions), most frequent first, top 10
	std::vector<Finding> top;                               // the most interesting, at most top_n, score > 0
};

Dashboard build_dashboard(const RunRecord& latest, const RunRecord* previous, size_t top_n = 10);

} // namespace proculus

#endif // PROCULUS_INSIGHT_DASHBOARD_HPP
