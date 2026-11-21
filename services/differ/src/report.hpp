#ifndef PROCULUS_REPORT_HPP
#define PROCULUS_REPORT_HPP

#include <string>
#include <vector>

#include "compare.hpp"
#include "track.hpp"

namespace proculus {

struct ReportOptions {
	bool json = false;
	bool all = false;    // list everything instead of the first few entries of each kind
	bool events = false; // tracking: also list the individual events of every run
};

// Two runs side by side.
std::string render_comparison(const RunRecord& before, const RunRecord& after, const Comparison& c, const ReportOptions& o);

// The history of a replay: one line (or object) per run, and the final state of every host.
std::string render_tracking(const std::vector<RunUpdate>& updates, const Tracker& tracker, const ReportOptions& o);

} // namespace proculus

#endif // PROCULUS_REPORT_HPP
