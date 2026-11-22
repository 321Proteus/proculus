#ifndef PROCULUS_EXPORTER_DOJO_HPP
#define PROCULUS_EXPORTER_DOJO_HPP

// A run as a DefectDojo "Generic Findings Import" document (JSON), ready for
// POST /api/v2/import-scan/ or reimport-scan/ with scan_type "Generic Findings Import".
//
// One finding per service. Its unique_id_from_tool is "ip:port/protocol", so a
// re-import of a later run matches the same finding instead of making a new one.
// Severity comes from the priority level of libs/insight (high -> High, medium ->
// Medium, low -> Low, info -> Info). Everything that comes from a scanned machine
// is untrusted and DefectDojo renders descriptions as Markdown, so it is
// stripped of control characters, shortened and Markdown-escaped.

#include <string>

#include "proculus/results/results.hpp"

namespace proculus {

// "info", "low", "medium" or "high"; throws std::invalid_argument otherwise.
int parse_dojo_min_level(const std::string& name);

// Services below `min_level` (0 info, 1 low, 2 medium, 3 high) are left out.
std::string render_dojo(const RunRecord& run, int min_level = 1);

// Control characters -> space, cut to `max` bytes (at a character boundary), Markdown/HTML escaped.
std::string dojo_text(const std::string& value, size_t max = 200);

} // namespace proculus

#endif
