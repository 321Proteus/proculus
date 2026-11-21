#ifndef PROCULUS_RENDER_HPP
#define PROCULUS_RENDER_HPP

// Turns stored scan runs into text for people and files for other tools.

#include <string>
#include <vector>

#include "proculus/results/results.hpp"

namespace proculus {

enum class Format { Text, Json, Csv };

// "text", "json" or "csv"; throws std::invalid_argument otherwise.
Format parse_format(const std::string& name);

// One run in full.
std::string render_run(const RunRecord& run, Format f);

// All runs, one line each.
std::string render_list(const std::vector<RunSummary>& runs, Format f);

// RFC 4180 quoting for one CSV field. With `guard`, a field that a spreadsheet
// would treat as a formula (starting with = + - @ or a control character) gets
// a leading apostrophe: banners and titles come from scanned machines, which
// are not trusted.
std::string csv_field(const std::string& value, bool guard = true);

} // namespace proculus

#endif // PROCULUS_RENDER_HPP
