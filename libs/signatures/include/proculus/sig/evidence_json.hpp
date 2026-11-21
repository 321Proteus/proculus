#ifndef PROCULUS_SIG_EVIDENCE_JSON_HPP
#define PROCULUS_SIG_EVIDENCE_JSON_HPP

// Evidence as a flat JSON object, e.g.
//   {"status": 200, "title": "Welcome", "header:server": ["nginx/1.24.0"], "cookie": ["PHPSESSID"]}
// Used for examples inside signature files, for dumping what a target looks
// like, and for testing a signature against captured evidence.

#include <nlohmann/json.hpp>

#include <string>
#include <utility>
#include <vector>

#include "proculus/sig/evidence.hpp"

namespace proculus::sig {

// A problem found while reading evidence: where (the field name) and what.
using EvidenceProblem = std::pair<std::string, std::string>;

// Reads `j` into `out`. Every field must be known and its value of the right
// type; a list field also accepts a single string. Returns false if anything
// was wrong, with each problem in `problems`; valid fields are still added.
bool evidence_from_json(const nlohmann::json& j, Evidence& out, std::vector<EvidenceProblem>& problems);

nlohmann::ordered_json evidence_to_json(const Evidence& evidence);

} // namespace proculus::sig

#endif // PROCULUS_SIG_EVIDENCE_JSON_HPP
