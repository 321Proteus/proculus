#ifndef PROCULUS_PROBE_REPORT_HPP
#define PROCULUS_PROBE_REPORT_HPP

#include <nlohmann/json.hpp>

#include <string>

#include "prober.hpp"

namespace proculus {

using ProbeJson = nlohmann::ordered_json;

// The observation as JSON. The response body is left out unless `include_body`
// (only its length and SHA-256 are kept): it can be large and may hold secrets.
ProbeJson probe_to_json(const HttpObservation& o, bool include_body = false);

// A short report for people. Text that came from the network is sanitised.
std::string probe_to_text(const HttpObservation& o);

} // namespace proculus

#endif // PROCULUS_PROBE_REPORT_HPP
