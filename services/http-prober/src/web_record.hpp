#ifndef PROCULUS_WEB_RECORD_HPP
#define PROCULUS_WEB_RECORD_HPP

// Converts what the prober saw (and what the signatures concluded) into the
// stored form kept in a run (see libs/results).

#include <vector>

#include "proculus/results/results.hpp"
#include "proculus/sig/engine.hpp"
#include "prober.hpp"

namespace proculus {

DetectionRecord to_detection_record(const sig::Detection& d);

// Headers are kept (Set-Cookie values are already redacted by the prober), the
// body is not. Lists and text are capped so one odd service cannot bloat a run.
WebRecord to_web_record(const HttpObservation& o, const std::vector<sig::Detection>& detections);

} // namespace proculus

#endif // PROCULUS_WEB_RECORD_HPP
