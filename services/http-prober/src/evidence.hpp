#ifndef PROCULUS_PROBER_EVIDENCE_HPP
#define PROCULUS_PROBER_EVIDENCE_HPP

// Turns what the prober saw into the named facts signatures are matched
// against (see libs/signatures fields.hpp).

#include "proculus/sig/evidence.hpp"
#include "prober.hpp"

namespace proculus {

sig::Evidence to_evidence(const HttpObservation& o);

} // namespace proculus

#endif // PROCULUS_PROBER_EVIDENCE_HPP
