#ifndef PROCULUS_INSIGHT_INTEREST_HPP
#define PROCULUS_INSIGHT_INTEREST_HPP

// How much an analyst should care about a service ("ciekawość" / priority).
//
// The score is 0-100 and always comes with the reasons behind it, so a person
// can check why something is ranked high. It is built from what the signatures
// found (their own 0-5 interest, scaled by confidence) and from what is
// exposed at all (remote administration and database ports on a network are
// worth a look even if no signature matched). Hygiene problems such as an
// expired certificate are signatures themselves and arrive through them.

#include <string>
#include <vector>

#include "proculus/results/results.hpp"

namespace proculus {

struct Interest {
	int score = 0; // 0-100
	std::vector<std::string> reasons;
};

Interest score_service(const ServiceRecord& service);

// "high" (>= 70), "medium" (>= 40), "low" (>= 15), "info".
const char* interest_level(int score);

} // namespace proculus

#endif // PROCULUS_INSIGHT_INTEREST_HPP
