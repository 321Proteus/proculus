#ifndef PROCULUS_SIG_BUILTIN_HPP
#define PROCULUS_SIG_BUILTIN_HPP

#include <vector>

#include "proculus/sig/signature.hpp"

namespace proculus::sig {

struct BuiltinSource {
	const char* name; // file name the data came from, e.g. "cms.json"
	const char* json;
};

// The signature files in libs/signatures/builtin/, compiled into the binary so
// nothing has to be installed next to it.
const std::vector<BuiltinSource>& builtin_sources();

// All built-in signatures. Throws std::logic_error describing the problems if
// the embedded data is invalid: that is a defect in the build, not user input.
SignatureSet builtin_signatures();

} // namespace proculus::sig

#endif // PROCULUS_SIG_BUILTIN_HPP
