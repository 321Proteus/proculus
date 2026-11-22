#include "proculus/sig/builtin.hpp"

#include <stdexcept>

namespace proculus::sig {

SignatureSet builtin_signatures() {
	SignatureSet set;
	LoadPolicy policy;
	policy.max_probe_paths = 1000; // the limit exists for user files, not for ours
	std::string problems;
	for (const BuiltinSource& src : builtin_sources()) {
		const LoadResult r = set.add_json(src.json, std::string("builtin:") + src.name, true, policy);
		for (const Diagnostic& d : r.diagnostics)
			if (d.level == Diagnostic::Level::Error) problems += describe(d) + "\n";
	}
	if (!problems.empty()) throw std::logic_error("the built-in signatures are invalid:\n" + problems);
	return set;
}

} // namespace proculus::sig
