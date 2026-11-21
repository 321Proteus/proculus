#ifndef PROCULUS_SIG_ENGINE_HPP
#define PROCULUS_SIG_ENGINE_HPP

#include <string>
#include <vector>

#include "proculus/sig/signature.hpp"

namespace proculus::sig {

struct Detection {
	std::string id;
	std::string name;
	Category category = Category::Other;
	std::vector<std::string> tags;
	double confidence = 0; // 0..0.99
	int interest = 0;
	std::string version;   // "" if unknown
	bool builtin = false;
	// What matched, one line per matched signal (and leaf), for people to check.
	std::vector<std::string> evidence;
};

struct EvalStats {
	size_t signatures_evaluated = 0;
	size_t regex_limit_hits = 0; // searches that were cut short by the effort limits
};

// Evaluates one signature. nullopt if it does not apply.
std::optional<Detection> evaluate_signature(const Signature& sig, const Evidence& evidence, EvalStats* stats = nullptr);

// Every enabled signature against the evidence, best first (confidence, then
// interest, then id).
std::vector<Detection> evaluate(const SignatureSet& set, const Evidence& evidence, EvalStats* stats = nullptr);

// Runs the built-in examples of every enabled signature; returns one message
// per failure (empty = all good).
std::vector<std::string> run_examples(const SignatureSet& set);

} // namespace proculus::sig

#endif // PROCULUS_SIG_ENGINE_HPP
