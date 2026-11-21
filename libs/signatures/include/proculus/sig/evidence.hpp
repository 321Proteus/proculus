#ifndef PROCULUS_SIG_EVIDENCE_HPP
#define PROCULUS_SIG_EVIDENCE_HPP

// What is known about a service, as named facts: "status" -> 200,
// "header:server" -> ["nginx/1.24.0"], "title" -> "Welcome", ...
//
// The signature engine knows nothing about HTTP or about where the facts came
// from. Whoever observed the service (the web prober, an nmap result, a test)
// fills an Evidence, and signatures are matched against it. The names and
// types of the fields are listed in fields.hpp.

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace proculus::sig {

class Evidence {
public:
	using Value = std::variant<std::string, double, bool, std::vector<std::string>>;

	// Setting a field replaces what it held before.
	void set(const std::string& field, std::string value);
	void set(const std::string& field, const char* value) { set(field, std::string(value)); }
	void set(const std::string& field, double value);
	void set(const std::string& field, int value) { set(field, static_cast<double>(value)); }
	void set(const std::string& field, bool value);
	void set_list(const std::string& field, std::vector<std::string> values);
	// Appends to a list field (creating it if needed).
	void add(const std::string& field, std::string value);

	bool has(const std::string& field) const { return values_.count(field) != 0; }
	const Value* find(const std::string& field) const;
	size_t size() const { return values_.size(); }
	const std::map<std::string, Value>& all() const { return values_; }

	// Lowercase copy of a string field, computed once and kept: most matching is
	// case-insensitive and bodies are large. Empty if the field is not a string.
	const std::string& lowered(const std::string& field) const;

private:
	std::map<std::string, Value> values_;
	mutable std::map<std::string, std::string> lower_cache_;
};

} // namespace proculus::sig

#endif // PROCULUS_SIG_EVIDENCE_HPP
