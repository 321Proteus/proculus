#ifndef PROCULUS_SIG_SIGNATURE_HPP
#define PROCULUS_SIG_SIGNATURE_HPP

// Signatures: declarative descriptions of how to recognise a technology, a
// product, an admin panel or an environment from what a service shows.
//
// A signature is a set of weighted *signals*. Each signal is a condition on the
// evidence (a header, a cookie, text in the page, a favicon fingerprint, a
// certificate property, a path that exists, ...). The signature's confidence is
// 1 - prod(1 - weight) over the signals that matched, so independent
// corroboration raises certainty, and it is reported once that reaches the
// signature's threshold. Signatures only ever *detect*: they describe what to
// look for in responses and which harmless paths to look at, never what to send.
//
// Files are JSON; see signatures/README.md for the format.

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "proculus/sig/evidence.hpp"
#include "proculus/sig/fields.hpp"
#include "proculus/sig/regex.hpp"

namespace proculus::sig {

enum class Category { Cms, Framework, Server, Iot, Staging, Admin, Other };

const char* to_string(Category c);
std::optional<Category> parse_category(const std::string& name);

struct Leaf {
	std::string field;
	FieldType field_type = FieldType::String;
	Op op = Op::Equals;
	std::vector<std::string> strings;            // alternatives: any of them matches
	std::vector<std::string> lowered_strings;    // the same in lowercase (filled for case-insensitive string matching)
	std::vector<double> numbers;                 // alternatives for equals; the comparison value for gt/ge/lt/le
	bool flag = true;                            // bool fields: the expected value. exists: true = must exist, false = must be absent
	bool case_sensitive = false;                 // string matching ignores case unless this is set
	std::vector<std::shared_ptr<Regex>> regexes; // compiled alternatives for the regex operator
};

struct Condition {
	enum class Kind { Leaf, All, Any, Not };
	Kind kind = Kind::Leaf;
	Leaf leaf;                       // Kind::Leaf
	std::vector<Condition> children; // All / Any: one or more; Not: exactly one
};

struct Signal {
	double weight = 0;     // 0 < weight <= 1: how strongly this alone suggests the technology
	bool required = false; // the signature is not reported unless this signal matched
	std::string label;     // optional description for reports
	Condition match;
};

struct VersionRule {
	std::string field;
	FieldType field_type = FieldType::String;
	std::shared_ptr<Regex> regex; // exactly one capture group: the version
};

// A built-in check: this evidence must (not) trigger this signature.
struct Example {
	std::string name;
	Evidence evidence;
	bool expect_match = true;
	std::string expect_version; // if non-empty, the version the detection must report
};

struct Signature {
	std::string id;   // unique: lowercase letters, digits, '.', '_', '-'
	std::string name;
	Category category = Category::Other;
	std::vector<std::string> tags;
	int interest = 0; // 0-5: how much an analyst should care that this is present
	std::string description;
	std::vector<std::string> references;
	double threshold = 0.5;
	std::vector<Signal> signals;
	std::optional<Condition> exclude; // if it matches, the signature does not apply
	std::optional<VersionRule> version;
	std::vector<Example> examples;
	bool enabled = true;
	bool builtin = false;
	std::string source; // file name, or "builtin:<name>"
};

struct Diagnostic {
	enum class Level { Error, Warning } level = Level::Error;
	std::string source;
	std::string signature; // id, or "" for problems with the file itself
	std::string where;     // path inside the document, e.g. "signals[1].match.all[0].value"
	std::string message;
};

struct LoadPolicy {
	size_t max_signatures_per_source = 2000;
	// How many distinct extra paths one source may ask the prober to fetch. This
	// is what stops a custom signature file from turning the scanner into a
	// path brute-forcer.
	size_t max_probe_paths = 20;
};

struct LoadResult {
	size_t loaded = 0; // signatures accepted from this source
	std::vector<Diagnostic> diagnostics;

	size_t errors() const;
	size_t warnings() const;
	bool has_errors() const { return errors() > 0; }
};

std::string describe(const Diagnostic& d); // "file: signature-id: where: message"

class SignatureSet {
public:
	// Adds the signatures in a JSON document. A signature with an error is left
	// out and reported; the others are still added. A document that is not even
	// valid JSON adds nothing. Never throws for bad input.
	LoadResult add_json(const std::string& text, const std::string& source, bool builtin = false, const LoadPolicy& policy = {});
	LoadResult add_file(const std::filesystem::path& file, bool builtin = false, const LoadPolicy& policy = {});
	// Every *.json in the directory, in name order.
	LoadResult add_directory(const std::filesystem::path& dir, bool builtin = false, const LoadPolicy& policy = {});

	const std::vector<Signature>& all() const { return signatures_; }
	size_t size() const { return signatures_.size(); }
	size_t enabled_count() const;
	const Signature* find(const std::string& id) const;
	bool set_enabled(const std::string& id, bool enabled);

	// The distinct extra paths that enabled signatures look at, most valuable
	// first: by the highest interest of the signatures that want the path, then
	// by how many want it, then by name. At most `limit` of them if limit > 0,
	// so a small budget is spent on the findings that matter most.
	std::vector<std::string> required_paths(size_t limit = 0) const;

private:
	std::vector<Signature> signatures_;
};

} // namespace proculus::sig

#endif // PROCULUS_SIG_SIGNATURE_HPP
