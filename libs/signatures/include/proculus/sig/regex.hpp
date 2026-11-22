#ifndef PROCULUS_SIG_REGEX_HPP
#define PROCULUS_SIG_REGEX_HPP

// Regular expressions for signatures, run against text that comes from the
// network. A backtracking engine on hostile input can be made to run for
// minutes (the classic "(a+)+$" on "aaaa...b"), which would freeze a scanner
// that merely looked at a malicious page. This wrapper therefore runs PCRE2
// with hard limits on match effort, memory and subject size: when a limit is
// hit the search ends at once and reports it, so a bad pattern or a hostile
// page costs a bounded amount of time.

#include <memory>
#include <string>
#include <string_view>

namespace proculus::sig {

class Regex {
public:
	enum class Result {
		Match,
		NoMatch,
		LimitExceeded, // gave up: too much effort or memory (treated as "no match" by the engine)
	};

	static constexpr size_t kMaxPatternLength = 500;
	static constexpr size_t kMaxSubjectLength = 1 << 20; // longer subjects are cut

	// Compiles `pattern` (PCRE2 / Perl syntax, bytes not UTF-8). Returns nullptr
	// and sets `error` if the pattern is too long or invalid.
	static std::shared_ptr<Regex> compile(const std::string& pattern, bool caseless, std::string& error);

	~Regex();
	Regex(const Regex&) = delete;
	Regex& operator=(const Regex&) = delete;

	// Does the pattern match somewhere in `subject`? If it does and `capture`
	// is not null, it receives capture group `group` (empty if that group did
	// not take part).
	Result search(std::string_view subject, std::string* capture = nullptr, int group = 1) const;

	int group_count() const { return groups_; }
	const std::string& pattern() const { return pattern_; }

private:
	Regex() = default;
	struct Impl;
	std::unique_ptr<Impl> impl_;
	std::string pattern_;
	int groups_ = 0;
};

} // namespace proculus::sig

#endif // PROCULUS_SIG_REGEX_HPP
