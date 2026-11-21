#undef NDEBUG
#include <cassert>
#include <chrono>
#include <functional>

#include "proculus/sig/regex.hpp"

using namespace proculus::sig;

static std::shared_ptr<Regex> compile(const std::string& p, bool caseless = false) {
	std::string error;
	auto re = Regex::compile(p, caseless, error);
	assert(re && error.empty());
	return re;
}

static void test_matching_and_captures() {
	auto re = compile("nginx/([0-9.]+)");
	std::string cap;
	assert(re->search("Server: nginx/1.24.0 (Ubuntu)", &cap) == Regex::Result::Match && cap == "1.24.0");
	assert(re->search("Server: Apache", &cap) == Regex::Result::NoMatch);
	assert(re->group_count() == 1 && re->pattern() == "nginx/([0-9.]+)");

	assert(compile("NGINX", true)->search("nginx") == Regex::Result::Match);          // caseless on request
	assert(compile("NGINX", false)->search("nginx") == Regex::Result::NoMatch);
	assert(compile("(?i)nginx")->search("NGINX") == Regex::Result::Match);            // or inline
	assert(compile("^wp-")->search("wp-login") == Regex::Result::Match && compile("^wp-")->search("a wp-") == Regex::Result::NoMatch);

	// groups: a group that did not take part is empty; a missing group number gives empty
	std::string c2 = "stale";
	assert(compile("a(b)?c")->search("ac", &c2) == Regex::Result::Match && c2.empty());
	std::string c3 = "stale";
	assert(compile("abc")->search("xabcx", &c3, 1) == Regex::Result::Match && c3.empty());
	assert(compile("(a)(b)")->search("ab", &c3, 2) == Regex::Result::Match && c3 == "b");
	assert(compile("abc")->search("abc", nullptr) == Regex::Result::Match);                 // capture is optional

	// bytes, not text: non-UTF-8 input is just bytes
	assert(compile("caf.")->search(std::string("caf\xe9 au lait")) == Regex::Result::Match);
	assert(compile("\\x00")->search(std::string("a\0b", 3)) == Regex::Result::Match);
	assert(compile("a.c")->search("a\nc") == Regex::Result::NoMatch);                      // dot excludes newline, as usual
	assert(compile("(?s)a.c")->search("a\nc") == Regex::Result::Match);
}

static void test_rejected_patterns() {
	std::string error;
	for (const char* bad : {"", "(unclosed", "[a-", "*start", "a{2,1}", "(?<n>x)(?<n>y)", "\\"}) {
		error.clear();
		assert(!Regex::compile(bad, false, error) && !error.empty());
	}
	error.clear();
	assert(!Regex::compile(std::string(501, 'a'), false, error) && error.find("longer than") != std::string::npos);
	assert(Regex::compile(std::string(500, 'a'), false, error));
	error.clear();
	assert(!Regex::compile("a\\C", false, error));            // \C is refused
	assert(error.find("(at position") != std::string::npos);
}

static double seconds_of(const std::function<void()>& f) {
	const auto t0 = std::chrono::steady_clock::now();
	f();
	return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

static void test_hostile_input_is_bounded() {
	// the classic catastrophic backtracking cases: each must come back quickly and say so
	const std::string evil_subject(60000, 'a');
	for (const char* pattern : {"(a+)+$", "(a|aa)+$", "(.*a){12}x", "^(a+)+b", "(x+x+)+y", "((a*)*)*b"}) {
		auto re = compile(pattern);
		Regex::Result r = Regex::Result::NoMatch;
		const double t = seconds_of([&] { r = re->search(evil_subject + "!"); });
		assert(t < 2.0);                                                   // bounded, not exponential
		assert(r == Regex::Result::LimitExceeded || r == Regex::Result::NoMatch || r == Regex::Result::Match);
	}
	// at least the textbook one must have been cut off by a limit, not by luck
	auto re = compile("(a+)+$");
	assert(re->search(std::string(40, 'a') + "!") == Regex::Result::LimitExceeded);
	assert(compile("(a+)+$")->search(std::string(40, 'a')) == Regex::Result::Match);   // the same pattern on benign input works

	// a huge subject is cut to the cap rather than scanned in full
	const std::string huge(5 << 20, 'z');
	auto lit = compile("zzzz");
	const double t = seconds_of([&] { assert(lit->search(huge) == Regex::Result::Match); });
	assert(t < 1.0);
	std::string tail_only = std::string(Regex::kMaxSubjectLength, 'q') + "needle";
	assert(compile("needle")->search(tail_only) == Regex::Result::NoMatch);          // beyond the cap: not seen, by design

	// after a limit hit the regex is still usable
	assert(re->search("aaa") == Regex::Result::Match);
}

int main() {
	test_matching_and_captures();
	test_rejected_patterns();
	test_hostile_input_is_bounded();
	return 0;
}
