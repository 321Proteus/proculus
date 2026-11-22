#include "proculus/sig/regex.hpp"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include <vector>

namespace proculus::sig {

struct Regex::Impl {
	pcre2_code* code = nullptr;
	~Impl() { pcre2_code_free(code); }
};

std::shared_ptr<Regex> Regex::compile(const std::string& pattern, bool caseless, std::string& error) {
	if (pattern.empty()) {
		error = "empty pattern";
		return nullptr;
	}
	if (pattern.size() > kMaxPatternLength) {
		error = "pattern is longer than " + std::to_string(kMaxPatternLength) + " characters";
		return nullptr;
	}
	int code = 0;
	PCRE2_SIZE offset = 0;
	uint32_t options = PCRE2_NEVER_BACKSLASH_C; // \C can split characters; not needed
	if (caseless) options |= PCRE2_CASELESS;
	pcre2_code* compiled = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(pattern.data()), pattern.size(), options, &code, &offset, nullptr);
	if (!compiled) {
		PCRE2_UCHAR msg[256];
		pcre2_get_error_message(code, msg, sizeof msg);
		error = std::string(reinterpret_cast<char*>(msg)) + " (at position " + std::to_string(offset) + ")";
		return nullptr;
	}
	std::shared_ptr<Regex> re(new Regex());
	re->impl_ = std::make_unique<Impl>();
	re->impl_->code = compiled;
	re->pattern_ = pattern;
	uint32_t captures = 0;
	pcre2_pattern_info(compiled, PCRE2_INFO_CAPTURECOUNT, &captures);
	re->groups_ = static_cast<int>(captures);
	return re;
}

Regex::~Regex() = default;

Regex::Result Regex::search(std::string_view subject, std::string* capture, int group) const {
	if (subject.size() > kMaxSubjectLength) subject = subject.substr(0, kMaxSubjectLength);

	pcre2_match_context* ctx = pcre2_match_context_create(nullptr);
	pcre2_set_match_limit(ctx, 200000); // backtracking steps
	pcre2_set_depth_limit(ctx, 2000);
	pcre2_set_heap_limit(ctx, 4096);    // KiB
	pcre2_match_data* md = pcre2_match_data_create_from_pattern(impl_->code, nullptr);

	const int rc = pcre2_match(impl_->code, reinterpret_cast<PCRE2_SPTR>(subject.data()), subject.size(), 0, 0, md, ctx);
	Result result;
	if (rc >= 0) {
		result = Result::Match;
		if (capture) {
			capture->clear();
			if (group >= 0 && group < rc) {
				const PCRE2_SIZE* ov = pcre2_get_ovector_pointer(md);
				if (ov[2 * group] != PCRE2_UNSET) capture->assign(subject.substr(ov[2 * group], ov[2 * group + 1] - ov[2 * group]));
			}
		}
	} else if (rc == PCRE2_ERROR_NOMATCH) {
		result = Result::NoMatch;
	} else {
		// match limit, depth limit, heap limit, or any other failure: stop and say so
		result = Result::LimitExceeded;
	}
	pcre2_match_data_free(md);
	pcre2_match_context_free(ctx);
	return result;
}

} // namespace proculus::sig
