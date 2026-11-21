#include "proculus/netutil/target.h"

#include <string.h>

static int is_space(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}
static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_alpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int looks_like_ip(const char* s) {
	for (; *s; s++) {
		if (!is_digit(*s) && *s != '.' && *s != '/' && *s != '-') return 0;
	}
	return 1;
}

static int parse_domain(const char* s, size_t n, char* out) {
	if (n == 0 || n > 253) return -1;
	size_t label_len = 0;
	int label_all_digits = 1;

	for (size_t i = 0; i < n; i++) {
		char c = s[i];
		if (c == '.') {
			if (label_len == 0 || s[i - 1] == '-') return -1;
			label_len = 0;
			label_all_digits = 1;
			out[i] = '.';
			continue;
		}

		if (is_alpha(c)) {
			label_all_digits = 0;
			out[i] = (char)(c | ' '); // lowercase

		} else if (is_digit(c)) {
			out[i] = c;

		} else if (c == '-') {
			if (label_len == 0) return -1;

			label_all_digits = 0;
			out[i] = c;

		} else {
			return -1;
		}

		if (++label_len > 63) return -1;
	}
	if (label_len == 0 || s[n - 1] == '-') return -1;
	if (label_all_digits) return -1; // last label must not be numeric

	out[n] = '\0';
	return 0;
}

int pc_target_parse(const char* s, pc_target* out) {
	if (!out) return -1;

	memset(out, 0, sizeof *out);
	if (!s) return -1;

	while (is_space(*s))
		s++;
	size_t n = strlen(s);
	while (n > 0 && is_space(s[n - 1]))
		n--;
	if (n == 0 || n >= 256) return -1;

	char buf[256];
	memcpy(buf, s, n);
	buf[n] = '\0';

	if (looks_like_ip(buf)) {
		if (pc_range_parse(buf, &out->range) != 0) return -1;
		out->kind = strchr(buf, '/') ? PC_TARGET_CIDR
			: strchr(buf, '-')		 ? PC_TARGET_RANGE
									 : PC_TARGET_IP;
		return 0;
	}

	if (buf[n - 1] == '.') n--; // abs name
	if (parse_domain(buf, n, out->domain) != 0) {
		out->domain[0] = '\0';
		return -1;
	}
	out->kind = PC_TARGET_DOMAIN;
	return 0;
}

const char* pc_target_kind_name(pc_target_kind k) {
	switch (k) {
	case PC_TARGET_IP:	   return "ip";
	case PC_TARGET_CIDR:   return "cidr";
	case PC_TARGET_RANGE:  return "range";
	case PC_TARGET_DOMAIN: return "domain";
	default:			   return "invalid";
	}
}
