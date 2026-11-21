#include "proculus/range.h"

#include <stdlib.h>
#include <string.h>

pc_range pc_cidr_to_range(const pc_cidr* c) {
	pc_range r;
	r.lo = c->base;
	r.hi = (uint32_t)(c->base + (pc_cidr_count(c) - 1));
	return r;
}

uint64_t pc_range_count(const pc_range* r) {
	return (uint64_t)r->hi - r->lo + 1;
}

int pc_range_parse(const char* s, pc_range* out) {
	if (!s || !out) return -1;

	const char* dash = strchr(s, '-');
	if (!dash) {
		pc_cidr c;
		if (pc_cidr_parse(s, &c) != 0) return -1;

		*out = pc_cidr_to_range(&c);
		return 0;
	}

	size_t n = (size_t)(dash - s);
	char left[PC_IP_STR_MAX];
	if (n == 0 || n >= sizeof left) return -1;

	memcpy(left, s, n);
	left[n] = '\0';

	uint32_t lo, hi;
	if (pc_ip_parse(left, &lo) != 0) return -1;

	const char* right = dash + 1;
	if (strchr(right, '.')) {
		if (pc_ip_parse(right, &hi) != 0) return -1;

	} else {
		// nmap-style "a.b.c.d-N", replace the last octet
		if (*right < '0' || *right > '9') return -1;
		if (*right == '0' && right[1] != '\0') return -1;

		char* end;
		unsigned long v = strtoul(right, &end, 10);
		if (*end != '\0' || v > 255) return -1;

		hi = (lo & 0xffffff00u) | (uint32_t)v;
	}

	if (lo > hi) return -1;

	out->lo = lo;
	out->hi = hi;
	return 0;
}
