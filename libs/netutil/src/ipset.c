#include "proculus/ipset.h"

#include <stdlib.h>
#include <string.h>

void pc_ipset_init(pc_ipset* s) {
	s->ranges = NULL;
	s->len = s->cap = 0;
	s->dirty = 0;
}

void pc_ipset_free(pc_ipset* s) {
	free(s->ranges);
	pc_ipset_init(s);
}

static int reserve(pc_ipset* s, size_t need) {
	if (need <= s->cap) return 0;

	size_t cap = s->cap ? s->cap : 8;
	while (cap < need) {
		if (cap > SIZE_MAX / 2 / sizeof(pc_range)) return -1;
		cap *= 2;
	}

	pc_range* p = realloc(s->ranges, cap * sizeof *p);
	if (!p) return -1;

	s->ranges = p;
	s->cap = cap;

	return 0;
}

static int cmp_range(const void* a, const void* b) {
	uint32_t x = ((const pc_range*)a)->lo, y = ((const pc_range*)b)->lo;
	return (x > y) - (x < y);
}

/* Sort and merge overlapping or adjacent ranges. */
static void normalize(pc_ipset* s) {
	if (!s->dirty) return;

	s->dirty = 0;
	if (s->len < 2) return;

	qsort(s->ranges, s->len, sizeof *s->ranges, cmp_range);
	size_t w = 0;
	for (size_t i = 1; i < s->len; i++) {
		/* 64-bit math so hi == UINT32_MAX does not wrap. */
		if ((uint64_t)s->ranges[i].lo <= (uint64_t)s->ranges[w].hi + 1) {
			if (s->ranges[i].hi > s->ranges[w].hi)
				s->ranges[w].hi = s->ranges[i].hi;
		} else {
			s->ranges[++w] = s->ranges[i];
		}
	}

	s->len = w + 1;
}

int pc_ipset_add_range(pc_ipset* s, pc_range r) {
	if (r.lo > r.hi) return -1;

	if (reserve(s, s->len + 1) != 0) return -1;

	s->ranges[s->len++] = r;
	s->dirty = 1;

	return 0;
}

int pc_ipset_add_cidr(pc_ipset* s, const pc_cidr* c) {
	return pc_ipset_add_range(s, pc_cidr_to_range(c));
}

int pc_ipset_add_spec(pc_ipset* s, const char* spec) {
	pc_range r;
	if (pc_range_parse(spec, &r) != 0) return -1;

	return pc_ipset_add_range(s, r);
}

int pc_ipset_subtract_range(pc_ipset* s, pc_range r) {
	if (r.lo > r.hi) return -1;
	normalize(s);
	/* Each existing range yields at most two pieces, so 2*len is enough. */
	pc_range* out = malloc((s->len ? s->len * 2 : 1) * sizeof *out);
	if (!out) return -1;

	size_t w = 0;
	for (size_t i = 0; i < s->len; i++) {
		pc_range c = s->ranges[i];
		if (c.hi < r.lo || c.lo > r.hi) {
			out[w++] = c;
			continue;
		}
		if (c.lo < r.lo) out[w++] = (pc_range){ c.lo, r.lo - 1 };
		if (c.hi > r.hi) out[w++] = (pc_range){ r.hi + 1, c.hi };
	}

	free(s->ranges);
	s->ranges = out;
	s->len = w;
	s->cap = s->len ? s->len * 2 : 1;

	return 0;
}

int pc_ipset_subtract(pc_ipset* s, pc_ipset* other) {
	normalize(other);
	for (size_t i = 0; i < other->len; i++) {
		if (pc_ipset_subtract_range(s, other->ranges[i]) != 0) return -1;
	}
	return 0;
}

int pc_ipset_contains(pc_ipset* s, uint32_t ip) {
	normalize(s);
	size_t lo = 0, hi = s->len;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (ip < s->ranges[mid].lo) hi = mid;

		else if (ip > s->ranges[mid].hi)
			lo = mid + 1;

		else
			return 1;
	}

	return 0;
}

uint64_t pc_ipset_count(pc_ipset* s) {
	normalize(s);
	uint64_t n = 0;

	for (size_t i = 0; i < s->len; i++)
		n += pc_range_count(&s->ranges[i]);

	return n;
}

size_t pc_ipset_range_count(pc_ipset* s) {
	normalize(s);
	return s->len;
}

pc_range pc_ipset_range_at(pc_ipset* s, size_t i) {
	normalize(s);
	return s->ranges[i];
}

int pc_ipset_slice(pc_ipset* s, uint64_t start, uint64_t count, pc_ipset* out) {
	normalize(s);
	uint64_t skip = start;

	for (size_t i = 0; i < s->len && count > 0; i++) {
		pc_range c = s->ranges[i];
		uint64_t n = pc_range_count(&c);
		if (skip >= n) {
			skip -= n;
			continue;
		}

		uint64_t take = n - skip;
		if (take > count) take = count;

		pc_range piece = { (uint32_t)(c.lo + skip),
			(uint32_t)(c.lo + skip + take - 1) };

		if (pc_ipset_add_range(out, piece) != 0) return -1;

		count -= take;
		skip = 0;
	}

	return 0;
}

static int is_sep(char c) {
	return c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

int pc_ipset_add_list(pc_ipset* s, const char* list) {
	if (!list) return -1;
	size_t orig_len = s->len;
	int orig_dirty = s->dirty;
	const char* p = list;

	while (*p) {
		if (is_sep(*p)) {
			p++;
			continue;
		}

		const char* start = p;
		while (*p && !is_sep(*p))
			p++;
		char tok[64];

		size_t n = (size_t)(p - start);
		if (n >= sizeof tok) goto fail;

		memcpy(tok, start, n);
		tok[n] = '\0';

		if (pc_ipset_add_spec(s, tok) != 0) goto fail;
	}
	return 0;

fail:
	s->len = orig_len;
	s->dirty = orig_dirty;
	return -1;
}

int pc_ipset_subtract_reserved(pc_ipset* s) {
	// 0/8, 127/8, 169.254/16, 224.0.0.0 - 255.255.255.255
	static const pc_range reserved[] = {
		{ 0x00000000u, 0x00ffffffu },
		{ 0x7f000000u, 0x7fffffffu },
		{ 0xa9fe0000u, 0xa9feffffu },
		{ 0xe0000000u, 0xffffffffu },
	};

	for (size_t i = 0; i < sizeof reserved / sizeof *reserved; i++) {
		if (pc_ipset_subtract_range(s, reserved[i]) != 0) return -1;
	}

	return 0;
}

char* pc_ipset_format(pc_ipset* s, char sep) {
	normalize(s);
	// <= 62 blocks per range, each at most 255.255.255.255/32 + sep
	char* buf = malloc(s->len * PC_RANGE_MAX_CIDRS * PC_CIDR_STR_MAX + 1);
	if (!buf) return NULL;

	char* w = buf;
	int first = 1;

	for (size_t i = 0; i < s->len; i++) {
		pc_cidr blocks[PC_RANGE_MAX_CIDRS];
		int n = pc_range_to_cidrs(&s->ranges[i], blocks, PC_RANGE_MAX_CIDRS);

		for (int k = 0; k < n; k++) {
			if (!first) *w++ = sep;
			first = 0;

			if (blocks[k].prefix == 32) {
				pc_ip_format(blocks[k].base, w);
			} else
				pc_cidr_format(&blocks[k], w);

			w += strlen(w);
		}
	}

	*w = '\0';
	return buf;
}
