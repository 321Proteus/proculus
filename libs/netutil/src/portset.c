#include "proculus/netutil/portset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pc_portset_init(pc_portset* s) {
	s->ranges = NULL;
	s->len = s->cap = 0;
	s->dirty = 0;
}

void pc_portset_free(pc_portset* s) {
	free(s->ranges);
	pc_portset_init(s);
}

static int cmp_range(const void* a, const void* b) {
	unsigned x = ((const pc_port_range*)a)->lo,
			 y = ((const pc_port_range*)b)->lo;
	return (x > y) - (x < y);
}

static void normalize(pc_portset* s) {
	if (!s->dirty) return;

	s->dirty = 0;
	if (s->len < 2) return;

	qsort(s->ranges, s->len, sizeof *s->ranges, cmp_range);
	size_t w = 0;

	for (size_t i = 1; i < s->len; i++) {
		if ((unsigned)s->ranges[i].lo <= (unsigned)s->ranges[w].hi + 1) {
			if (s->ranges[i].hi > s->ranges[w].hi)
				s->ranges[w].hi = s->ranges[i].hi;
		} else {
			s->ranges[++w] = s->ranges[i];
		}
	}
	s->len = w + 1;
}

int pc_portset_add_range(pc_portset* s, uint16_t lo, uint16_t hi) {
	if (lo == 0 || lo > hi) return -1;
	if (s->len == s->cap) {
		size_t cap = s->cap ? s->cap * 2 : 8;
		pc_port_range* p = realloc(s->ranges, cap * sizeof *p);
		if (!p) return -1;
		s->ranges = p;
		s->cap = cap;
	}
	s->ranges[s->len++] = (pc_port_range){ lo, hi };
	s->dirty = 1;
	return 0;
}

static const char* parse_port(const char* s, unsigned* out) {
	if (*s < '0' || *s > '9') return NULL;
	if (*s == '0') return NULL;

	unsigned v = 0;
	while (*s >= '0' && *s <= '9') {
		v = v * 10 + (unsigned)(*s - '0');
		if (v > 65535) return NULL;

		s++;
	}

	*out = v;
	return s;
}

static int is_sep(char c) {
	return c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

int pc_portset_add_list(pc_portset* s, const char* list) {
	if (!list) return -1;

	size_t orig_len = s->len;
	int orig_dirty = s->dirty;

	const char* p = list;
	while (*p) {
		if (is_sep(*p)) {
			p++;
			continue;
		}

		unsigned lo, hi;
		const char* q = parse_port(p, &lo);
		if (!q) goto fail;

		hi = lo;
		if (*q == '-') {
			q = parse_port(q + 1, &hi);
			if (!q) goto fail;
		}

		if (*q && !is_sep(*q)) goto fail;
		if (pc_portset_add_range(s, (uint16_t)lo, (uint16_t)hi) != 0) goto fail;
		p = q;
	}

	return 0;
fail:

	s->len = orig_len;
	s->dirty = orig_dirty;
	return -1;
}

int pc_portset_intersect(pc_portset* s, pc_portset* other) {
	normalize(s);
	normalize(other);

	size_t cap = s->len + other->len + 1;
	pc_port_range* out = malloc(cap * sizeof *out);
	if (!out) return -1;

	size_t w = 0, i = 0, j = 0;

	while (i < s->len && j < other->len) {
		pc_port_range a = s->ranges[i], b = other->ranges[j];
		uint16_t lo = a.lo > b.lo ? a.lo : b.lo;
		uint16_t hi = a.hi < b.hi ? a.hi : b.hi;

		if (lo <= hi) out[w++] = (pc_port_range){ lo, hi };
		if (a.hi < b.hi) i++;
		else
			j++;
	}
	free(s->ranges);
	s->ranges = out;
	s->len = w;
	s->cap = cap;
	return 0;
}

int pc_portset_contains(pc_portset* s, uint16_t port) {
	normalize(s);
	size_t lo = 0, hi = s->len;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (port < s->ranges[mid].lo) hi = mid;
		else if (port > s->ranges[mid].hi)
			lo = mid + 1;
		else
			return 1;
	}
	return 0;
}

uint32_t pc_portset_count(pc_portset* s) {
	normalize(s);
	uint32_t n = 0;
	for (size_t i = 0; i < s->len; i++)
		n += (uint32_t)s->ranges[i].hi - s->ranges[i].lo + 1;
	return n;
}

size_t pc_portset_range_count(pc_portset* s) {
	normalize(s);
	return s->len;
}

pc_port_range pc_portset_range_at(pc_portset* s, size_t i) {
	normalize(s);
	return s->ranges[i];
}

char* pc_portset_format(pc_portset* s) {
	normalize(s);

	char* buf = malloc(s->len * 12 + 1);
	if (!buf) return NULL;

	char* w = buf;
	for (size_t i = 0; i < s->len; i++) {
		if (i) *w++ = ',';
		if (s->ranges[i].lo == s->ranges[i].hi)
			w += snprintf(w, 12, "%u", (unsigned)s->ranges[i].lo);
		else
			w += snprintf(w, 12, "%u-%u", (unsigned)s->ranges[i].lo,
				(unsigned)s->ranges[i].hi);
	}

	*w = '\0';
	return buf;
}
