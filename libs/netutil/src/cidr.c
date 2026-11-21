#include "proculus/cidr.h"

#include <stdio.h>

static const char* parse_uint(const char* s, unsigned max, unsigned* out) {
	if (*s < '0' || *s > '9') return NULL;
	if (*s == '0' && s[1] >= '0' && s[1] <= '9') return NULL; // leading zero

	unsigned v = 0;
	while (*s >= '0' && *s <= '9') {
		v = v * 10 + (unsigned)(*s - '0');
		if (v > max) return NULL;

		s++;
	}

	*out = v;
	return s;
}

static const char* parse_ip(const char* s, uint32_t* out) {
	uint32_t ip = 0;
	for (int i = 0; i < 4; i++) {
		unsigned octet;
		s = parse_uint(s, 255, &octet);
		if (!s) return NULL;

		ip = (ip << 8) | octet;
		if (i < 3) {
			if (*s != '.') return NULL;

			s++;
		}
	}

	*out = ip;
	return s;
}

int pc_ip_parse(const char* s, uint32_t* out) {
	if (!s) return -1;
	const char* end = parse_ip(s, out);
	return (end && *end == '\0') ? 0 : -1;
}

void pc_ip_format(uint32_t ip, char* buf) {
	snprintf(buf, PC_IP_STR_MAX, "%u.%u.%u.%u", (unsigned)(ip >> 24),
		(unsigned)((ip >> 16) & 0xff), (unsigned)((ip >> 8) & 0xff),
		(unsigned)(ip & 0xff));
}

static uint32_t prefix_mask(unsigned prefix) {
	return prefix == 0 ? 0 : 0xffffffffu << (32 - prefix);
}

int pc_cidr_parse(const char* s, pc_cidr* out) {
	if (!s || !out) return -1;

	uint32_t ip;
	const char* p = parse_ip(s, &ip);
	if (!p) return -1;

	unsigned prefix = 32;

	if (*p == '/') {
		p = parse_uint(p + 1, 32, &prefix);
		if (!p) return -1;
	}

	if (*p != '\0') return -1;

	out->base = ip & prefix_mask(prefix);
	out->prefix = (uint8_t)prefix;

	return 0;
}

uint64_t pc_cidr_count(const pc_cidr* c) {
	return (uint64_t)1 << (32 - c->prefix);
}

uint32_t pc_cidr_nth(const pc_cidr* c, uint64_t i) {
	return c->base + (uint32_t)i;
}

int pc_cidr_contains(const pc_cidr* c, uint32_t ip) {
	return (ip & prefix_mask(c->prefix)) == c->base;
}
