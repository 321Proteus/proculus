#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "proculus/ipset.h"

static uint32_t ip(const char* s) {
	uint32_t v;
	assert(pc_ip_parse(s, &v) == 0);
	return v;
}

static void test_range_parse(void) {
	pc_range r;
	assert(pc_range_parse("10.0.0.1-10.0.0.9", &r) == 0);
	assert(r.lo == ip("10.0.0.1") && r.hi == ip("10.0.0.9"));
	assert(pc_range_parse("10.0.0.1-9", &r) == 0);
	assert(r.lo == ip("10.0.0.1") && r.hi == ip("10.0.0.9"));
	assert(pc_range_parse("10.0.0.0/30", &r) == 0);
	assert(pc_range_count(&r) == 4);
	assert(pc_range_parse("10.0.0.7", &r) == 0 && r.lo == r.hi);
	assert(pc_range_parse("10.0.0.5-10.0.0.5", &r) == 0 && r.lo == r.hi);

	const char* bad[] = { "10.0.0.9-10.0.0.1", "10.0.0.9-1", "10.0.0.1-256",
		"10.0.0.1-", "-10.0.0.1", "10.0.0.1-01", "10.0.0.1-a", "10.0.0.1-1-2",
		"10.0.0.1-10.0.0", "10.0.0.0/33-10.0.0.9", "host-name" };
	for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
		assert(pc_range_parse(bad[i], &r) == -1);
}

static void test_merge(void) {
	pc_ipset s;
	pc_ipset_init(&s);
	// overlapping, adjacent, out of order, duplicate
	assert(pc_ipset_add_spec(&s, "10.0.0.128/25") == 0);
	assert(pc_ipset_add_spec(&s, "10.0.0.0/25") == 0);
	assert(pc_ipset_add_spec(&s, "10.0.0.50-60") == 0);
	assert(pc_ipset_add_spec(&s, "10.0.0.0/24") == 0);
	assert(pc_ipset_add_spec(&s, "10.0.2.0/24") == 0);
	assert(pc_ipset_range_count(&s) == 2);
	assert(pc_ipset_count(&s) == 512);
	assert(pc_ipset_contains(&s, ip("10.0.0.200")));
	assert(!pc_ipset_contains(&s, ip("10.0.1.0")));
	assert(pc_ipset_add_spec(&s, "bogus") == -1);
	pc_ipset_free(&s);
}

static void test_top_of_space(void) {
	pc_ipset s;
	pc_ipset_init(&s);
	assert(pc_ipset_add_spec(&s, "255.255.255.0/24") == 0);
	assert(pc_ipset_add_spec(&s, "255.255.254.0/24") == 0);
	assert(pc_ipset_range_count(&s) == 1);
	assert(pc_ipset_count(&s) == 512);
	assert(pc_ipset_contains(&s, 0xffffffffu));
	pc_ipset_free(&s);

	pc_ipset all;
	pc_ipset_init(&all);
	assert(pc_ipset_add_spec(&all, "0.0.0.0/0") == 0);
	assert(pc_ipset_count(&all) == 4294967296ULL);
	assert(pc_ipset_subtract_range(&all, (pc_range){ 0, 0xffffffffu }) == 0);
	assert(pc_ipset_count(&all) == 0);
	pc_ipset_free(&all);
}

static void test_subtract(void) {
	pc_ipset s, ex;
	pc_ipset_init(&s);
	pc_ipset_init(&ex);
	assert(pc_ipset_add_spec(&s, "10.0.0.0/24") == 0);
	assert(pc_ipset_add_spec(&ex, "10.0.0.10-20") == 0);
	assert(pc_ipset_add_spec(&ex, "10.0.0.0") == 0);
	assert(pc_ipset_add_spec(&ex, "10.0.0.255") == 0);
	assert(pc_ipset_add_spec(&ex, "192.168.0.0/16") == 0); /* disjoint: no-op */
	assert(pc_ipset_subtract(&s, &ex) == 0);
	assert(pc_ipset_count(&s) == 256 - 11 - 2);
	assert(!pc_ipset_contains(&s, ip("10.0.0.15")));
	assert(pc_ipset_contains(&s, ip("10.0.0.9")));
	assert(pc_ipset_contains(&s, ip("10.0.0.21")));
	assert(!pc_ipset_contains(&s, ip("10.0.0.255")));
	assert(pc_ipset_range_count(&s) == 2);
	pc_ipset_free(&s);
	pc_ipset_free(&ex);
}

static void test_slice(void) {
	pc_ipset s;
	pc_ipset_init(&s);
	assert(pc_ipset_add_spec(&s, "10.0.0.0/30") == 0);
	assert(pc_ipset_add_spec(&s, "10.0.1.0/30") == 0);

	/* chunks of 3 over 8 addresses: 3 + 3 + 2, covering everything exactly once
	 */
	uint64_t total = 0;
	for (uint64_t off = 0; off < pc_ipset_count(&s); off += 3) {
		pc_ipset chunk;
		pc_ipset_init(&chunk);
		assert(pc_ipset_slice(&s, off, 3, &chunk) == 0);
		uint64_t n = pc_ipset_count(&chunk);
		assert(n == (off + 3 <= 8 ? 3 : 8 - off));
		total += n;
		pc_ipset_free(&chunk);
	}
	assert(total == 8);

	/* a chunk straddling both ranges */
	pc_ipset mid;
	pc_ipset_init(&mid);
	assert(pc_ipset_slice(&s, 2, 4, &mid) == 0);
	assert(pc_ipset_count(&mid) == 4);
	assert(pc_ipset_contains(&mid, ip("10.0.0.2")));
	assert(pc_ipset_contains(&mid, ip("10.0.0.3")));
	assert(pc_ipset_contains(&mid, ip("10.0.1.0")));
	assert(pc_ipset_contains(&mid, ip("10.0.1.1")));
	assert(!pc_ipset_contains(&mid, ip("10.0.1.2")));
	pc_ipset_free(&mid);

	/* out of range start yields nothing */
	pc_ipset none;
	pc_ipset_init(&none);
	assert(pc_ipset_slice(&s, 100, 5, &none) == 0);
	assert(pc_ipset_count(&none) == 0);
	pc_ipset_free(&none);
	pc_ipset_free(&s);
}

static void expect_format(pc_ipset* s, char sep, const char* want) {
	char* got = pc_ipset_format(s, sep);
	assert(got && strcmp(got, want) == 0);
	free(got);
}

static void test_cidr_decomposition(void) {
	pc_cidr out[PC_RANGE_MAX_CIDRS];
	pc_range r;

	assert(pc_range_parse("10.0.0.0/24", &r) == 0);
	assert(pc_range_to_cidrs(&r, out, PC_RANGE_MAX_CIDRS) == 1 &&
		out[0].prefix == 24);

	/* unaligned: .1-.6 -> /32, /31, /30(.4-.7 too big) ... check by sum */
	assert(pc_range_parse("10.0.0.1-6", &r) == 0);
	int n = pc_range_to_cidrs(&r, out, PC_RANGE_MAX_CIDRS);
	assert(n == 4); /* .1/32 .2/31 .4/31 .6/32 */
	uint64_t total = 0;
	for (int i = 0; i < n; i++)
		total += pc_cidr_count(&out[i]);
	assert(total == 6);

	/* whole space and worst case */
	r = (pc_range){ 0, 0xffffffffu };
	assert(pc_range_to_cidrs(&r, out, PC_RANGE_MAX_CIDRS) == 1 &&
		out[0].prefix == 0);
	r = (pc_range){ 1, 0xfffffffeu };
	n = pc_range_to_cidrs(&r, out, PC_RANGE_MAX_CIDRS);
	assert(n == 62);
	total = 0;
	for (int i = 0; i < n; i++)
		total += pc_cidr_count(&out[i]);
	assert(total == 4294967294ULL);
	assert(pc_range_to_cidrs(&r, out, 10) == -1); /* cap too small */

	// top of space
	r = (pc_range){ 0xffffffffu, 0xffffffffu };
	assert(pc_range_to_cidrs(&r, out, PC_RANGE_MAX_CIDRS) == 1 &&
		out[0].prefix == 32);
}

static void test_list_and_format(void) {
	pc_ipset s;
	pc_ipset_init(&s);
	assert(pc_ipset_add_list(
			   &s, "10.0.0.0/24, 10.0.1.1-3\n8.8.8.8\t10.0.0.5") == 0);
	expect_format(&s, ',', "8.8.8.8,10.0.0.0/24,10.0.1.1,10.0.1.2/31");
	expect_format(&s, '\n', "8.8.8.8\n10.0.0.0/24\n10.0.1.1\n10.0.1.2/31");

	// round trip
	char* text = pc_ipset_format(&s, ' ');
	pc_ipset t;
	pc_ipset_init(&t);
	assert(pc_ipset_add_list(&t, text) == 0);
	assert(pc_ipset_count(&t) == pc_ipset_count(&s));
	assert(pc_ipset_count(&t) == 1 + 256 + 3);
	free(text);
	pc_ipset_free(&t);

	// all or nothig
	uint64_t before = pc_ipset_count(&s);
	assert(pc_ipset_add_list(&s, "1.1.1.1, 2.2.2.2, nope") == -1);
	assert(pc_ipset_count(&s) == before);
	assert(!pc_ipset_contains(&s, ip("1.1.1.1")));
	assert(pc_ipset_add_list(&s, "") == 0);
	pc_ipset_free(&s);

	pc_ipset empty;
	pc_ipset_init(&empty);
	expect_format(&empty, ',', "");
}

static void test_reserved(void) {
	assert(pc_ip_is_reserved(ip("0.1.2.3")));
	assert(pc_ip_is_reserved(ip("127.0.0.1")));
	assert(pc_ip_is_reserved(ip("169.254.10.10")));
	assert(pc_ip_is_reserved(ip("224.0.0.1")));
	assert(pc_ip_is_reserved(ip("240.0.0.1")));
	assert(pc_ip_is_reserved(ip("255.255.255.255")));
	assert(!pc_ip_is_reserved(ip("10.0.0.1")));
	assert(!pc_ip_is_reserved(ip("192.168.1.1")));
	assert(!pc_ip_is_reserved(ip("169.253.0.1")));
	assert(!pc_ip_is_reserved(ip("223.255.255.255")));
	assert(!pc_ip_is_reserved(ip("126.255.255.255")));

	pc_ipset s;
	pc_ipset_init(&s);
	assert(pc_ipset_add_spec(&s, "0.0.0.0/0") == 0);
	assert(pc_ipset_subtract_reserved(&s) == 0);
	/* 2^32 - 2^24 (0/8) - 2^24 (127/8) - 2^16 (169.254/16) - 2^28 (224/4) -
	 * 2^28 (240/4) */
	assert(pc_ipset_count(&s) ==
		4294967296ULL - 16777216 - 16777216 - 65536 - 268435456 * 2);
	/* the set must agree with pc_ip_is_reserved on a sample of addresses */
	for (uint64_t a = 0; a < 4294967296ULL; a += 65537) {
		assert(pc_ipset_contains(&s, (uint32_t)a) ==
			!pc_ip_is_reserved((uint32_t)a));
	}
	pc_ipset_free(&s);
}

int main(void) {
	test_range_parse();
	test_merge();
	test_top_of_space();
	test_subtract();
	test_slice();
	test_cidr_decomposition();
	test_list_and_format();
	test_reserved();
	return 0;
}
