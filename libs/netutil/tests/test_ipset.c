#undef NDEBUG
#include <assert.h>
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

int main(void) {
	test_range_parse();
	test_merge();
	test_top_of_space();
	test_subtract();
	test_slice();
	return 0;
}
