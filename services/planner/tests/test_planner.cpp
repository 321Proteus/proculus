#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <sstream>

#include "planner.hpp"
#include "proculus/netutil/ipset.hpp"
#include "proculus/timing/rate.hpp"

using namespace proculus;

static Plan plan_of(const std::string& text, const PlannerConfig& cfg = {}) {
	std::istringstream in(text);
	return make_plan(in, cfg);
}

static void test_basic() {
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 1;
	cfg.chunk_seconds = 100; // 100 hosts per chunk
	Plan p = plan_of("10.0.0.0/24\n# comment\n\n192.168.1.1  # trailing\n", cfg);
	assert(p.errors.empty());
	assert(p.input_addresses == 257);
	assert(p.total_addresses == 257);
	assert(p.target_chunk_size == 100);
	// 257 addresses in 3 chunks: balanced (86 + 86 + 85), not 100 + 100 + 57
	assert(p.chunks.size() == 3 && p.chunk_size == 86);
	assert(p.chunks[0].count == 86 && p.chunks[1].count == 86 && p.chunks[2].count == 85);
	assert(p.chunks[0].offset == 0 && p.chunks[1].offset == 86 && p.chunks[2].offset == 172);
	assert(p.estimated_seconds == 257.0);

	uint64_t sum = 0;
	for (const auto& c : p.chunks) sum += c.count;
	assert(sum == p.total_addresses);
}

static void test_exclusions_and_reserved() {
	PlannerConfig cfg;
	cfg.exclusions = {"10.0.0.0/25"};
	Plan p = plan_of("10.0.0.0/24\n127.0.0.0/30\n224.0.0.1\n", cfg);
	assert(p.input_addresses == 256 + 4 + 1);
	assert(p.excluded_addresses == 128);
	assert(p.reserved_addresses == 5);
	assert(p.total_addresses == 128);
	assert(p.chunks.size() == 1 && p.chunks[0].cidrs == "10.0.0.128/25");

	cfg.allow_reserved = true;
	p = plan_of("127.0.0.0/30\n", cfg);
	assert(p.total_addresses == 4 && p.reserved_addresses == 0);
}

static void test_bad_lines_and_domains() {
	Plan p = plan_of("10.0.0.1\nnot a target\nExample.com\nexample.com\n256.1.1.1\n  \n10.0.0.2\n");
	assert(p.total_addresses == 2);
	assert(p.domains.size() == 1 && p.domains[0] == "example.com");
	assert(p.errors.size() == 2);
	assert(p.errors[0].line == 2 && p.errors[1].line == 5);
}

static void test_empty_and_errors() {
	Plan p = plan_of("");
	assert(p.total_addresses == 0 && p.chunks.empty() && p.estimated_seconds == 0);

	bool threw = false;
	PlannerConfig cfg;
	cfg.exclusions = {"nonsense"};
	try { plan_of("10.0.0.1\n", cfg); } catch (const std::invalid_argument&) { threw = true; }
	assert(threw);

	threw = false;
	cfg = {};
	cfg.rate_hosts_per_sec = 0;
	try { plan_of("10.0.0.1\n", cfg); } catch (const std::invalid_argument&) { threw = true; }
	assert(threw);

	threw = false;
	cfg = {};
	cfg.max_chunk_size = 1;
	cfg.max_chunks = 10;
	try { plan_of("10.0.0.0/24\n", cfg); } catch (const std::runtime_error&) { threw = true; }
	assert(threw);
}

static void test_chunk_size_clamps() {
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 0.001;
	cfg.chunk_seconds = 1; // < 1 host -> clamps to 1
	assert(plan_of("10.0.0.1\n", cfg).target_chunk_size == 1);
	cfg.rate_hosts_per_sec = 1e9;
	cfg.max_chunk_size = 512;
	assert(plan_of("10.0.0.1\n", cfg).target_chunk_size == 512);
}

static void test_large() {
	// 10 /16 blocks = 655,360 addresses, planned without enumerating them
	std::ostringstream in;
	for (int i = 0; i < 10; i++) in << "10." << i << ".0.0/16\n";
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 1000;
	cfg.chunk_seconds = 60; // 60,000 per chunk
	Plan p = plan_of(in.str(), cfg);
	assert(p.total_addresses == 655360);
	assert(p.chunks.size() == 11);
}


// The chunks must cover the plan's addresses exactly once.
static void assert_exact_cover(const Plan& p, const char* expected_spec_list) {
	IpSet want;
	want.add_list(expected_spec_list);
	IpSet seen;
	uint64_t sum = 0;
	for (const auto& c : p.chunks) {
		IpSet piece;
		piece.add_list(c.cidrs);
		assert(piece.count() == c.count);
		sum += c.count;
		seen.add_list(c.cidrs);
	}
	assert(sum == want.count());          // no address twice
	assert(seen.count() == want.count()); // none missing, none extra
	seen.subtract(want);
	assert(seen.count() == 0);
}

static std::string lines(std::initializer_list<const char*> l) {
	std::string s;
	for (const char* x : l) s += std::string(x) + "\n";
	return s;
}

static void test_balanced_chunks() {
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 1;
	cfg.chunk_seconds = 100;
	for (int total : {1, 7, 99, 100, 101, 199, 200, 201, 250, 999}) {
		std::ostringstream in;
		in << "10.9." << 0 << ".0-10.9." << (total - 1) / 256 << "." << (total - 1) % 256 << "\n";
		Plan p = plan_of(in.str(), cfg);
		assert(p.total_addresses == static_cast<uint64_t>(total));
		uint64_t lo = UINT64_MAX, hi = 0;
		for (const auto& c : p.chunks) {
			lo = std::min(lo, c.count);
			hi = std::max(hi, c.count);
		}
		assert(hi - lo <= 1);           // sizes differ by at most one
		assert(hi == p.chunk_size);
		assert(hi <= 100);              // never above the aimed-for size
	}
}

static void test_workers() {
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 10;
	cfg.chunk_seconds = 100; // aims for 1000 per chunk
	Plan one = plan_of("10.0.0.0/22\n", cfg); // 1024 addresses
	assert(one.chunks.size() == 2);

	cfg.workers = 4; // rounded up to a multiple of 4 chunks, so nobody idles
	Plan four = plan_of("10.0.0.0/22\n", cfg);
	assert(four.chunks.size() == 4);
	for (const auto& c : four.chunks) assert(c.count == 256);
	assert(four.estimated_seconds == 1024.0 / (10 * 4));
	assert(four.seconds_per_chunk == 25.6);

	// never more chunks than addresses
	cfg.workers = 50;
	Plan tiny = plan_of("10.0.0.0/30\n", cfg);
	assert(tiny.chunks.size() == 4);

	cfg.workers = 0;
	bool threw = false;
	try { plan_of("10.0.0.1\n", cfg); } catch (const std::invalid_argument&) { threw = true; }
	assert(threw);
}

static void test_spread_across_networks() {
	// Two /16 networks, 12800 addresses per chunk (50 /24 blocks).
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 128;
	cfg.chunk_seconds = 100;
	const std::string in = lines({"10.1.0.0/16", "10.2.0.0/16"});

	Plan spread = plan_of(in, cfg);
	assert(spread.total_addresses == 131072);
	assert_exact_cover(spread, "10.1.0.0/16,10.2.0.0/16");
	for (const auto& c : spread.chunks) assert(c.networks == 2); // every chunk touches both

	cfg.interleave = false; // contiguous: the first chunks sit entirely in 10.1.0.0/16
	Plan flat = plan_of(in, cfg);
	assert(flat.chunks.front().networks == 1 && flat.chunks.back().networks == 1);
	assert_exact_cover(flat, "10.1.0.0/16,10.2.0.0/16");
}

static void test_round_robin_order() {
	// Three networks, chunks of exactly three /24 blocks: one block from each, in network order.
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 768;
	cfg.chunk_seconds = 1; // 768 addresses
	Plan p = plan_of(lines({"10.3.0.0/16", "10.1.0.0/16", "10.2.0.0/16"}), cfg);
	assert(p.target_chunk_size == 768);
	assert(p.chunks[0].cidrs == "10.1.0.0/24,10.2.0.0/24,10.3.0.0/24");
	assert(p.chunks[1].cidrs == "10.1.1.0/24,10.2.1.0/24,10.3.1.0/24");
	assert(p.chunks[0].networks == 3);

	// A single network has nothing to interleave: plain address order.
	cfg.rate_hosts_per_sec = 1024;
	p = plan_of(lines({"10.1.0.0/16"}), cfg); // 64 chunks of exactly 1024
	assert(p.chunks.size() == 64);
	assert(p.chunks[0].cidrs == "10.1.0.0/22" && p.chunks[1].cidrs == "10.1.4.0/22");
	assert(p.chunks[1].offset == 1024);
}

static void test_ragged_edges_still_cover_exactly() {
	// ranges that start and end inside /24 blocks, in several networks
	PlannerConfig cfg;
	cfg.rate_hosts_per_sec = 3;
	cfg.chunk_seconds = 100; // ~300 per chunk, smaller than a block pair
	const char* spec = "10.1.0.77-10.1.2.9,10.2.5.5,10.3.0.0/25,10.3.0.200-10.3.0.255";
	Plan p = plan_of(lines({"10.1.0.77-10.1.2.9", "10.2.5.5", "10.3.0.0/25", "10.3.0.200-10.3.0.255"}), cfg);
	assert(p.total_addresses > 0);
	assert_exact_cover(p, spec);

	cfg.block_prefix = 28; // finer blocks
	cfg.group_prefix = 24;
	assert_exact_cover(plan_of(lines({"10.1.0.77-10.1.2.9", "10.2.5.5", "10.3.0.0/25", "10.3.0.200-10.3.0.255"}), cfg), spec);
	cfg.block_prefix = 32; // one block per address
	cfg.group_prefix = 32;
	assert_exact_cover(plan_of(lines({"10.1.0.250-10.1.1.10", "10.2.5.5"}), cfg), "10.1.0.250-10.1.1.10,10.2.5.5");
}

static void test_prefix_validation_and_block_limit() {
	PlannerConfig cfg;
	auto bad = [&](int block, int group) {
		cfg.block_prefix = block;
		cfg.group_prefix = group;
		try { plan_of("10.0.0.1\n", cfg); } catch (const std::invalid_argument&) { return true; }
		return false;
	};
	assert(bad(16, 24));  // group finer than block
	assert(bad(24, 0));
	assert(bad(33, 16));
	assert(!bad(24, 16) && !bad(32, 32) && !bad(24, 24));
	cfg.interleave = false; // prefixes are ignored when not interleaving
	cfg.block_prefix = 99;
	plan_of("10.0.0.1\n", cfg);

	// 4 blocks allowed, a /22 has 4 /24s: fine; a /21 has 8: refused
	cfg = {};
	cfg.max_blocks = 4;
	plan_of("10.0.0.0/22\n", cfg);
	bool threw = false;
	try { plan_of("10.0.0.0/21\n", cfg); } catch (const std::runtime_error&) { threw = true; }
	assert(threw);
}

static void test_measured_rate_sizes_chunks() {
	RateEstimator est;
	PlannerConfig cfg;
	cfg.chunk_seconds = 60;
	cfg.rate_hosts_per_sec = 10;
	cfg.set_rate_from(est); // no measurement yet: keeps the configured guess
	assert(cfg.rate_hosts_per_sec == 10);

	est.record(50000, 100); // measured 500 addresses/s: chunks of 30000
	cfg.set_rate_from(est);
	assert(cfg.rate_hosts_per_sec == 500);
	Plan p = plan_of("10.0.0.0/16\n", cfg);
	assert(p.target_chunk_size == 30000);
	assert(p.chunks.size() == 3 && p.estimated_seconds == 65536.0 / 500);
}

static void test_no_addresses() {
	Plan p = plan_of("example.com\n127.0.0.1\n");
	assert(p.total_addresses == 0 && p.chunks.empty() && p.chunk_size == 0);
	assert(p.domains.size() == 1);
}

int main() {
	test_basic();
	test_exclusions_and_reserved();
	test_bad_lines_and_domains();
	test_empty_and_errors();
	test_chunk_size_clamps();
	test_large();
	test_balanced_chunks();
	test_workers();
	test_spread_across_networks();
	test_round_robin_order();
	test_ragged_edges_still_cover_exactly();
	test_prefix_validation_and_block_limit();
	test_measured_rate_sizes_chunks();
	test_no_addresses();
	return 0;
}
