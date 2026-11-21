#undef NDEBUG
#include <cassert>
#include <sstream>

#include "planner.hpp"

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
	assert(p.chunk_size == 100);
	assert(p.chunks.size() == 3);
	assert(p.chunks[0].count == 100 && p.chunks[1].count == 100 && p.chunks[2].count == 57);
	assert(p.chunks[0].offset == 0 && p.chunks[2].offset == 200);
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
	assert(plan_of("10.0.0.1\n", cfg).chunk_size == 1);
	cfg.rate_hosts_per_sec = 1e9;
	cfg.max_chunk_size = 512;
	assert(plan_of("10.0.0.1\n", cfg).chunk_size == 512);
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

int main() {
	test_basic();
	test_exclusions_and_reserved();
	test_bad_lines_and_domains();
	test_empty_and_errors();
	test_chunk_size_clamps();
	test_large();
	return 0;
}
