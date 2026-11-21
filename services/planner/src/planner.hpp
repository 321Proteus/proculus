#ifndef PROCULUS_PLANNER_HPP
#define PROCULUS_PLANNER_HPP

#include <cstdint>
#include <istream>
#include <string>
#include <vector>

#include "proculus/timing/rate.hpp"

namespace proculus {

struct PlannerConfig {
	// Specs (IP, CIDR or range) that must never be scanned.
	std::vector<std::string> exclusions;
	// Expected scan speed of ONE worker, used to size chunks and estimate
	// duration. Once real chunks have been timed, take it from a RateEstimator
	// with set_rate_from() instead of guessing.
	double rate_hosts_per_sec = 100;
	// Workers that will scan chunks in parallel. The number of chunks is rounded
	// up to a multiple of it, so all workers finish at about the same time.
	unsigned workers = 1;
	// Target wall-clock duration of one chunk.
	double chunk_seconds = 300;
	uint64_t max_chunk_size = 65536;
	// Reserved space (loopback, multicast, ...) is removed unless this is set.
	bool allow_reserved = false;
	// Refuse plans that would produce more chunks than this.
	uint64_t max_chunks = 1000000;

	// Spread-out ordering. The address space is cut into blocks of /block_prefix
	// (one /24 = one compact CIDR entry for nmap) and the blocks are dealt out
	// round-robin across the /group_prefix networks they belong to, so a chunk
	// touches many networks lightly instead of one network heavily. Requires
	// 1 <= group_prefix <= block_prefix <= 32. With interleave off, chunks are
	// contiguous slices in address order.
	bool interleave = true;
	int block_prefix = 24;
	int group_prefix = 16;
	// Refuse to enumerate more blocks than this (a /0 at /24 is 16 million).
	uint64_t max_blocks = 4000000;

	// Uses the measured rate if the estimator has one; keeps the current value otherwise.
	void set_rate_from(const RateEstimator& r) {
		if (r.has_estimate()) rate_hosts_per_sec = r.rate();
	}
};

struct Chunk {
	size_t index = 0;
	uint64_t offset = 0; // position in scan order (see PlannerConfig::interleave)
	uint64_t count = 0;
	size_t networks = 0; // distinct /group_prefix networks the chunk touches
	std::string cidrs;   // comma-separated minimal CIDR list, nmap-ready
};

struct LineError {
	size_t line = 0; // 1-based
	std::string text;
	std::string reason;
};

struct Plan {
	std::vector<Chunk> chunks;
	std::vector<std::string>
		domains; // unique, in input order; need DNS resolution
	std::vector<LineError> errors;

	uint64_t input_addresses = 0; // after merging duplicates/overlaps
	uint64_t excluded_addresses = 0; // removed by explicit exclusions
	uint64_t reserved_addresses = 0; // removed as reserved space
	uint64_t total_addresses = 0; // what will actually be scanned
	uint64_t target_chunk_size = 0; // size asked for by rate x chunk_seconds
	uint64_t chunk_size = 0;        // largest actual chunk; chunks differ by at most one address
	double seconds_per_chunk = 0;   // expected duration of the largest chunk on one worker
	double estimated_seconds = 0;   // whole plan, divided across the workers
};

// Reads one target per line (blank lines and '#' comments are skipped) and
// builds a scan plan. Invalid lines are reported in Plan::errors and do not
// abort planning. Chunks are equal in size (within one address) rather than
// "full chunks plus a small remainder".
// Throws std::invalid_argument for a bad config or exclusion, and
// std::runtime_error if the plan would exceed max_chunks or max_blocks.
Plan make_plan(std::istream& targets, const PlannerConfig& config);

} // namespace proculus

#endif // PROCULUS_PLANNER_HPP
