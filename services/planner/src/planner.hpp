#ifndef PROCULUS_PLANNER_HPP
#define PROCULUS_PLANNER_HPP

#include <cstdint>
#include <istream>
#include <string>
#include <vector>

namespace proculus {

struct PlannerConfig {
	// Specs (IP, CIDR or range) that must never be scanned.
	std::vector<std::string> exclusions;
	// Expected scan speed, used to size chunks and estimate duration.
	double rate_hosts_per_sec = 100;
	// Target wall-clock duration of one chunk.
	double chunk_seconds = 300;
	uint64_t max_chunk_size = 65536;
	// Reserved space (loopback, multicast, ...) is removed unless this is set.
	bool allow_reserved = false;
	// Refuse plans that would produce more chunks than this.
	uint64_t max_chunks = 1000000;
};

struct Chunk {
	size_t index = 0;
	uint64_t offset = 0; // position within the planned address space
	uint64_t count = 0;
	std::string cidrs; // comma-separated minimal CIDR list, nmap-ready
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
	uint64_t chunk_size = 0;
	double estimated_seconds = 0;
};

Plan make_plan(std::istream& targets, const PlannerConfig& config);

} // namespace proculus

#endif // PROCULUS_PLANNER_HPP
