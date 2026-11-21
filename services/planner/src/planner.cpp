#include "planner.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <stdexcept>

#include "proculus/netutil/ipset.hpp"
#include "proculus/netutil/target.h"

namespace proculus {

static void validate(const PlannerConfig& c) {
	if (!(c.rate_hosts_per_sec > 0))
		throw std::invalid_argument("rate must be > 0");
	if (!(c.chunk_seconds > 0))
		throw std::invalid_argument("chunk_seconds must be > 0");
	if (c.max_chunk_size == 0)
		throw std::invalid_argument("max_chunk_size must be > 0");
	if (c.workers == 0)
		throw std::invalid_argument("workers must be >= 1");
	if (c.interleave && !(1 <= c.group_prefix && c.group_prefix <= c.block_prefix &&
				  c.block_prefix <= 32))
		throw std::invalid_argument(
			"need 1 <= group-prefix <= block-prefix <= 32");
}

// Addresses a chunk should hold to take chunk_seconds at the expected rate.
static uint64_t chunk_size_for(const PlannerConfig& c) {
	double want = std::floor(c.rate_hosts_per_sec * c.chunk_seconds);
	if (want < 1) return 1;
	if (want >= static_cast<double>(c.max_chunk_size)) return c.max_chunk_size;
	return static_cast<uint64_t>(want);
}

// Inclusive address range, used for the pieces the scan order is built from.
using Piece = pc_range;

static uint64_t piece_size(const Piece& p) {
	return static_cast<uint64_t>(p.hi) - p.lo + 1;
}

// The set's ranges, cut at /block_prefix boundaries.
static std::vector<Piece> split_into_blocks(IpSet& set, int block_prefix,
	uint64_t max_blocks) {
	const uint64_t block = uint64_t{1} << (32 - block_prefix);
	std::vector<Piece> out;
	const size_t n = pc_ipset_range_count(set.raw());
	for (size_t i = 0; i < n; i++) {
		const pc_range r = pc_ipset_range_at(set.raw(), i);
		uint64_t lo = r.lo;
		while (lo <= r.hi) {
			const uint64_t end = std::min<uint64_t>(r.hi, lo | (block - 1));
			if (out.size() >= max_blocks)
				throw std::runtime_error(
					"plan would need more than " + std::to_string(max_blocks) +
					" address blocks; use a larger --block-prefix");
			out.push_back({ static_cast<uint32_t>(lo), static_cast<uint32_t>(end) });
			lo = end + 1;
		}
	}
	return out;
}

// Deals the blocks out round-robin across their /group_prefix networks: first
// block of the lowest network, first block of the next, ..., then the second
// block of each, and so on. Blocks of one network keep their address order.
static std::vector<Piece> interleave_blocks(const std::vector<Piece>& blocks,
	int group_prefix) {
	const int shift = 32 - group_prefix;
	std::map<uint64_t, std::vector<Piece>> groups;
	for (const Piece& b : blocks) {
		groups[static_cast<uint64_t>(b.lo) >> shift].push_back(b);
	}

	std::vector<const std::vector<Piece>*> active;
	for (const auto& kv : groups)
		active.push_back(&kv.second);

	std::vector<Piece> out;
	out.reserve(blocks.size());
	for (size_t round = 0; !active.empty(); round++) {
		size_t keep = 0;
		for (const auto* g : active) {
			out.push_back((*g)[round]);
			if (round + 1 < g->size()) active[keep++] = g;
		}
		active.resize(keep);
	}
	return out;
}

// How many /group_prefix networks the set touches.
static size_t count_networks(IpSet& set, int group_prefix) {
	const int shift = 32 - group_prefix;
	std::set<uint64_t> nets;
	const size_t n = pc_ipset_range_count(set.raw());
	for (size_t i = 0; i < n; i++) {
		const pc_range r = pc_ipset_range_at(set.raw(), i);
		for (uint64_t g = static_cast<uint64_t>(r.lo) >> shift;
			g <= (static_cast<uint64_t>(r.hi) >> shift); g++)
			nets.insert(g);
	}
	return nets.size();
}

// Cuts the pieces, in order, into `n` chunks whose sizes differ by at most one.
static std::vector<Chunk> cut_chunks(const std::vector<Piece>& pieces,
	uint64_t total, uint64_t n, int group_prefix) {
	std::vector<Chunk> chunks;
	chunks.reserve(n);
	const uint64_t base = total / n, extra = total % n;

	size_t at = 0;       // current piece
	uint64_t used = 0;   // addresses already taken from it
	uint64_t offset = 0;
	for (uint64_t i = 0; i < n; i++) {
		uint64_t want = base + (i < extra ? 1 : 0);
		Chunk c;
		c.index = i;
		c.offset = offset;
		c.count = want;

		IpSet set;
		while (want > 0) {
			const Piece& p = pieces[at];
			const uint64_t take = std::min(want, piece_size(p) - used);
			const uint32_t lo = static_cast<uint32_t>(p.lo + used);
			set.add({ lo, static_cast<uint32_t>(lo + (take - 1)) });
			used += take;
			want -= take;
			if (used == piece_size(p)) {
				at++;
				used = 0;
			}
		}
		offset += c.count;
		c.networks = count_networks(set, group_prefix);
		c.cidrs = set.format(',');
		chunks.push_back(std::move(c));
	}
	return chunks;
}

Plan make_plan(std::istream& targets, const PlannerConfig& config) {
	validate(config);
	Plan plan;

	IpSet set;
	std::set<std::string> seen_domains;
	std::string line;
	size_t line_no = 0;

	while (std::getline(targets, line)) {
		line_no++;
		if (auto hash = line.find('#'); hash != std::string::npos)
			line.erase(hash);

		pc_target t;
		if (pc_target_parse(line.c_str(), &t) != 0) {
			if (line.find_first_not_of(" \t\r\n") == std::string::npos)
				continue;
			plan.errors.push_back(
				{ line_no, line, "not an IP, CIDR, range or domain" });
			continue;
		}

		if (t.kind == PC_TARGET_DOMAIN) {
			if (seen_domains.insert(t.domain).second)
				plan.domains.push_back(t.domain);
		} else {
			set.add(t.range);
		}
	}

	plan.input_addresses = set.count();

	IpSet exclusions;
	for (const auto& spec : config.exclusions)
		exclusions.add_spec(spec);
	set.subtract(exclusions);
	uint64_t after_exclusions = set.count();
	plan.excluded_addresses = plan.input_addresses - after_exclusions;

	if (!config.allow_reserved) set.subtract_reserved();
	plan.total_addresses = set.count();
	plan.reserved_addresses = after_exclusions - plan.total_addresses;

	// How many chunks: enough for the requested duration, rounded up to a
	// multiple of the worker count so no worker is left idle at the end, but
	// never more chunks than addresses.
	plan.target_chunk_size = chunk_size_for(config);
	const uint64_t total = plan.total_addresses;
	uint64_t n_chunks = (total + plan.target_chunk_size - 1) / plan.target_chunk_size;
	if (n_chunks > 0 && config.workers > 1) {
		n_chunks = (n_chunks + config.workers - 1) / config.workers * config.workers;
		n_chunks = std::min(n_chunks, total);
	}
	if (n_chunks > config.max_chunks)
		throw std::runtime_error("plan needs " + std::to_string(n_chunks) +
			" chunks, over the limit of " + std::to_string(config.max_chunks));

	plan.chunk_size = n_chunks ? (total + n_chunks - 1) / n_chunks : 0;
	plan.seconds_per_chunk =
		static_cast<double>(plan.chunk_size) / config.rate_hosts_per_sec;
	plan.estimated_seconds = static_cast<double>(total) /
		(config.rate_hosts_per_sec * config.workers);

	if (n_chunks == 0) return plan;

	// Scan order: spread-out blocks, or the set's own ranges in address order.
	std::vector<Piece> pieces;
	if (config.interleave) {
		pieces = interleave_blocks(
			split_into_blocks(set, config.block_prefix, config.max_blocks),
			config.group_prefix);
	} else {
		const size_t n = pc_ipset_range_count(set.raw());
		for (size_t i = 0; i < n; i++)
			pieces.push_back(pc_ipset_range_at(set.raw(), i));
	}

	const int group_prefix = config.group_prefix >= 1 ? config.group_prefix : 16;
	plan.chunks = cut_chunks(pieces, total, n_chunks, group_prefix);
	return plan;
}

} // namespace proculus
