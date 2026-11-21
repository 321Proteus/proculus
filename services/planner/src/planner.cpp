#include "planner.hpp"

#include <algorithm>
#include <cmath>
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
}

static uint64_t chunk_size_for(const PlannerConfig& c) {
	double want = std::floor(c.rate_hosts_per_sec * c.chunk_seconds);
	if (want < 1) return 1;
	if (want >= static_cast<double>(c.max_chunk_size)) return c.max_chunk_size;
	return static_cast<uint64_t>(want);
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

	plan.chunk_size = chunk_size_for(config);
	plan.estimated_seconds =
		static_cast<double>(plan.total_addresses) / config.rate_hosts_per_sec;

	uint64_t n_chunks =
		(plan.total_addresses + plan.chunk_size - 1) / plan.chunk_size;
	if (n_chunks > config.max_chunks)
		throw std::runtime_error("plan needs " + std::to_string(n_chunks) +
			" chunks, over the limit of " + std::to_string(config.max_chunks));

	plan.chunks.reserve(n_chunks);
	for (uint64_t off = 0; off < plan.total_addresses; off += plan.chunk_size) {
		IpSet piece = set.slice(off, plan.chunk_size);
		Chunk c;
		c.index = plan.chunks.size();
		c.offset = off;
		c.count = piece.count();
		c.cidrs = piece.format(',');
		plan.chunks.push_back(std::move(c));
	}
	return plan;
}

} // namespace proculus
