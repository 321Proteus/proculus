// planner: turns a target list into a chunked scan plan.
#include <getopt.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "planner.hpp"

static void usage(const char* argv0) {
	std::cerr
		<< "usage: " << argv0 << " [options] [targets-file | -]\n"
		<< "  -x, --exclude SPEC            exclude an IP/CIDR/range "
		   "(repeatable)\n"
		<< "  -X, --exclude-file FILE       read exclusions from FILE (one per "
		   "line)\n"
		<< "  -r, --rate HOSTS_PER_SEC      expected scan rate (default 100)\n"
		<< "  -s, --chunk-seconds SECONDS   target duration of one chunk "
		   "(default 300)\n"
		<< "  -m, --max-chunk N             max addresses per chunk (default "
		   "65536)\n"
		<< "  -w, --workers N               workers scanning in parallel; chunks are "
		   "balanced across them (default 1)\n"
		<< "      --no-interleave           contiguous chunks instead of spreading "
		   "them over networks\n"
		<< "      --block-prefix N          unit that is dealt out in spread-out "
		   "order (default 24)\n"
		<< "      --group-prefix N          networks to spread over (default 16)\n"
		<< "      --allow-reserved          do not strip "
		   "loopback/multicast/link-local space\n"
		<< "      --summary-only            do not list individual chunks\n";
}

enum {
	OPT_ALLOW_RESERVED = 256,
	OPT_SUMMARY_ONLY,
	OPT_NO_INTERLEAVE,
	OPT_BLOCK_PREFIX,
	OPT_GROUP_PREFIX
};

static const option long_opts[] = {
	{ "exclude", required_argument, nullptr, 'x' },
	{ "exclude-file", required_argument, nullptr, 'X' },
	{ "rate", required_argument, nullptr, 'r' },
	{ "chunk-seconds", required_argument, nullptr, 's' },
	{ "max-chunk", required_argument, nullptr, 'm' },
	{ "workers", required_argument, nullptr, 'w' },
	{ "no-interleave", no_argument, nullptr, OPT_NO_INTERLEAVE },
	{ "block-prefix", required_argument, nullptr, OPT_BLOCK_PREFIX },
	{ "group-prefix", required_argument, nullptr, OPT_GROUP_PREFIX },
	{ "allow-reserved", no_argument, nullptr, OPT_ALLOW_RESERVED },
	{ "summary-only", no_argument, nullptr, OPT_SUMMARY_ONLY },
	{ "help", no_argument, nullptr, 'h' },
	{ nullptr, 0, nullptr, 0 },
};

static unsigned parse_uint(const char* s, const char* what) {
	try {
		size_t pos = 0;
		unsigned long v = std::stoul(s, &pos);
		if (s[pos] != '\0' || s[0] == '-' || v > 1000000)
			throw std::invalid_argument("");
		return static_cast<unsigned>(v);
	} catch (const std::exception&) {
		throw std::invalid_argument(
			std::string("invalid number for ") + what + ": " + s);
	}
}

static void read_exclusions(const char* path, std::vector<std::string>& out) {
	std::ifstream f(path);
	if (!f)
		throw std::invalid_argument(
			std::string("cannot open exclusions file ") + path);
	std::string l;

	while (std::getline(f, l)) {
		if (auto h = l.find('#'); h != std::string::npos) l.erase(h);
		if (l.find_first_not_of(" \t\r") != std::string::npos) out.push_back(l);
	}
}

int main(int argc, char** argv) {
	proculus::PlannerConfig cfg;
	std::string path = "-";
	bool summary_only = false;

	try {
		opterr = 0;
		int opt;

		while ((opt = getopt_long(
					argc, argv, ":x:X:r:s:m:w:h", long_opts, nullptr)) != -1) {
			switch (opt) {
			case 'x': cfg.exclusions.push_back(optarg); break;
			case 'X': read_exclusions(optarg, cfg.exclusions); break;
			case 'r': cfg.rate_hosts_per_sec = std::stod(optarg); break;
			case 's': cfg.chunk_seconds = std::stod(optarg); break;
			case 'm': cfg.max_chunk_size = std::stoull(optarg); break;
			case 'w': cfg.workers = parse_uint(optarg, "--workers"); break;
			case OPT_NO_INTERLEAVE: cfg.interleave = false; break;
			case OPT_BLOCK_PREFIX:
				cfg.block_prefix = parse_uint(optarg, "--block-prefix");
				break;
			case OPT_GROUP_PREFIX:
				cfg.group_prefix = parse_uint(optarg, "--group-prefix");
				break;
			case OPT_ALLOW_RESERVED: cfg.allow_reserved = true; break;
			case OPT_SUMMARY_ONLY:	 summary_only = true; break;
			case 'h':				 usage(argv[0]); return 0;
			case ':':
				throw std::invalid_argument(
					std::string("missing value for -") + char(optopt));
			default:
				throw std::invalid_argument(
					std::string("unknown option ") + argv[optind - 1]);
			}
		}
		if (optind < argc) path = argv[optind++];
		if (optind < argc)
			throw std::invalid_argument("only one targets file is allowed");

		std::ifstream file;
		if (path != "-") {
			file.open(path);
			if (!file) throw std::invalid_argument("cannot open " + path);
		}
		proculus::Plan plan =
			proculus::make_plan(path == "-" ? std::cin : file, cfg);

		for (const auto& e : plan.errors)
			std::cerr << "line " << e.line << ": " << e.reason << ": " << e.text
					  << "\n";

		std::cout << "addresses in input:  " << plan.input_addresses << "\n"
				  << "excluded:            " << plan.excluded_addresses << "\n"
				  << "reserved removed:    " << plan.reserved_addresses << "\n"
				  << "to scan:             " << plan.total_addresses << "\n"
				  << "domains to resolve:  " << plan.domains.size() << "\n"
				  << "invalid lines:       " << plan.errors.size() << "\n"
				  << "chunks:              " << plan.chunks.size()
				  << "  (" << plan.chunk_size << " addresses each, aimed for "
				  << plan.target_chunk_size << ")\n"
				  << "workers:             " << cfg.workers << "\n"
				  << "time per chunk:      "
				  << static_cast<long long>(plan.seconds_per_chunk) << " s\n"
				  << "estimated duration:  "
				  << static_cast<long long>(plan.estimated_seconds) << " s\n";

		if (!summary_only) {
			for (const auto& c : plan.chunks)
				std::cout << "chunk " << c.index << " (" << c.count << " addresses, "
						  << c.networks << " networks): " << c.cidrs << "\n";
		}
		return plan.errors.empty() ? 0 : 2;

	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
