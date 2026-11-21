// Gateway: the entry point of the system. The REST API and access control are
// not built yet; for now it runs a demonstration of the scanning pipeline
// against an emulated network.
#include <getopt.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "demo.hpp"
#include "proculus/version.h"

enum { OPT_SEED = 256, OPT_ROUNDS, OPT_WORKERS, OPT_NETWORKS, OPT_DENSITY, OPT_WINDOW, OPT_START, OPT_HELP };

static const option long_opts[] = {
	{ "seed", required_argument, nullptr, OPT_SEED },
	{ "rounds", required_argument, nullptr, OPT_ROUNDS },
	{ "workers", required_argument, nullptr, OPT_WORKERS },
	{ "networks", required_argument, nullptr, OPT_NETWORKS },
	{ "density", required_argument, nullptr, OPT_DENSITY },
	{ "window", required_argument, nullptr, OPT_WINDOW },
	{ "start", required_argument, nullptr, OPT_START },
	{ "help", no_argument, nullptr, OPT_HELP },
	{ nullptr, 0, nullptr, 0 },
};

static void usage(const char* argv0) {
	std::cerr
		<< "usage: " << argv0 << " [options]\n"
		<< "Runs the scan pipeline against an emulated network (virtual time).\n"
		<< "  --rounds N       scan rounds to run (default 3)\n"
		<< "  --workers N      parallel scan workers (default 3)\n"
		<< "  --window W       scan window, e.g. 22:00-06:00 (default 22:00-22:03,\n"
		<< "                   deliberately too short, to show pause and resume)\n"
		<< "  --start TIME     virtual start, e.g. 2026-11-21T21:00:00Z\n"
		<< "  --networks LIST  address ranges of the emulated network\n"
		<< "  --density D      fraction of addresses that are hosts (default 0.03)\n"
		<< "  --seed N         same seed, same network (default 42)\n";
}

static double to_double(const char* s, const char* what) {
	try {
		size_t pos = 0;
		double v = std::stod(s, &pos);
		if (s[pos] != '\0') throw std::invalid_argument("");
		return v;
	} catch (const std::exception&) {
		throw std::invalid_argument(std::string("invalid number for ") + what + ": " + s);
	}
}

int main(int argc, char** argv) {
	proculus::DemoConfig cfg;
	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_SEED: cfg.seed = static_cast<uint64_t>(to_double(optarg, "--seed")); break;
			case OPT_ROUNDS: cfg.rounds = static_cast<int>(to_double(optarg, "--rounds")); break;
			case OPT_WORKERS: cfg.workers = static_cast<unsigned>(to_double(optarg, "--workers")); break;
			case OPT_NETWORKS: cfg.networks = optarg; break;
			case OPT_DENSITY: cfg.density = to_double(optarg, "--density"); break;
			case OPT_WINDOW: cfg.window = optarg; break;
			case OPT_START: cfg.start = optarg; break;
			case OPT_HELP: usage(argv[0]); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (optind < argc) throw std::invalid_argument(std::string("unexpected argument: ") + argv[optind]);

		std::cout << "proculus gateway v" << proculus_version() << "\n\n";
		proculus::run_demo(cfg, std::cout);
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
