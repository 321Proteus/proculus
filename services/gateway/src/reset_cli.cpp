#include "reset_cli.hpp"

#include <getopt.h>

#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace proculus {

namespace fs = std::filesystem;

namespace {

bool is_run_file(const std::string& n) {
	if (n.size() != 15 || n.compare(0, 4, "run-") != 0 || n.compare(10, 5, ".json") != 0) return false;
	for (size_t i = 4; i < 10; i++)
		if (n[i] < '0' || n[i] > '9') return false;
	return true;
}

} // namespace

std::vector<fs::path> reset_targets(const fs::path& dir, bool include_runs) {
	std::vector<fs::path> out;
	std::error_code ec;
	if (!fs::is_directory(dir, ec)) throw std::invalid_argument(dir.string() + " is not a directory");
	for (const char* name : {"accounts", "edits", "scan-config.json", "scan-config.json.tmp"}) {
		const fs::path p = dir / name;
		if (fs::exists(fs::symlink_status(p, ec)) && !fs::is_symlink(p, ec)) out.push_back(p);
	}
	if (include_runs)
		for (const auto& e : fs::directory_iterator(dir, ec))
			if (e.is_regular_file(ec) && !e.is_symlink(ec) && is_run_file(e.path().filename().string())) out.push_back(e.path());
	return out;
}

size_t reset_store(const fs::path& dir, bool include_runs) {
	size_t n = 0;
	for (const fs::path& p : reset_targets(dir, include_runs)) {
		fs::remove_all(p);
		n++;
	}
	return n;
}

int reset_command(int argc, char** argv) {
	enum { OPT_STORE = 256, OPT_RUNS, OPT_YES, OPT_HELP };
	static const option opts[] = {{"store", required_argument, nullptr, OPT_STORE}, {"runs", no_argument, nullptr, OPT_RUNS}, {"yes", no_argument, nullptr, OPT_YES},
		{"help", no_argument, nullptr, OPT_HELP}, {nullptr, 0, nullptr, 0}};
	std::string store;
	bool runs = false, yes = false;
	try {
		optind = 1;
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_STORE: store = optarg; break;
			case OPT_RUNS: runs = true; break;
			case OPT_YES: yes = true; break;
			case OPT_HELP:
				std::cerr << "usage: gateway reset --store DIR [--runs] [--yes]\n"
				          << "  Gives a file store a fresh start: removes accounts/ (the next start asks for the setup token again),\n"
				          << "  edits/ and scan-config.json; with --runs also the saved runs. Nothing else in DIR is touched.\n"
				          << "  Without --yes it only lists what it would remove. Stop the gateway first.\n";
				return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (optind < argc) throw std::invalid_argument(std::string("unexpected argument: ") + argv[optind]);
		if (store.empty())
			if (const char* env = std::getenv("PROCULUS_STORE_DIR")) store = env;
		if (store.empty()) throw std::invalid_argument("give --store DIR");
		const auto targets = reset_targets(store, runs);
		if (targets.empty()) {
			std::cerr << "nothing to remove in " << store << "\n";
			return 0;
		}
		for (const auto& p : targets) std::cerr << (yes ? "removing " : "would remove ") << p.string() << "\n";
		if (!yes) {
			std::cerr << "nothing was removed; run again with --yes to do it" << (runs ? "" : " (add --runs to remove the saved runs too)") << "\n";
			return 0;
		}
		const size_t n = reset_store(store, runs);
		std::cerr << "removed " << n << " item(s); the next gateway start shows the first-run setup\n";
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}

} // namespace proculus
