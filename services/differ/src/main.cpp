// differ: compares saved scan runs, and replays them to follow hosts and
// services over time.
#include <getopt.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "proculus/results/results.hpp"
#include "report.hpp"

enum { OPT_STORE = 256, OPT_FORMAT, OPT_ALL, OPT_EVENTS, OPT_UNTIL, OPT_STALE_BELOW, OPT_GONE_BELOW, OPT_GONE_AFTER,
	OPT_FLAP_WINDOW, OPT_FLAP_TRANSITIONS, OPT_HELP };

static const option long_opts[] = {
	{ "store", required_argument, nullptr, OPT_STORE },
	{ "format", required_argument, nullptr, OPT_FORMAT },
	{ "all", no_argument, nullptr, OPT_ALL },
	{ "events", no_argument, nullptr, OPT_EVENTS },
	{ "until", required_argument, nullptr, OPT_UNTIL },
	{ "stale-below", required_argument, nullptr, OPT_STALE_BELOW },
	{ "gone-below", required_argument, nullptr, OPT_GONE_BELOW },
	{ "gone-after", required_argument, nullptr, OPT_GONE_AFTER },
	{ "flap-window", required_argument, nullptr, OPT_FLAP_WINDOW },
	{ "flap-transitions", required_argument, nullptr, OPT_FLAP_TRANSITIONS },
	{ "help", no_argument, nullptr, OPT_HELP },
	{ nullptr, 0, nullptr, 0 },
};

static void usage(const char* argv0) {
	std::cerr
		<< "usage: " << argv0 << " --store DIR diff A B [--format text|json] [--all]\n"
		<< "       " << argv0 << " --store DIR track [options]\n"
		<< "  diff A B   compare two saved runs: run numbers, or 'latest'; A may also be 'previous',\n"
		<< "             meaning the run just before B (so `diff previous latest` shows what changed last)\n"
		<< "  track      replay the saved runs in order and follow every host and service\n"
		<< "options:\n"
		<< "  --format text|json   output format (default text)\n"
		<< "  --all                list everything instead of the first few entries\n"
		<< "  --events             track: also list each run's individual events\n"
		<< "  --until N            track: stop after run N\n"
		<< "  --stale-below X      existence confidence under which a host is stale (default 0.5)\n"
		<< "  --gone-below X       ... under which it may be gone (default 0.05)\n"
		<< "  --gone-after T       minimum time unseen before gone, e.g. 12h (default 12h)\n"
		<< "  --flap-window N      recent scans inspected for flapping (default 8)\n"
		<< "  --flap-transitions N answered/missed changes in that window that mean flapping (default 3)\n";
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

static int64_t resolve(const proculus::FileResultStore& store, const std::string& which, bool allow_previous) {
	using namespace proculus;
	if (which == "latest" || (allow_previous && which == "previous")) {
		auto runs = store.list();
		const size_t need = which == "latest" ? 1 : 2;
		if (runs.size() < need) throw std::runtime_error("not enough runs stored for '" + which + "'");
		return runs[runs.size() - need].id;
	}
	if (which.empty() || which.size() > 15 || which.find_first_not_of("0123456789") != std::string::npos)
		throw std::invalid_argument("not a run number: " + which);
	return std::stoll(which);
}

static proculus::RunRecord load(const proculus::FileResultStore& store, int64_t id) {
	auto run = store.load(id);
	if (!run) throw std::runtime_error("no run " + std::to_string(id) + " in the store");
	return *run;
}

int main(int argc, char** argv) {
	using namespace proculus;
	std::string store_dir;
	ReportOptions report;
	DifferConfig cfg;
	int64_t until = -1;

	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_STORE: store_dir = optarg; break;
			case OPT_FORMAT: {
				const std::string f = optarg;
				if (f != "text" && f != "json") throw std::invalid_argument("unknown format '" + f + "' (use text or json)");
				report.json = f == "json";
				break;
			}
			case OPT_ALL: report.all = true; break;
			case OPT_EVENTS: report.events = true; break;
			case OPT_UNTIL: until = static_cast<int64_t>(to_double(optarg, "--until")); break;
			case OPT_STALE_BELOW: cfg.stale_below = to_double(optarg, "--stale-below"); break;
			case OPT_GONE_BELOW: cfg.gone_below = to_double(optarg, "--gone-below"); break;
			case OPT_GONE_AFTER: cfg.gone_after = parse_duration(optarg); break;
			case OPT_FLAP_WINDOW: cfg.flap_window = static_cast<int>(to_double(optarg, "--flap-window")); break;
			case OPT_FLAP_TRANSITIONS: cfg.flap_transitions = static_cast<int>(to_double(optarg, "--flap-transitions")); break;
			case OPT_HELP: usage(argv[0]); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (store_dir.empty()) throw std::invalid_argument("--store DIR is required (see --help)");
		if (optind >= argc) throw std::invalid_argument("expected a command: diff or track");
		const std::string command = argv[optind++];
		FileResultStore store(store_dir);

		if (command == "diff") {
			if (optind + 2 != argc) throw std::invalid_argument("diff needs two runs: diff A B");
			const std::string a = argv[optind], b = argv[optind + 1];
			// "previous" as the first argument means the run before B
			RunRecord after = load(store, resolve(store, b, false));
			RunRecord before;
			if (a == "previous") {
				auto runs = store.list();
				int64_t prev = -1;
				for (const auto& r : runs)
					if (r.id < after.id) prev = r.id;
				if (prev < 0) throw std::runtime_error("there is no run before run " + std::to_string(after.id));
				before = load(store, prev);
			} else {
				before = load(store, resolve(store, a, false));
			}
			std::cout << render_comparison(before, after, compare_runs(before, after), report);
		} else if (command == "track") {
			if (optind < argc) throw std::invalid_argument("track takes no arguments");
			Tracker tracker(cfg);
			std::vector<RunUpdate> updates;
			for (const RunSummary& s : store.list()) {
				if (until >= 0 && s.id > until) break;
				updates.push_back(tracker.apply(load(store, s.id)));
			}
			if (updates.empty()) throw std::runtime_error("no runs stored in " + store_dir);
			std::cout << render_tracking(updates, tracker, report);
		} else {
			throw std::invalid_argument("unknown command '" + command + "' (use diff or track)");
		}
		return 0;
	} catch (const FormatError& e) {
		std::cerr << "error: stored data is damaged: " << e.what() << "\n";
		return 3;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
