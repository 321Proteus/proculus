// scheduler: previews a scan schedule. Shows when scanning windows open, and
// replays a run of a given length to show where it would start, pause (when the
// window closes) and resume.
#include <getopt.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "schedule.hpp"

using namespace proculus;

enum { OPT_WINDOW = 256, OPT_DAYS, OPT_OFFSET, OPT_INTERVAL, OPT_MIN_REMAINING, OPT_FROM, OPT_COUNT, OPT_RUN, OPT_HELP };

static const option long_opts[] = {
	{"window", required_argument, nullptr, OPT_WINDOW},
	{"days", required_argument, nullptr, OPT_DAYS},
	{"utc-offset", required_argument, nullptr, OPT_OFFSET},
	{"interval", required_argument, nullptr, OPT_INTERVAL},
	{"min-remaining", required_argument, nullptr, OPT_MIN_REMAINING},
	{"from", required_argument, nullptr, OPT_FROM},
	{"count", required_argument, nullptr, OPT_COUNT},
	{"run", required_argument, nullptr, OPT_RUN},
	{"help", no_argument, nullptr, OPT_HELP},
	{nullptr, 0, nullptr, 0},
};

static void usage(const char* argv0) {
	std::cerr << "usage: " << argv0 << " --window HH:MM-HH:MM [options]\n"
		  << "  --window W        daily scan window, e.g. 22:00-06:00 (may cross midnight)\n"
		  << "  --days D          weekdays a window may start on: all, mon-fri, sat,sun (default all)\n"
		  << "  --utc-offset O    local time = UTC + O, e.g. +01:00 (default Z; no DST handling)\n"
		  << "  --interval T      minimum time between run starts, e.g. 24h, 3d (default 24h)\n"
		  << "  --min-remaining T do not start a run with less than T of the window left (default 5m)\n"
		  << "  --from TIME       preview from this UTC time, e.g. 2026-11-21T12:00:00Z (default: now)\n"
		  << "  --count N         how many upcoming windows to list (default 5)\n"
		  << "  --run T           also replay a run needing T of scanning, e.g. 20h\n";
}

int main(int argc, char** argv) {
	Schedule s;
	TimePoint from = std::chrono::time_point_cast<Seconds>(std::chrono::system_clock::now());
	size_t count = 5;
	std::optional<Seconds> run;
	bool have_window = false;

	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_WINDOW: parse_window(optarg, s); have_window = true; break;
			case OPT_DAYS: s.days = parse_days(optarg); break;
			case OPT_OFFSET: s.utc_offset_min = parse_utc_offset(optarg); break;
			case OPT_INTERVAL: s.interval = parse_duration(optarg); break;
			case OPT_MIN_REMAINING: s.min_start_remaining = parse_duration(optarg); break;
			case OPT_FROM: from = parse_time(optarg); break;
			case OPT_COUNT: count = std::stoul(optarg); break;
			case OPT_RUN: run = parse_duration(optarg); break;
			case OPT_HELP: usage(argv[0]); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (optind < argc) throw std::invalid_argument(std::string("unexpected argument: ") + argv[optind]);
		if (!have_window) throw std::invalid_argument("--window is required (see --help)");
		validate(s);

		std::cout << "from " << format_time(from) << "\n";
		if (const auto w = window_containing(s, from))
			std::cout << "window open now, closes " << format_time(w->end) << "\n";
		std::cout << "upcoming windows:\n";
		for (const auto& w : upcoming_windows(s, from, count)) {
			const auto len = std::chrono::duration_cast<Seconds>(w.end - w.start).count();
			std::cout << "  " << format_time(w.start) << " -> " << format_time(w.end) << "  (" << len / 3600 << "h"
				  << len % 3600 / 60 << "m)\n";
		}

		if (run) {
			std::cout << "run of " << run->count() / 3600 << "h" << run->count() % 3600 / 60 << "m of scanning:\n";
			static const char* names[] = {"started", "paused (window closed)", "resumed", "finished"};
			const auto events = simulate_run(s, from, *run);
			if (events.empty()) std::cout << "  never starts (schedule disabled or no usable windows)\n";
			for (const auto& e : events)
				std::cout << "  " << format_time(e.at) << "  " << names[static_cast<int>(e.type)] << "\n";
		}
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
