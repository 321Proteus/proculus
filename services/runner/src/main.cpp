// runner: runs real scans: planned chunks, nmap workers, scan windows, optional
// web probing with signatures, results saved as runs.
#include <getopt.h>

#include <csignal>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>

#include "runner.hpp"

using namespace proculus;

static Runner* g_runner = nullptr;
static void on_signal(int) {
	if (g_runner) g_runner->request_stop();
}

enum {
	OPT_SCOPE = 256, OPT_PORTS, OPT_SERVICE_PORTS, OPT_EXCLUDE_FILE, OPT_STORE, OPT_WORKERS, OPT_RATE, OPT_TIMING, OPT_RETRIES, OPT_HOST_TIMEOUT,
	OPT_PRIVILEGED, OPT_NO_VERSION, OPT_ALLOW_RESERVED, OPT_NMAP, OPT_CHUNK_SECONDS, OPT_DISC_RATE, OPT_SERV_RATE, OPT_ATTEMPTS, OPT_WINDOW, OPT_OFFSET,
	OPT_DAYS, OPT_INTERVAL, OPT_MIN_REMAINING, OPT_ROUNDS, OPT_WEB, OPT_WEB_RATE, OPT_WEB_WORKERS, OPT_MAX_PATHS, OPT_SIGNATURES, OPT_NO_BUILTIN_SIGS, OPT_DRY_RUN, OPT_HELP
};

static const option long_opts[] = {
	{"scope", required_argument, nullptr, OPT_SCOPE},
	{"allowed-ports", required_argument, nullptr, OPT_PORTS},
	{"service-ports", required_argument, nullptr, OPT_SERVICE_PORTS},
	{"exclude", required_argument, nullptr, 'x'},
	{"exclude-file", required_argument, nullptr, OPT_EXCLUDE_FILE},
	{"targets", required_argument, nullptr, 't'},
	{"store", required_argument, nullptr, OPT_STORE},
	{"workers", required_argument, nullptr, OPT_WORKERS},
	{"rate", required_argument, nullptr, OPT_RATE},
	{"timing", required_argument, nullptr, OPT_TIMING},
	{"retries", required_argument, nullptr, OPT_RETRIES},
	{"host-timeout", required_argument, nullptr, OPT_HOST_TIMEOUT},
	{"privileged", no_argument, nullptr, OPT_PRIVILEGED},
	{"no-version-detection", no_argument, nullptr, OPT_NO_VERSION},
	{"allow-reserved", no_argument, nullptr, OPT_ALLOW_RESERVED},
	{"nmap", required_argument, nullptr, OPT_NMAP},
	{"chunk-seconds", required_argument, nullptr, OPT_CHUNK_SECONDS},
	{"assumed-discovery-rate", required_argument, nullptr, OPT_DISC_RATE},
	{"assumed-services-rate", required_argument, nullptr, OPT_SERV_RATE},
	{"max-attempts", required_argument, nullptr, OPT_ATTEMPTS},
	{"window", required_argument, nullptr, OPT_WINDOW},
	{"utc-offset", required_argument, nullptr, OPT_OFFSET},
	{"days", required_argument, nullptr, OPT_DAYS},
	{"interval", required_argument, nullptr, OPT_INTERVAL},
	{"min-remaining", required_argument, nullptr, OPT_MIN_REMAINING},
	{"rounds", required_argument, nullptr, OPT_ROUNDS},
	{"web", no_argument, nullptr, OPT_WEB},
	{"web-rate", required_argument, nullptr, OPT_WEB_RATE},
	{"web-workers", required_argument, nullptr, OPT_WEB_WORKERS},
	{"max-paths", required_argument, nullptr, OPT_MAX_PATHS},
	{"signatures", required_argument, nullptr, OPT_SIGNATURES},
	{"no-builtin-signatures", no_argument, nullptr, OPT_NO_BUILTIN_SIGS},
	{"dry-run", no_argument, nullptr, OPT_DRY_RUN},
	{"help", no_argument, nullptr, OPT_HELP},
	{nullptr, 0, nullptr, 0},
};

static void usage() {
	std::cerr
		<< "usage: runner --scope LIST --allowed-ports LIST [options] [TARGET...]\n"
		<< "Scans real networks: discovery, services (nmap), optional web probing, results saved as runs.\n"
		<< "targets and limits\n"
		<< "  TARGET...                IP, CIDR, range or domain (or -t FILE; '-' = stdin)\n"
		<< "  --scope LIST             hard limit: only these addresses may ever be scanned (required)\n"
		<< "  --allowed-ports LIST     hard limit: only these ports may be probed (required)\n"
		<< "  --service-ports LIST     ports for the services stage (default: all allowed ports)\n"
		<< "  -x, --exclude SPEC       never scan this (repeatable)      --exclude-file FILE\n"
		<< "  --allow-reserved         allow loopback/multicast/link-local addresses (for tests)\n"
		<< "how hard\n"
		<< "  --workers N              nmap processes at once (default 2)\n"
		<< "  --rate PPS               packets/s per nmap process (default 100; total = workers x rate)\n"
		<< "  --timing 0-4             nmap -T level (default 3)    --retries N (default 1)    --host-timeout S (default 60)\n"
		<< "  --privileged             raw-socket scans (SYN, ICMP ping): needs root / CAP_NET_RAW; better host discovery\n"
		<< "  --no-version-detection   skip nmap -sV\n"
		<< "  --chunk-seconds S        aimed duration of one chunk (default 120)\n"
		<< "  --assumed-discovery-rate N / --assumed-services-rate N   speed assumed until measured (addresses/s, hosts/s per worker)\n"
		<< "  --nmap PATH              nmap binary (default nmap)\n"
		<< "when\n"
		<< "  --window HH:MM-HH:MM     scan window (UTC; --utc-offset +01:00); running scans are stopped when it closes and resumed in the next\n"
		<< "  --days mon-fri           weekdays a window may start on\n"
		<< "  --min-remaining 5m       a round is not started with less than this left of the window (default 5m)\n"
		<< "  --interval 24h           minimum time between rounds       --rounds N   rounds to run (default 1, 0 = until stopped)\n"
		<< "results\n"
		<< "  --store DIR              save every round as a run (read with exporter / differ / the web UI)\n"
		<< "  --web                    probe the web services found (headers, cookies, TLS, titles) and detect technologies\n"
		<< "  --web-rate N / --web-workers N / --max-paths N / --signatures PATH / --no-builtin-signatures   (see http-prober)\n"
		<< "  --dry-run                show the plan and the estimated duration, scan nothing\n"
		<< "Only scan networks you are authorised to scan.\n";
}

static double to_double(const char* s, const char* what) {
	try {
		size_t pos = 0;
		const double v = std::stod(s, &pos);
		if (s[pos] != '\0') throw std::invalid_argument("");
		return v;
	} catch (const std::exception&) {
		throw std::invalid_argument(std::string("invalid number for ") + what + ": " + s);
	}
}

static std::string duration_text(double seconds) {
	const long long s = static_cast<long long>(seconds + 0.5);
	std::ostringstream o;
	if (s >= 3600) o << s / 3600 << "h ";
	if (s >= 60) o << s / 60 % 60 << "m ";
	o << s % 60 << "s";
	return o.str();
}

static void read_lines(std::istream& in, std::vector<std::string>& out) {
	std::string l;
	while (std::getline(in, l)) {
		if (auto h = l.find('#'); h != std::string::npos) l.erase(h);
		if (l.find_first_not_of(" \t\r") != std::string::npos) out.push_back(l);
	}
}

int main(int argc, char** argv) {
	RunnerConfig cfg;
	std::string store_dir, window, offset, days, interval, min_remaining, targets_file;
	int rounds = 1;
	bool dry_run = false;

	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "x:t:", long_opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_SCOPE: cfg.scope = optarg; break;
			case OPT_PORTS: cfg.allowed_ports = optarg; break;
			case OPT_SERVICE_PORTS: cfg.ports = optarg; break;
			case 'x': cfg.exclusions.push_back(optarg); break;
			case OPT_EXCLUDE_FILE: {
				std::ifstream f(optarg);
				if (!f) throw std::invalid_argument(std::string("cannot open ") + optarg);
				read_lines(f, cfg.exclusions);
				break;
			}
			case 't': targets_file = optarg; break;
			case OPT_STORE: store_dir = optarg; break;
			case OPT_WORKERS: cfg.workers = static_cast<unsigned>(to_double(optarg, "--workers")); break;
			case OPT_RATE: cfg.rate = static_cast<int>(to_double(optarg, "--rate")); break;
			case OPT_TIMING: cfg.timing = static_cast<int>(to_double(optarg, "--timing")); break;
			case OPT_RETRIES: cfg.retries = static_cast<int>(to_double(optarg, "--retries")); break;
			case OPT_HOST_TIMEOUT: cfg.host_timeout_s = static_cast<int>(to_double(optarg, "--host-timeout")); break;
			case OPT_PRIVILEGED: cfg.privileged = true; break;
			case OPT_NO_VERSION: cfg.version_detect = false; break;
			case OPT_ALLOW_RESERVED: cfg.allow_reserved = true; break;
			case OPT_NMAP: cfg.nmap_path = optarg; break;
			case OPT_CHUNK_SECONDS: cfg.chunk_seconds = to_double(optarg, "--chunk-seconds"); break;
			case OPT_DISC_RATE: cfg.assumed_discovery_rate = to_double(optarg, "--assumed-discovery-rate"); break;
			case OPT_SERV_RATE: cfg.assumed_services_rate = to_double(optarg, "--assumed-services-rate"); break;
			case OPT_ATTEMPTS: cfg.max_attempts = static_cast<int>(to_double(optarg, "--max-attempts")); break;
			case OPT_WINDOW: window = optarg; break;
			case OPT_OFFSET: offset = optarg; break;
			case OPT_DAYS: days = optarg; break;
			case OPT_INTERVAL: interval = optarg; break;
			case OPT_MIN_REMAINING: min_remaining = optarg; break;
			case OPT_ROUNDS: rounds = static_cast<int>(to_double(optarg, "--rounds")); break;
			case OPT_WEB: cfg.web.enabled = true; break;
			case OPT_WEB_RATE: cfg.web.requests_per_second = to_double(optarg, "--web-rate"); break;
			case OPT_WEB_WORKERS: cfg.web.workers = static_cast<unsigned>(to_double(optarg, "--web-workers")); break;
			case OPT_MAX_PATHS: cfg.web.max_paths = static_cast<size_t>(to_double(optarg, "--max-paths")); break;
			case OPT_SIGNATURES: cfg.web.signature_paths.push_back(optarg); break;
			case OPT_NO_BUILTIN_SIGS: cfg.web.builtin_signatures = false; break;
			case OPT_DRY_RUN: dry_run = true; break;
			case OPT_HELP: usage(); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		while (optind < argc) cfg.targets.push_back(argv[optind++]);
		if (!targets_file.empty()) {
			if (targets_file == "-") read_lines(std::cin, cfg.targets);
			else {
				std::ifstream f(targets_file);
				if (!f) throw std::invalid_argument("cannot open " + targets_file);
				read_lines(f, cfg.targets);
			}
		}
		if (rounds < 0) throw std::invalid_argument("--rounds must be >= 0");

		if (!window.empty() || !interval.empty() || !days.empty() || !offset.empty() || !min_remaining.empty()) {
			Schedule sch; // default: window open all day, every day
			if (!window.empty()) parse_window(window, sch);
			if (!offset.empty()) sch.utc_offset_min = parse_utc_offset(offset);
			if (!days.empty()) sch.days = parse_days(days);
			if (!min_remaining.empty()) sch.min_start_remaining = parse_duration(min_remaining);
			if (!interval.empty()) sch.interval = parse_duration(interval);
			else if (rounds != 1) sch.interval = Seconds(24 * 3600);
			cfg.schedule = sch;
		} else if (rounds != 1) {
			throw std::invalid_argument("several rounds need --interval (and optionally --window)");
		}

		if (dry_run) {
			if (cfg.scope.empty() || cfg.allowed_ports.empty()) throw std::invalid_argument("--scope and --allowed-ports are required");
			PlannerConfig pc;
			pc.exclusions = cfg.exclusions;
			pc.workers = cfg.workers;
			pc.chunk_seconds = cfg.chunk_seconds;
			pc.rate_hosts_per_sec = cfg.assumed_discovery_rate;
			pc.allow_reserved = cfg.allow_reserved;
			std::string text;
			for (const std::string& l : cfg.targets) text += l + "\n";
			std::istringstream in(text);
			const Plan plan = make_plan(in, pc);
			for (const LineError& e : plan.errors) std::cerr << "line " << e.line << " ignored (" << e.reason << "): " << e.text << "\n";
			std::cout << "addresses to scan:   " << plan.total_addresses << "\n"
			          << "domains to resolve:  " << plan.domains.size() << " (their addresses are added at run time)\n"
			          << "discovery chunks:    " << plan.chunks.size() << " (" << plan.chunk_size << " addresses each)\n"
			          << "workers:             " << cfg.workers << " x " << cfg.rate << " packets/s\n"
			          << "discovery estimate:  " << duration_text(plan.estimated_seconds) << " at the assumed " << cfg.assumed_discovery_rate
			          << " addresses/s per worker (the real speed is measured as chunks finish)\n"
			          << "services stage:      depends on how many hosts answer (assumed " << cfg.assumed_services_rate << " hosts/s per worker)\n";
			if (cfg.schedule) std::cout << "scan window:         " << (window.empty() ? "always" : window) << ", interval " << duration_text(static_cast<double>(cfg.schedule->interval.count())) << "\n";
			return 0;
		}

		std::unique_ptr<FileResultStore> store;
		if (!store_dir.empty()) store = std::make_unique<FileResultStore>(store_dir);
		SystemClock clock;
		RunnerDeps deps;
		deps.clock = &clock;
		deps.store = store.get();
		deps.log = &std::cerr;
		Runner runner(cfg, deps);
		g_runner = &runner;
		std::signal(SIGINT, on_signal);
		std::signal(SIGTERM, on_signal);

		for (int round = 1; rounds == 0 || round <= rounds; round++) {
			if (rounds != 1) std::cerr << "=== round " << round << " ===\n";
			const RoundReport r = runner.run_round();
			for (const std::string& w : r.warnings) std::cerr << "warning: " << w << "\n";
			std::cout << "round finished: " << r.live_hosts << " hosts, " << r.services << " services";
			if (cfg.web.enabled) std::cout << ", " << r.web_responding << " web services answered, " << r.detections << " detections";
			std::cout << "; " << r.chunks << " chunks, " << r.pauses << " pauses, " << r.cancelled_chunks << " cut off, " << r.splits << " splits";
			if (r.run_id) std::cout << "; saved as run " << r.run_id;
			std::cout << "\n";
		}
		g_runner = nullptr;
		return 0;
	} catch (const RunAborted&) {
		std::cerr << "stopped; the unfinished round was not saved\n";
		return 130;
	} catch (const ScanError& e) {
		std::cerr << "scan failed: " << e.what() << " (nothing was saved for this round)\n";
		return 3;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
