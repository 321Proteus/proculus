// scan-worker: validates a scan job against hard limits, runs nmap, and
// prints the parsed result as JSON on stdout (diagnostics go to stderr).
#include <getopt.h>
#include <unistd.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "job.hpp"
#include "nmap_xml.hpp"
#include "process.hpp"
#include "result_json.hpp"

enum {
	OPT_STAGE = 256,
	OPT_TARGETS,
	OPT_SCOPE,
	OPT_PORTS,
	OPT_ALLOWED_PORTS,
	OPT_PROBE_PORTS,
	OPT_RATE,
	OPT_MAX_RATE,
	OPT_RETRIES,
	OPT_HOST_TIMEOUT,
	OPT_TIMEOUT,
	OPT_TIMING,
	OPT_NO_VERSION,
	OPT_ALLOW_RESERVED,
	OPT_NMAP,
	OPT_DRY_RUN,
	OPT_HELP
};

static const option long_opts[] = {
	{ "stage", required_argument, nullptr, OPT_STAGE },
	{ "targets", required_argument, nullptr, OPT_TARGETS },
	{ "scope", required_argument, nullptr, OPT_SCOPE },
	{ "ports", required_argument, nullptr, OPT_PORTS },
	{ "allowed-ports", required_argument, nullptr, OPT_ALLOWED_PORTS },
	{ "probe-ports", required_argument, nullptr, OPT_PROBE_PORTS },
	{ "rate", required_argument, nullptr, OPT_RATE },
	{ "max-rate", required_argument, nullptr, OPT_MAX_RATE },
	{ "retries", required_argument, nullptr, OPT_RETRIES },
	{ "host-timeout", required_argument, nullptr, OPT_HOST_TIMEOUT },
	{ "timeout", required_argument, nullptr, OPT_TIMEOUT },
	{ "timing", required_argument, nullptr, OPT_TIMING },
	{ "no-version", no_argument, nullptr, OPT_NO_VERSION },
	{ "allow-reserved", no_argument, nullptr, OPT_ALLOW_RESERVED },
	{ "nmap", required_argument, nullptr, OPT_NMAP },
	{ "dry-run", no_argument, nullptr, OPT_DRY_RUN },
	{ "help", no_argument, nullptr, OPT_HELP },
	{ nullptr, 0, nullptr, 0 },
};

static void usage(const char* argv0) {
	std::cerr
		<< "usage: " << argv0
		<< " --stage discovery|services --targets LIST --scope LIST\n"
		<< "         --allowed-ports LIST [options]\n"
		<< "  --targets LIST       IPs/CIDRs/ranges to scan (one planner "
		   "chunk)\n"
		<< "  --scope LIST         hard limit: targets must lie inside "
		   "(required)\n"
		<< "  --allowed-ports LIST hard limit: only these ports may be probed "
		   "(required)\n"
		<< "  --ports LIST         ports for the services stage (default: all "
		   "allowed)\n"
		<< "  --probe-ports LIST   discovery TCP probe ports (default 80,443)\n"
		<< "  --rate N             packets/s (default 100)     --max-rate N  "
		   "ceiling (default 1000)\n"
		<< "  --retries N          (default 1)                 --timing 0..4 "
		   "(default 3)\n"
		<< "  --host-timeout S     per host (default 60)       --timeout S   "
		   "whole run (default 600)\n"
		<< "  --no-version         skip service version detection\n"
		<< "  --allow-reserved     do not strip loopback/multicast/link-local "
		   "targets\n"
		<< "  --nmap PATH          nmap binary (default: nmap)\n"
		<< "  --dry-run            print the nmap command and exit\n";
}

static int to_int(const char* s, const char* what) {
	try {
		size_t pos = 0;
		int v = std::stoi(s, &pos);
		if (s[pos] != '\0') throw std::invalid_argument("");
		return v;
	} catch (const std::exception&) {
		throw std::invalid_argument(
			std::string("invalid number for ") + what + ": " + s);
	}
}

int main(int argc, char** argv) {
	using namespace proculus;
	ScanJob job;
	JobLimits limits;
	std::string nmap = "nmap";
	bool dry_run = false;
	bool have_stage = false;
	job.privileged = geteuid() == 0;

	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_STAGE: {
				std::string s = optarg;
				if (s == "discovery") job.stage = Stage::Discovery;
				else if (s == "services")
					job.stage = Stage::Services;
				else
					throw std::invalid_argument(
						"stage must be discovery or services");
				have_stage = true;
				break;
			}
			case OPT_TARGETS:		job.targets = optarg; break;
			case OPT_SCOPE:			limits.scope = optarg; break;
			case OPT_PORTS:			job.ports = optarg; break;
			case OPT_ALLOWED_PORTS: limits.allowed_ports = optarg; break;
			case OPT_PROBE_PORTS:	job.probe_ports = optarg; break;
			case OPT_RATE:			job.rate = to_int(optarg, "--rate"); break;
			case OPT_MAX_RATE:
				limits.max_rate = to_int(optarg, "--max-rate");
				break;
			case OPT_RETRIES: job.retries = to_int(optarg, "--retries"); break;
			case OPT_HOST_TIMEOUT:
				job.host_timeout_s = to_int(optarg, "--host-timeout");
				break;
			case OPT_TIMEOUT:
				job.timeout_s = to_int(optarg, "--timeout");
				break;
			case OPT_TIMING:	 job.timing = to_int(optarg, "--timing"); break;
			case OPT_NO_VERSION: job.version_detect = false; break;
			case OPT_ALLOW_RESERVED: limits.allow_reserved = true; break;
			case OPT_NMAP:			 nmap = optarg; break;
			case OPT_DRY_RUN:		 dry_run = true; break;
			case OPT_HELP:			 usage(argv[0]); return 0;
			default:
				throw std::invalid_argument(
					std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (optind < argc)
			throw std::invalid_argument(
				"unexpected argument: " + std::string(argv[optind]));
		if (!have_stage || job.targets.empty())
			throw std::invalid_argument(
				"--stage and --targets are required (see --help)");

		NmapCommand cmd = build_command(job, limits, nmap);

		std::cerr << "targets: " << cmd.target_count << " address(es)";
		if (cmd.reserved_stripped)
			std::cerr << " (" << cmd.reserved_stripped << " reserved stripped)";
		std::cerr << "\ncommand:";
		for (const auto& a : cmd.argv)
			std::cerr << ' ' << a;
		std::cerr << "\n";
		if (dry_run) return 0;

		RunOptions ro;
		ro.timeout = std::chrono::seconds(cmd.timeout_s);
		RunResult rr = run_process(cmd.argv, ro);

		if (rr.timed_out) {
			std::cerr << "error: nmap exceeded the " << cmd.timeout_s
					  << " s limit and was stopped\n";
			return 3;
		}
		if (rr.exit_code != 0) {
			std::cerr << "error: nmap failed (exit " << rr.exit_code
					  << ", signal " << rr.term_signal << "): " << rr.err;
			return 3;
		}
		if (rr.output_truncated) {
			std::cerr << "error: nmap output exceeded the size limit\n";
			return 3;
		}
		std::cout << to_json(parse_nmap_xml(rr.out));
		return 0;
	} catch (const JobRejected& e) {
		std::cerr << "rejected: " << e.what() << "\n";
		return 4;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
