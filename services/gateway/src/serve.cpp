#include "serve.hpp"

#include <getopt.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include "proculus/web/guard.hpp"
#include "scan_control.hpp"
#include "server.hpp"
#include "token_guard.hpp"

namespace proculus {

namespace {

WebServer* g_server = nullptr;

void on_signal(int) {
	if (g_server) g_server->stop(); // stop() only flips the listener off; safe enough for a shutdown handler
}

void usage() {
	std::cerr << "usage: gateway serve [options]\n"
	          << "Serves a read-only JSON API over the saved runs (the web UI is services/ui).\n"
	          << "  --store DIR       directory of saved runs (default: $PROCULUS_STORE_DIR)\n"
	          << "  --port N          port to listen on (default 8081)\n"
	          << "  --bind ADDR       address to listen on (default 127.0.0.1)\n"
	          << "  --allow-host H    accept requests addressed to this host name too (repeatable)\n"
	          << "scans from the web UI (off by default; the limits below are fixed here, the form can only go under them)\n"
	          << "  --enable-scans          allow starting scans from the UI; needs --scan-scope and --scan-ports\n"
	          << "  --scan-scope LIST       the only addresses a UI scan may touch\n"
	          << "  --scan-ports LIST       the only ports a UI scan may probe\n"
	          << "  --scan-max-workers N    (default 4)    --scan-max-rate PPS  per nmap process (default 200)\n"
	          << "  --scan-allow-privileged raw-socket scans (needs root / CAP_NET_RAW)   --scan-no-web  no web probing\n"
	          << "  --scan-allow-reserved   allow loopback etc. (tests, local labs)       --scan-nmap PATH   --scan-signatures PATH (repeatable)\n"
	          << "  Starting or stopping a scan needs the control token ($PROCULUS_CONTROL_TOKEN, or a random one printed at startup).\n"
	          << "There is no login yet: keep it on the local machine.\n";
}

} // namespace

int serve_command(int argc, char** argv) {
	enum { OPT_STORE = 256, OPT_PORT, OPT_BIND, OPT_ALLOW_HOST, OPT_ENABLE_SCANS, OPT_SCAN_SCOPE, OPT_SCAN_PORTS, OPT_SCAN_WORKERS, OPT_SCAN_RATE, OPT_SCAN_PRIVILEGED, OPT_SCAN_NO_WEB,
		OPT_SCAN_ALLOW_RESERVED, OPT_SCAN_NMAP, OPT_SCAN_SIGNATURES, OPT_HELP };
	static const option opts[] = {
		{"store", required_argument, nullptr, OPT_STORE}, {"port", required_argument, nullptr, OPT_PORT},
		{"bind", required_argument, nullptr, OPT_BIND},   {"allow-host", required_argument, nullptr, OPT_ALLOW_HOST},
		{"enable-scans", no_argument, nullptr, OPT_ENABLE_SCANS},
		{"scan-scope", required_argument, nullptr, OPT_SCAN_SCOPE},
		{"scan-ports", required_argument, nullptr, OPT_SCAN_PORTS},
		{"scan-max-workers", required_argument, nullptr, OPT_SCAN_WORKERS},
		{"scan-max-rate", required_argument, nullptr, OPT_SCAN_RATE},
		{"scan-allow-privileged", no_argument, nullptr, OPT_SCAN_PRIVILEGED},
		{"scan-no-web", no_argument, nullptr, OPT_SCAN_NO_WEB},
		{"scan-allow-reserved", no_argument, nullptr, OPT_SCAN_ALLOW_RESERVED},
		{"scan-nmap", required_argument, nullptr, OPT_SCAN_NMAP},
		{"scan-signatures", required_argument, nullptr, OPT_SCAN_SIGNATURES},
		{"help", no_argument, nullptr, OPT_HELP}, {nullptr, 0, nullptr, 0},
	};
	ServerConfig cfg;
	ScanPolicy policy;
	std::string store_dir;
	try {
		optind = 1;
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_STORE: store_dir = optarg; break;
			case OPT_PORT: cfg.port = web::parse_port(optarg); break;
			case OPT_BIND: cfg.bind = optarg; break;
			case OPT_ALLOW_HOST: cfg.allowed_hosts.push_back(optarg); break;
			case OPT_ENABLE_SCANS: policy.enabled = true; break;
			case OPT_SCAN_SCOPE: policy.scope = optarg; break;
			case OPT_SCAN_PORTS: policy.allowed_ports = optarg; break;
			case OPT_SCAN_WORKERS: policy.max_workers = static_cast<unsigned>(std::stoul(optarg)); break;
			case OPT_SCAN_RATE: policy.max_rate = std::stoi(optarg); break;
			case OPT_SCAN_PRIVILEGED: policy.allow_privileged = true; break;
			case OPT_SCAN_NO_WEB: policy.allow_web = false; break;
			case OPT_SCAN_ALLOW_RESERVED: policy.allow_reserved = true; break;
			case OPT_SCAN_NMAP: policy.nmap_path = optarg; break;
			case OPT_SCAN_SIGNATURES: policy.signature_paths.push_back(optarg); break;
			case OPT_HELP: usage(); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (optind < argc) throw std::invalid_argument(std::string("unexpected argument: ") + argv[optind]);
		if (store_dir.empty())
			if (const char* env = std::getenv("PROCULUS_STORE_DIR")) store_dir = env;
		if (store_dir.empty()) throw std::invalid_argument("no store: give --store DIR or set PROCULUS_STORE_DIR");

		FileResultStore store(store_dir);
		if (policy.enabled) {
			if (const char* env = std::getenv("PROCULUS_CONTROL_TOKEN"); env && *env) {
				cfg.control_token = env;
				if (cfg.control_token.size() < 16) throw std::invalid_argument("PROCULUS_CONTROL_TOKEN is too short (use at least 16 characters)");
			} else {
				cfg.control_token = TokenGuard::generate();
				std::cerr << "proculus: control token for starting scans: " << cfg.control_token << "\n";
			}
		}
		ScanController scans(policy, &store); // validates the policy
		WebServer server(store, cfg, &scans);
		const int port = server.bind();
		g_server = &server;
		std::signal(SIGINT, on_signal);
		std::signal(SIGTERM, on_signal);
		std::cerr << "proculus: serving " << store_dir << " on http://" << cfg.bind << ":" << port << "/ (API, no login yet)\n";
		server.run();
		g_server = nullptr;
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}

} // namespace proculus
