// ui: the web UI service. Serves the pages and passes /api/ requests to the gateway.
#include <getopt.h>

#include <csignal>
#include <iostream>
#include <stdexcept>

#include "ui_server.hpp"

static proculus::UiServer* g_server = nullptr;
static void on_signal(int) {
	if (g_server) g_server->stop();
}

static void usage() {
	std::cerr << "usage: ui [options]\n"
	          << "Serves the Proculus web UI and passes its /api/ requests to the gateway.\n"
	          << "  --api URL         the gateway API (default http://127.0.0.1:8081)\n"
	          << "  --port N          port to listen on (default 8080)\n"
	          << "  --bind ADDR       address to listen on (default 127.0.0.1)\n"
	          << "  --allow-host H    accept requests addressed to this host name too (repeatable)\n"
	          << "  --web-dir DIR     serve the files from DIR instead of the built-in copy (for UI development)\n"
	          << "There is no login yet: keep it on the local machine.\n";
}

int main(int argc, char** argv) {
	enum { OPT_API = 256, OPT_PORT, OPT_BIND, OPT_ALLOW_HOST, OPT_WEB_DIR, OPT_HELP };
	static const option opts[] = {
		{"api", required_argument, nullptr, OPT_API},         {"port", required_argument, nullptr, OPT_PORT},
		{"bind", required_argument, nullptr, OPT_BIND},       {"allow-host", required_argument, nullptr, OPT_ALLOW_HOST},
		{"web-dir", required_argument, nullptr, OPT_WEB_DIR}, {"help", no_argument, nullptr, OPT_HELP}, {nullptr, 0, nullptr, 0},
	};
	proculus::UiConfig cfg;
	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_API: cfg.api = proculus::web::parse_upstream(optarg); break;
			case OPT_PORT: cfg.port = proculus::web::parse_port(optarg); break;
			case OPT_BIND: cfg.bind = optarg; break;
			case OPT_ALLOW_HOST: cfg.allowed_hosts.push_back(optarg); break;
			case OPT_WEB_DIR: cfg.web_dir = optarg; break;
			case OPT_HELP: usage(); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (optind < argc) throw std::invalid_argument(std::string("unexpected argument: ") + argv[optind]);

		proculus::UiServer server(cfg);
		const int port = server.bind();
		g_server = &server;
		std::signal(SIGINT, on_signal);
		std::signal(SIGTERM, on_signal);
		std::cerr << "proculus ui: http://" << cfg.bind << ":" << port << "/  (API: " << cfg.api.host << ":" << cfg.api.port << ")\n";
		server.run();
		g_server = nullptr;
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
