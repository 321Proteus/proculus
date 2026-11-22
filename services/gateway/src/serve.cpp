#include "serve.hpp"

#include <getopt.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include "proculus/web/guard.hpp"
#include "server.hpp"

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
	          << "There is no login yet: keep it on the local machine.\n";
}

} // namespace

int serve_command(int argc, char** argv) {
	enum { OPT_STORE = 256, OPT_PORT, OPT_BIND, OPT_ALLOW_HOST, OPT_HELP };
	static const option opts[] = {
		{"store", required_argument, nullptr, OPT_STORE}, {"port", required_argument, nullptr, OPT_PORT},
		{"bind", required_argument, nullptr, OPT_BIND},   {"allow-host", required_argument, nullptr, OPT_ALLOW_HOST},
		{"help", no_argument, nullptr, OPT_HELP}, {nullptr, 0, nullptr, 0},
	};
	ServerConfig cfg;
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
			case OPT_HELP: usage(); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (optind < argc) throw std::invalid_argument(std::string("unexpected argument: ") + argv[optind]);
		if (store_dir.empty())
			if (const char* env = std::getenv("PROCULUS_STORE_DIR")) store_dir = env;
		if (store_dir.empty()) throw std::invalid_argument("no store: give --store DIR or set PROCULUS_STORE_DIR");

		FileResultStore store(store_dir);
		WebServer server(store, cfg);
		const int port = server.bind();
		g_server = &server;
		std::signal(SIGINT, on_signal);
		std::signal(SIGTERM, on_signal);
		std::cerr << "proculus: serving " << store_dir << " on http://" << cfg.bind << ":" << port << "/ (read-only API, no login yet)\n";
		server.run();
		g_server = nullptr;
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}

} // namespace proculus
