#include "serve.hpp"

#include <getopt.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include "proculus/web/guard.hpp"
#ifdef PROCULUS_HAVE_PGSTORE
#include "proculus/pgstore/pgstore.hpp"
#endif
#ifdef PROCULUS_HAVE_AUTH
#include "proculus/auth/fileauth.hpp"
#include "proculus/auth/pgauth.hpp"
#endif
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
#ifdef PROCULUS_HAVE_PGSTORE
	          << "  --db URL          read and write runs in Postgres instead of --store (or $PROCULUS_DB_URL; keys from $PROCULUS_KEY / $PROCULUS_KEY_FILE)\n"
	          << "  --db-migrations D where the SQL migrations are (default $PROCULUS_MIGRATIONS_DIR)\n"
#endif
	          << "login (on by default: the first visit asks for the setup token printed here and creates the administrator)\n"
	          << "  --accounts DIR    where accounts are kept without a database (default: DIR/accounts inside --store)\n"
	          << "  --no-auth         NO LOGIN: anyone who can reach the server can read everything (local use only)\n"
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
	          << "Accounts: with --db in Postgres, otherwise in files; create more with `gateway user add`.\n";
}

} // namespace

int serve_command(int argc, char** argv) {
	enum { OPT_STORE = 256, OPT_PORT, OPT_BIND, OPT_ALLOW_HOST, OPT_DB, OPT_DB_MIGRATIONS, OPT_AUTH, OPT_NO_AUTH, OPT_ACCOUNTS, OPT_ENABLE_SCANS, OPT_SCAN_SCOPE, OPT_SCAN_PORTS, OPT_SCAN_WORKERS, OPT_SCAN_RATE, OPT_SCAN_PRIVILEGED, OPT_SCAN_NO_WEB,
		OPT_SCAN_ALLOW_RESERVED, OPT_SCAN_NMAP, OPT_SCAN_SIGNATURES, OPT_HELP };
	static const option opts[] = {
		{"store", required_argument, nullptr, OPT_STORE}, {"port", required_argument, nullptr, OPT_PORT},
		{"bind", required_argument, nullptr, OPT_BIND},   {"allow-host", required_argument, nullptr, OPT_ALLOW_HOST},
		{"db", required_argument, nullptr, OPT_DB},
		{"db-migrations", required_argument, nullptr, OPT_DB_MIGRATIONS},
		{"auth", no_argument, nullptr, OPT_AUTH},
		{"no-auth", no_argument, nullptr, OPT_NO_AUTH},
		{"accounts", required_argument, nullptr, OPT_ACCOUNTS},
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
	std::string store_dir, db_url, db_migrations;
	bool use_auth = true; // login is the default; --no-auth turns it off
	std::string accounts_dir;
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
			case OPT_DB: db_url = optarg; break;
			case OPT_DB_MIGRATIONS: db_migrations = optarg; break;
			case OPT_AUTH: use_auth = true; break;
			case OPT_NO_AUTH: use_auth = false; break;
			case OPT_ACCOUNTS: accounts_dir = optarg; break;
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
		if (db_url.empty())
			if (const char* env = std::getenv("PROCULUS_DB_URL")) db_url = env;
		if (store_dir.empty())
			if (const char* env = std::getenv("PROCULUS_STORE_DIR")) store_dir = env;
		if (store_dir.empty() && db_url.empty()) throw std::invalid_argument("no store: give --store DIR (or --db URL), or set PROCULUS_STORE_DIR");

		std::unique_ptr<ResultStore> store_owner;
		std::string store_name = store_dir;
		if (!db_url.empty()) {
#ifdef PROCULUS_HAVE_PGSTORE
			store_owner = open_pg_store(db_url, db_migrations.empty() ? default_migrations_dir() : std::filesystem::path(db_migrations));
			store_name = "the Postgres database";
#else
			throw std::invalid_argument("this build has no Postgres support (libpq and libsodium were not found)");
#endif
		} else {
			store_owner = std::make_unique<FileResultStore>(store_dir);
		}
		ResultStore& store = *store_owner;
		if (const char* env = std::getenv("PROCULUS_AUTH"); env && std::string(env) == "0") use_auth = false;
		std::unique_ptr<web::AuthBackend> auth_backend;
		if (use_auth) {
#ifdef PROCULUS_HAVE_AUTH
			if (!db_url.empty()) {
				auth_backend = auth::open_pg_auth(db_url, db_migrations.empty() ? default_migrations_dir() : std::filesystem::path(db_migrations));
			} else {
				if (accounts_dir.empty()) accounts_dir = (std::filesystem::path(store_dir) / "accounts").string();
				auth_backend = std::make_unique<auth::FileAuthBackend>(accounts_dir);
			}
			if (!auth_backend->has_users()) {
				if (const char* env = std::getenv("PROCULUS_SETUP_TOKEN"); env && *env) {
					cfg.setup_token = env;
					if (cfg.setup_token.size() < 16) throw std::invalid_argument("PROCULUS_SETUP_TOKEN is too short (use at least 16 characters)");
				} else {
					cfg.setup_token = TokenGuard::generate();
				}
				std::cerr << "proculus: FIRST-RUN SETUP: there are no accounts yet. Open the UI and create the administrator with this setup token:\n"
				          << "          " << cfg.setup_token << "\n"
				          << "          (or from the command line: gateway user add YOUR.NAME --role admin)\n";
			}
#else
			throw std::invalid_argument("this build has no login support (libsodium was not found); to run without login use --no-auth");
#endif
		} else {
			std::cerr << "proculus: WARNING: login is OFF (--no-auth): anyone who can reach this server can read everything\n";
		}
		if (policy.enabled && !use_auth) { // without login, starting scans needs the control token
			if (const char* env = std::getenv("PROCULUS_CONTROL_TOKEN"); env && *env) {
				cfg.control_token = env;
				if (cfg.control_token.size() < 16) throw std::invalid_argument("PROCULUS_CONTROL_TOKEN is too short (use at least 16 characters)");
			} else {
				cfg.control_token = TokenGuard::generate();
				std::cerr << "proculus: control token for starting scans: " << cfg.control_token << "\n";
			}
		}
		ScanController scans(policy, &store); // validates the policy
		WebServer server(store, cfg, &scans, auth_backend.get());
		const int port = server.bind();
		g_server = &server;
		std::signal(SIGINT, on_signal);
		std::signal(SIGTERM, on_signal);
		std::cerr << "proculus: serving " << store_name << " on http://" << cfg.bind << ":" << port << "/ (API, " << (auth_backend ? "login required" : "NO LOGIN") << ")\n";
		server.run();
		g_server = nullptr;
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}

} // namespace proculus
