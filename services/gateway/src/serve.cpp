#include "serve.hpp"

#include <getopt.h>

#include <csignal>
#include <thread>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include "proculus/web/guard.hpp"
#ifdef PROCULUS_HAVE_PGSTORE
#include "proculus/pgstore/pgedits.hpp"
#include "proculus/pgstore/pgstore.hpp"
#endif
#ifdef PROCULUS_HAVE_AUTH
#include "proculus/auth/fileauth.hpp"
#include "proculus/auth/pgauth.hpp"
#endif
#include "scan_control.hpp"
#include "server.hpp"
#include "simulate.hpp"
#include "token_guard.hpp"
#include "ui_server.hpp"

namespace proculus {

namespace {

WebServer* g_server = nullptr;
UiServer* g_ui = nullptr;

void on_signal(int) {
	if (g_ui) g_ui->stop();
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
	          << "web UI (started in this same process, so one command is enough; --no-ui if the UI runs as its own service)\n"
	          << "  --ui-port N       port of the web UI (default 8080)   --ui-bind ADDR  address of the web UI (default 127.0.0.1)\n"
	          << "  --no-ui           serve only the API\n"
	          << "simulation: the whole system against an emulated network, nothing is sent anywhere\n"
	          << "  --simulate        scans from the UI run on an emulated network (hosts that come and go, made-up web servers); use a store of its own\n"
	          << "  --sim-networks L  what the emulated network covers (default 10.20.0.0/20,10.30.0.0/20,172.16.8.0/20)   --sim-seed N  (default 42)\n"
	          << "login (on by default: the first visit asks for the setup token printed here and creates the administrator)\n"
	          << "  --accounts DIR    where accounts are kept without a database (default: DIR/accounts inside --store)\n"
	          << "  --no-auth         NO LOGIN: anyone who can reach the server can read everything (local use only)\n"
	          << "  --port N          port to listen on (default 8081)\n"
	          << "  --bind ADDR       address to listen on (default 127.0.0.1)\n"
	          << "  --allow-host H    accept requests addressed to this host name too (repeatable)\n"
	          << "scans from the web UI: off until an administrator turns them on in the UI (Admin > Scanning); that is saved in a file\n"
	          << "  --scan-ceiling LIST     the most an administrator may ever allow: the scan scope can not go beyond these addresses\n"
	          << "  --scan-config FILE      where the scan settings are kept (default: scan-config.json in --store, or in --accounts with --db)\n"
	          << "  --scan-nmap PATH   --scan-signatures PATH (repeatable)\n"
	          << "  First-run defaults (used only until the settings file exists; afterwards the UI is in charge):\n"
	          << "  --enable-scans   --scan-scope LIST   --scan-ports LIST   --scan-max-workers N   --scan-max-rate PPS\n"
	          << "  --scan-allow-privileged   --scan-no-web   --scan-allow-reserved\n"
	          << "  Without login (--no-auth) the settings can not be changed from the UI, and starting a scan needs the control token ($PROCULUS_CONTROL_TOKEN, or a random one printed at startup).\n"
	          << "Accounts: with --db in Postgres, otherwise in files; create more with `gateway user add`.\n";
}

} // namespace

int serve_command(int argc, char** argv) {
	enum { OPT_STORE = 256, OPT_PORT, OPT_BIND, OPT_ALLOW_HOST, OPT_DB, OPT_DB_MIGRATIONS, OPT_AUTH, OPT_NO_AUTH, OPT_ACCOUNTS, OPT_ENABLE_SCANS, OPT_SCAN_SCOPE, OPT_SCAN_PORTS, OPT_SCAN_WORKERS, OPT_SCAN_RATE, OPT_SCAN_PRIVILEGED, OPT_SCAN_NO_WEB,
		OPT_SCAN_ALLOW_RESERVED, OPT_UI_PORT, OPT_UI_BIND, OPT_NO_UI, OPT_SIMULATE, OPT_SIM_NETWORKS, OPT_SIM_SEED, OPT_SCAN_CEILING, OPT_SCAN_CONFIG, OPT_SCAN_NMAP, OPT_SCAN_SIGNATURES, OPT_HELP };
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
		{"simulate", no_argument, nullptr, OPT_SIMULATE},
		{"sim-networks", required_argument, nullptr, OPT_SIM_NETWORKS},
		{"sim-seed", required_argument, nullptr, OPT_SIM_SEED},
		{"ui-port", required_argument, nullptr, OPT_UI_PORT},
		{"ui-bind", required_argument, nullptr, OPT_UI_BIND},
		{"no-ui", no_argument, nullptr, OPT_NO_UI},
		{"scan-ceiling", required_argument, nullptr, OPT_SCAN_CEILING},
		{"scan-config", required_argument, nullptr, OPT_SCAN_CONFIG},
		{"scan-nmap", required_argument, nullptr, OPT_SCAN_NMAP},
		{"scan-signatures", required_argument, nullptr, OPT_SCAN_SIGNATURES},
		{"help", no_argument, nullptr, OPT_HELP}, {nullptr, 0, nullptr, 0},
	};
	ServerConfig cfg;
	UiConfig ui;
	bool with_ui = true, simulate = false;
	std::string sim_networks = "10.20.0.0/20,10.30.0.0/20,172.16.8.0/20";
	uint64_t sim_seed = 42;
	ScanPolicy policy;
	std::string store_dir, db_url, db_migrations;
	bool use_auth = true; // login is the default; --no-auth turns it off
	std::string accounts_dir, scan_config;
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
			case OPT_SIMULATE: simulate = true; break;
			case OPT_SIM_NETWORKS: sim_networks = optarg; break;
			case OPT_SIM_SEED: sim_seed = std::stoull(optarg); break;
			case OPT_UI_PORT: ui.port = web::parse_port(optarg); break;
			case OPT_UI_BIND: ui.bind = optarg; break;
			case OPT_NO_UI: with_ui = false; break;
			case OPT_SCAN_CEILING: policy.ceiling = optarg; break;
			case OPT_SCAN_CONFIG: scan_config = optarg; break;
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
		std::unique_ptr<EditStore> edit_store; // user edits: next to the runs, or in the database
		if (!db_url.empty()) {
#ifdef PROCULUS_HAVE_PGSTORE
			edit_store = make_pg_edit_store(db_url, db::FieldCipher(db::KeyRing::from_env()));
#endif
		} else {
			edit_store = make_file_edit_store(std::filesystem::path(store_dir) / "edits");
		}
		if (!use_auth) { // without login, changing anything (starting scans, editing) needs the control token
			if (const char* env = std::getenv("PROCULUS_CONTROL_TOKEN"); env && *env) {
				cfg.control_token = env;
				if (cfg.control_token.size() < 16) throw std::invalid_argument("PROCULUS_CONTROL_TOKEN is too short (use at least 16 characters)");
			} else {
				cfg.control_token = TokenGuard::generate();
				std::cerr << "proculus: control token for changes (scans, edits): " << cfg.control_token << "\n";
			}
		}
		RunnerDeps scan_deps;
		std::shared_ptr<Simulation> simulation;
		if (simulate) { // an emulated network: scans are on from the start, and can not leave it
			simulation = std::make_shared<Simulation>(sim_seed, sim_networks, 0.03);
			scan_deps = Simulation::deps(simulation);
			policy.simulated = true;
			policy.enabled = true;
			policy.ceiling = sim_networks;
			if (policy.scope.empty()) policy.scope = sim_networks;
			if (policy.allowed_ports.empty()) policy.allowed_ports = simulation->allowed_ports;
			policy.max_rate = 10000;
			std::cerr << "proculus: SIMULATION: scans run on an emulated network (" << sim_networks << ", " << simulation->net.host_count() << " hosts); nothing is sent over the network\n";
		}
		ScanController scans(policy, &store, scan_deps); // validates the flags (first-run defaults)
		if (scan_config.empty()) {
			if (!store_dir.empty()) scan_config = (std::filesystem::path(store_dir) / "scan-config.json").string();
			else if (!accounts_dir.empty()) scan_config = (std::filesystem::path(accounts_dir) / "scan-config.json").string();
		}
		std::filesystem::path sig_file; // the administrator's own signatures live next to the scan settings
		if (!scan_config.empty()) sig_file = std::filesystem::path(scan_config).parent_path() / "custom-signatures.json";
		SignatureStore signature_store(sig_file);
		if (sig_file.empty()) std::cerr << "proculus: note: no place for custom signatures (give --scan-config FILE); changes made in the UI will be lost on restart\n";
		else scans.set_custom_signatures(sig_file);
		if (scan_config.empty()) {
			std::cerr << "proculus: note: no place for the scan settings (give --scan-config FILE); changes made in the UI will be lost on restart\n";
		} else {
			scans.persist_to(scan_config);
			std::string problem;
			if (scans.load_settings(&problem)) std::cerr << "proculus: scan settings loaded from " << scan_config << (scans.enabled() ? " (scans ON)" : " (scans off)") << "\n";
			else if (!problem.empty()) std::cerr << "proculus: WARNING: ignoring " << scan_config << ": " << problem << "\n";
		}
		WebServer server(store, cfg, &scans, auth_backend.get(), edit_store.get(), &signature_store);
		const int port = server.bind();
		std::unique_ptr<UiServer> ui_server;
		int ui_port = 0;
		if (with_ui) { // the UI talks to this API over loopback, like a separate UI service would
			ui.api = web::Upstream{"127.0.0.1", port};
			ui.allowed_hosts = cfg.allowed_hosts;
			ui_server = std::make_unique<UiServer>(ui);
			ui_port = ui_server->bind(); // fails (and so does the start) when the port is taken
		}
		g_server = &server;
		g_ui = ui_server.get();
		std::signal(SIGINT, on_signal);
		std::signal(SIGTERM, on_signal);
		std::cerr << "proculus: serving " << store_name << " (API on http://" << cfg.bind << ":" << port << "/, " << (auth_backend ? "login required" : "NO LOGIN") << ")\n";
		std::thread ui_thread;
		if (ui_server) {
			ui_thread = std::thread([&] { ui_server->run(); });
			std::cerr << "proculus: open the UI at  http://" << ui.bind << ":" << ui_port << "/\n";
		}
		server.run();
		g_server = nullptr;
		if (ui_server) ui_server->stop();
		if (ui_thread.joinable()) ui_thread.join();
		g_ui = nullptr;
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}

} // namespace proculus
