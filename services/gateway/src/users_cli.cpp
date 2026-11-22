#include "users_cli.hpp"

#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include "proculus/auth/fileauth.hpp"
#include "proculus/auth/pgauth.hpp"
#include "proculus/pgstore/pgstore.hpp" // default_migrations_dir

namespace proculus {

namespace {

void usage() {
	std::cerr << "usage: gateway user COMMAND [options]\n"
	          << "  accounts are in Postgres (--db URL or $PROCULUS_DB_URL), or else in files: --accounts DIR, or DIR/accounts for --store DIR ($PROCULUS_STORE_DIR)\n"
	          << "  add USERNAME --role ROLE      create an account; asks for the password (or --password-env VAR)\n"
	          << "  list                          accounts\n"
	          << "  roles                         roles and their permissions\n"
	          << "  passwd USERNAME               set a new password\n"
	          << "  role USERNAME ROLE            change the role\n"
	          << "  disable USERNAME | enable USERNAME\n"
	          << "Passwords have at least 10 characters. There are no default accounts: create the first administrator with\n"
	          << "  gateway user add YOUR.NAME --role admin\n";
}

std::string read_password(const std::string& prompt, const char* env_name) {
	if (env_name) {
		const char* v = std::getenv(env_name);
		if (!v || !*v) throw std::invalid_argument(std::string("$") + env_name + " is not set");
		return v;
	}
	std::string pw;
	if (!isatty(STDIN_FILENO)) { // a script: one line from stdin
		std::getline(std::cin, pw);
		return pw;
	}
	termios old{};
	tcgetattr(STDIN_FILENO, &old);
	termios quiet = old;
	quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
	std::cerr << prompt << std::flush;
	std::getline(std::cin, pw);
	tcsetattr(STDIN_FILENO, TCSANOW, &old);
	std::cerr << "\n";
	return pw;
}

int64_t id_of(web::AuthBackend& b, const std::string& username) {
	for (const auto& u : b.users()) {
		std::string a = u.username, c = username;
		for (char& ch : a) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
		for (char& ch : c) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
		if (a == c) return u.id;
	}
	throw std::invalid_argument("no such user: " + username);
}

} // namespace

int users_command(int argc, char** argv) {
	enum { OPT_DB = 256, OPT_MIGRATIONS, OPT_ROLE, OPT_PASSWORD_ENV, OPT_STORE, OPT_ACCOUNTS, OPT_HELP };
	static const option opts[] = {{"db", required_argument, nullptr, OPT_DB}, {"db-migrations", required_argument, nullptr, OPT_MIGRATIONS}, {"role", required_argument, nullptr, OPT_ROLE},
		{"password-env", required_argument, nullptr, OPT_PASSWORD_ENV}, {"store", required_argument, nullptr, OPT_STORE}, {"accounts", required_argument, nullptr, OPT_ACCOUNTS}, {"help", no_argument, nullptr, OPT_HELP}, {nullptr, 0, nullptr, 0}};
	std::string db_url, migrations, role, store_dir, accounts_dir;
	const char* password_env = nullptr;
	try {
		optind = 1;
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_DB: db_url = optarg; break;
			case OPT_MIGRATIONS: migrations = optarg; break;
			case OPT_ROLE: role = optarg; break;
			case OPT_STORE: store_dir = optarg; break;
			case OPT_ACCOUNTS: accounts_dir = optarg; break;
			case OPT_PASSWORD_ENV: password_env = optarg; break;
			case OPT_HELP: usage(); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		std::vector<std::string> args(argv + optind, argv + argc);
		if (args.empty()) {
			usage();
			return 2;
		}
		if (db_url.empty())
			if (const char* env = std::getenv("PROCULUS_DB_URL")) db_url = env;
		std::unique_ptr<web::AuthBackend> backend;
		if (!db_url.empty()) {
			backend = auth::open_pg_auth(db_url, migrations.empty() ? default_migrations_dir() : std::filesystem::path(migrations));
		} else {
			if (accounts_dir.empty()) {
				if (store_dir.empty())
					if (const char* env = std::getenv("PROCULUS_STORE_DIR")) store_dir = env;
				if (store_dir.empty()) throw std::invalid_argument("no accounts location: give --db URL, --accounts DIR or --store DIR (or set PROCULUS_DB_URL / PROCULUS_STORE_DIR)");
				accounts_dir = (std::filesystem::path(store_dir) / "accounts").string();
			}
			backend = std::make_unique<auth::FileAuthBackend>(accounts_dir);
		}

		const std::string& cmd = args[0];
		auto need = [&](size_t n) {
			if (args.size() != n + 1) throw std::invalid_argument("wrong number of arguments (see --help)");
		};
		if (cmd == "list") {
			for (const auto& u : backend->users()) std::cout << u.username << "  " << u.role << (u.disabled ? "  [disabled]" : "") << "  last login: " << (u.last_login.empty() ? "never" : u.last_login) << "\n";
		} else if (cmd == "roles") {
			for (const auto& r : backend->roles()) {
				std::cout << r.name << (r.builtin ? " (built in)" : "") << ", " << r.users << " user(s): ";
				for (size_t i = 0; i < r.permissions.size(); i++) std::cout << (i ? ", " : "") << r.permissions[i];
				std::cout << "\n";
			}
		} else if (cmd == "add") {
			need(1);
			if (role.empty()) throw std::invalid_argument("--role is required (see `gateway user roles`)");
			if (auto why = auth::check_username(args[1]); !why.empty()) throw std::invalid_argument(why);
			std::string pw = read_password("password: ", password_env);
			if (!password_env && isatty(STDIN_FILENO) && read_password("again: ", nullptr) != pw) throw std::invalid_argument("the passwords differ");
			backend->create_user(args[1], pw, role);
			backend->record(nullptr, "user created", "user:" + args[1], "from the command line, role " + role, "");
			std::cout << "created " << args[1] << " (" << role << ")\n";
		} else if (cmd == "passwd") {
			need(1);
			const int64_t id = id_of(*backend, args[1]);
			std::string pw = read_password("new password: ", password_env);
			if (!password_env && isatty(STDIN_FILENO) && read_password("again: ", nullptr) != pw) throw std::invalid_argument("the passwords differ");
			backend->update_user(id, std::nullopt, std::nullopt, pw);
			backend->record(nullptr, "user updated", "user:" + std::to_string(id), "password, from the command line", "");
			std::cout << "password changed\n";
		} else if (cmd == "role") {
			need(2);
			backend->update_user(id_of(*backend, args[1]), args[2], std::nullopt, std::nullopt);
			backend->record(nullptr, "user updated", "user:" + args[1], "role=" + args[2] + ", from the command line", "");
			std::cout << "done\n";
		} else if (cmd == "disable" || cmd == "enable") {
			need(1);
			backend->update_user(id_of(*backend, args[1]), std::nullopt, cmd == "disable", std::nullopt);
			backend->record(nullptr, "user updated", "user:" + args[1], cmd + "d, from the command line", "");
			std::cout << "done\n";
		} else {
			throw std::invalid_argument("unknown command '" + cmd + "'");
		}
		return 0;
	} catch (const web::AuthError& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}

} // namespace proculus
