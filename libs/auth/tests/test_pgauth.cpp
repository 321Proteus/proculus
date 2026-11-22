// Integration test against a live Postgres (PROCULUS_TEST_DB_URL); runs in a throw-away schema.
#undef NDEBUG
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iostream>

#include "backend_suite.hpp"
#include "proculus/auth/pgauth.hpp"
#include "proculus/db/connection.hpp"
#include "proculus/db/migrate.hpp"

using namespace proculus;
using namespace proculus::auth;

int main() {
	const char* env = std::getenv("PROCULUS_TEST_DB_URL");
	if (!env || !*env) {
		std::cerr << "PROCULUS_TEST_DB_URL is not set: skipping the auth tests\n";
		return 77;
	}
	test_rules();
	const std::string url = env;
	std::vector<std::string> schemas;
	auto fresh = [&](const std::string& tag) {
		const std::string schema = "pgauth_" + tag + "_" + std::to_string(getpid());
		schemas.push_back(schema);
		db::Connection admin(url);
		admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
		admin.exec("CREATE SCHEMA " + schema);
		const std::string scoped = url + (url.find('?') == std::string::npos ? "?" : "&") + "options=-csearch_path%3D" + schema;
		return open_pg_auth(scoped, PROCULUS_MIGRATIONS_DIR);
	};
	auto cleanup = [&] {
		db::Connection admin(url);
		for (const auto& s : schemas) admin.exec("DROP SCHEMA IF EXISTS " + s + " CASCADE");
	};
	try {
		run_backend_suite(*fresh("main"));
		run_setup_suite(*fresh("setup"));
		run_setup_race(*fresh("race"));
	} catch (...) {
		cleanup();
		throw;
	}
	cleanup();
	return 0;
}
