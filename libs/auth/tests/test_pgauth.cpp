// Integration test against a live Postgres (PROCULUS_TEST_DB_URL); runs in a throw-away schema.
#undef NDEBUG
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iostream>

#include "proculus/auth/pgauth.hpp"
#include "proculus/db/connection.hpp"
#include "proculus/db/migrate.hpp"

using namespace proculus;
using namespace proculus::auth;

template <class F>
static bool refused(int status, F f, const char* needle = "") {
	try {
		f();
	} catch (const web::AuthError& e) {
		return e.status == status && std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

static void test_rules() {
	assert(check_username("ann.k-1_x").empty() && !check_username("ab").empty() && !check_username("a b c").empty() && !check_username(std::string(65, 'a')).empty());
	assert(check_password("ann", "correct horse").empty() && !check_password("ann", "short").empty() && !check_password("annannannann", "AnnAnnAnnAnn").empty());
	assert(!check_password("ann", std::string(201, 'x')).empty());
}

static void test_backend(PgAuthBackend& a) {
	assert(!a.has_users());
	assert(!a.verify("nobody", "whatever password"));

	// the four built-in roles from the spec
	const auto roles = a.roles();
	assert(roles.size() == 4 && roles[0].name == "admin" && roles[0].builtin);
	auto role = [&](const std::string& n) {
		for (const auto& r : roles)
			if (r.name == n) return r;
		assert(false);
		return roles[0];
	};
	assert(role("admin").permissions.size() == 8);
	const auto viewer_role = role("viewer");
	assert(std::find(viewer_role.permissions.begin(), viewer_role.permissions.end(), "scan.run") == viewer_role.permissions.end());
	assert(role("manager").permissions.size() > role("editor").permissions.size() && role("editor").permissions.size() > role("viewer").permissions.size());

	// accounts
	const auto admin = a.create_user("root.admin", "correct horse battery", "admin");
	assert(admin.id > 0 && a.has_users());
	assert(refused(409, [&] { a.create_user("ROOT.ADMIN", "another long password", "viewer"); }, "already exists"));
	assert(refused(400, [&] { a.create_user("x", "another long password", "viewer"); }));
	assert(refused(400, [&] { a.create_user("short.pw", "short", "viewer"); }, "10 characters"));
	assert(refused(400, [&] { a.create_user("no.role", "another long password", "no-such-role"); }, "no such role"));
	const auto viewer = a.create_user("vera.viewer", "viewer password 1", "viewer");

	// login: right password only, case-insensitive name, never the hash
	auto u = a.verify("Root.Admin", "correct horse battery");
	assert(u && u->username == "root.admin" && u->role == "admin" && u->has("users.manage") && u->id == admin.id);
	assert(!a.verify("root.admin", "wrong password!!") && !a.verify("root.admin", "") && !a.verify("", "x") && !a.verify("root.admin' OR '1'='1", "x"));
	auto v = a.verify("vera.viewer", "viewer password 1");
	assert(v && v->has("data.read") && !v->has("scan.run") && !v->has("users.manage"));
	for (const auto& info : a.users()) assert(info.username != "root.admin" || !info.last_login.empty()); // last login is recorded
	assert(a.users().size() == 2);

	// disabling, and changing role and password
	a.update_user(viewer.id, std::nullopt, true, std::nullopt);
	assert(!a.verify("vera.viewer", "viewer password 1")); // right password, disabled account
	a.update_user(viewer.id, "editor", false, "new viewer password");
	assert(!a.verify("vera.viewer", "viewer password 1"));
	auto changed = a.verify("vera.viewer", "new viewer password");
	assert(changed && changed->role == "editor" && changed->has("data.edit"));
	assert(refused(404, [&] { a.update_user(99999, "viewer", std::nullopt, std::nullopt); }));
	assert(refused(400, [&] { a.update_user(viewer.id, "ghost", std::nullopt, std::nullopt); }, "no such role"));
	assert(refused(400, [&] { a.update_user(viewer.id, std::nullopt, std::nullopt, "short"); }, "10 characters"));

	// there is always an administrator
	assert(refused(409, [&] { a.update_user(admin.id, std::nullopt, true, std::nullopt); }, "no administrator"));
	assert(refused(409, [&] { a.update_user(admin.id, "viewer", std::nullopt, std::nullopt); }, "no administrator"));
	assert(a.verify("root.admin", "correct horse battery")); // refused changes were rolled back
	const auto second = a.create_user("second.admin", "second admin password", "admin");
	a.update_user(admin.id, "viewer", std::nullopt, std::nullopt); // fine now
	a.update_user(admin.id, "admin", std::nullopt, std::nullopt);

	// custom roles
	const auto custom = a.create_role("auditor", "Reads and exports", {"data.read", "export", "export"});
	assert(custom.permissions.size() == 2 && !custom.builtin);
	assert(refused(409, [&] { a.create_role("auditor", "", {"data.read"}); }, "already exists"));
	assert(refused(400, [&] { a.create_role("Bad Name", "", {"data.read"}); }));
	assert(refused(400, [&] { a.create_role("empty-role", "", {}); }, "at least one"));
	assert(refused(400, [&] { a.create_role("bogus-role", "", {"data.read", "god.mode"}); }, "unknown permission"));
	a.update_user(viewer.id, "auditor", std::nullopt, std::nullopt);
	assert(a.verify("vera.viewer", "new viewer password")->role == "auditor");
	assert(refused(409, [&] { a.delete_role("auditor"); }, "in use"));
	assert(refused(409, [&] { a.delete_role("admin"); }, "built-in"));
	assert(refused(404, [&] { a.delete_role("ghost"); }));
	a.update_user(viewer.id, "viewer", std::nullopt, std::nullopt);
	a.delete_role("auditor");
	assert(a.roles().size() == 4);
	(void)second;

	// the audit log: written without a user too, newest first, never throws
	a.record(&*u, "login", "user:root.admin", "from the test", "10.1.2.3");
	a.record(nullptr, "login failed", "user:ghost", "x'; DROP TABLE users;--", "");
	a.record(nullptr, "bad ip", "", std::string("weird\0detail", 12), "not-an-ip");
	const auto log = a.audit(10);
	assert(log.size() == 3 && log[0].action == "bad ip" && log[1].detail.find("DROP TABLE users") != std::string::npos && log[2].user == "root.admin" && log[2].source_ip == "10.1.2.3");
	assert(a.audit(1).size() == 1 && a.has_users()); // the table is still there
}

int main() {
	const char* env = std::getenv("PROCULUS_TEST_DB_URL");
	if (!env || !*env) {
		std::cerr << "PROCULUS_TEST_DB_URL is not set: skipping the auth tests\n";
		return 77;
	}
	test_rules();
	const std::string url = env, schema = "pgauth_test_" + std::to_string(getpid());
	{
		db::Connection admin(url);
		admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
		admin.exec("CREATE SCHEMA " + schema);
	}
	const std::string scoped = url + (url.find('?') == std::string::npos ? "?" : "&") + "options=-csearch_path%3D" + schema;
	try {
		auto backend = open_pg_auth(scoped, PROCULUS_MIGRATIONS_DIR);
		test_backend(*backend);
	} catch (...) {
		db::Connection admin(url);
		admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
		throw;
	}
	db::Connection admin(url);
	admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
	return 0;
}
