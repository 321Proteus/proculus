// Integration test against a live Postgres. Set PROCULUS_TEST_DB_URL, e.g.
//   postgresql://proculus:proculus@localhost:5432/proculus
// Everything runs inside a throw-away schema that is dropped at the end.
#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>

#include "proculus/db/connection.hpp"
#include "proculus/db/crypto.hpp"
#include "proculus/db/migrate.hpp"

using namespace proculus::db;

static std::string g_url;

static std::string schema_name() { return "test_" + std::to_string(getpid()); }

static void use_schema(Connection& c) { c.exec("SET search_path TO " + schema_name()); }

template <class F>
static std::string sqlstate_of(F f) {
	try {
		f();
	} catch (const DbError& e) {
		return e.sqlstate;
	}
	return "";
}

static void test_params_and_results(Connection& c) {
	c.exec("CREATE TABLE t (id serial PRIMARY KEY, name text, n bigint, flag boolean, blob bytea)");
	std::vector<uint8_t> raw = {0x00, 0x01, 0xff, 0x27, 0x5c, 0x00, 0x80};
	c.exec("INSERT INTO t (name, n, flag, blob) VALUES ($1, $2, $3, $4)", {"it's \"quoted\"; DROP TABLE t;--", 42, true, raw});
	c.exec("INSERT INTO t (name, n, flag, blob) VALUES ($1, $2, $3, $4)", {nullptr, int64_t{-1}, false, nullptr});

	Result r = c.exec("SELECT name, n, flag, blob FROM t ORDER BY id");
	assert(r.rows() == 2 && r.cols() == 4);
	assert(r.str(0, 0) == "it's \"quoted\"; DROP TABLE t;--");   // injection is just data
	assert(r.integer(0, 1) == 42 && r.str(0, 2) == "t");
	assert(r.bytes(0, 3) == raw);                                 // NUL and 0xff survive
	assert(r.is_null(1, 0) && r.is_null(1, 3) && r.bytes(1, 3).empty());
	assert(r.integer(1, 1) == -1);
	assert(sqlstate_of([&] { r.integer(1, 0); }).empty());        // NULL -> DbError, no sqlstate

	assert(c.exec("UPDATE t SET n = n + 1").affected() == 2);
	assert(c.exec("DELETE FROM t WHERE n = $1", {43}).affected() == 1);

	assert(sqlstate_of([&] { c.exec("SELECT * FROM missing_table"); }) == "42P01");
	assert(sqlstate_of([&] { c.exec("INSERT INTO t (id) VALUES (1), (1)"); }) == "23505");
	assert(c.exec("SELECT 1").rows() == 1);                       // connection still usable
}

static void test_transactions(Connection& c) {
	c.exec("CREATE TABLE tx (v int)");
	{
		Transaction t(c);
		c.exec("INSERT INTO tx VALUES (1)");
	} // rolled back
	assert(c.exec("SELECT count(*) FROM tx").integer(0, 0) == 0);
	{
		Transaction t(c);
		c.exec("INSERT INTO tx VALUES (2)");
		t.commit();
	}
	assert(c.exec("SELECT count(*) FROM tx").integer(0, 0) == 1);
	try {
		Transaction t(c);
		c.exec("INSERT INTO tx VALUES (3)");
		c.exec("SELECT 1/0"); // fails mid-transaction
		t.commit();
	} catch (const DbError&) {
	}
	assert(c.exec("SELECT count(*) FROM tx").integer(0, 0) == 1);
}

static void test_migrations(Connection& c) {
	auto applied = migrate(c, PROCULUS_MIGRATIONS_DIR);
	assert(!applied.empty() && applied[0] == "0001_init");
	assert(migrate(c, PROCULUS_MIGRATIONS_DIR).empty()); // idempotent

	// the schema exists, and the four builtin roles are seeded
	for (const char* table : {"roles", "users", "targets", "scan_runs", "scan_chunks", "observations",
		     "http_observations", "assets", "services", "http_endpoints", "signatures", "detections",
		     "overrides", "audit_log", "settings", "schedules", "scan_profiles"}) {
		assert(c.exec("SELECT to_regclass($1) IS NOT NULL", {std::string(schema_name() + "." + table)}).str(0, 0) == "t");
	}
	Result roles = c.exec("SELECT name FROM roles ORDER BY name");
	assert(roles.rows() == 4 && roles.str(0, 0) == "admin" && roles.str(3, 0) == "viewer");

	// editing an applied migration is detected
	namespace fs = std::filesystem;
	fs::path dir = fs::temp_directory_path() / ("proculus_mig_" + std::to_string(getpid()));
	fs::create_directories(dir);
	fs::copy_file(fs::path(PROCULUS_MIGRATIONS_DIR) / "0001_init.sql", dir / "0001_init.sql");
	{
		std::ofstream f(dir / "0001_init.sql", std::ios::app);
		f << "\n-- edited later\n";
	}
	bool detected = false;
	try {
		migrate(c, dir);
	} catch (const DbError& e) {
		detected = std::string(e.what()).find("modified") != std::string::npos;
	}
	assert(detected);

	// a failing migration rolls back completely and can be retried after a fix
	fs::remove(dir / "0001_init.sql");
	{
		std::ofstream f(dir / "0002_bad.sql");
		f << "CREATE TABLE half_done (x int);\nSELECT 1/0;\n";
	}
	assert(!sqlstate_of([&] { migrate(c, dir); }).empty());
	assert(c.exec("SELECT to_regclass($1) IS NULL", {std::string(schema_name() + ".half_done")}).str(0, 0) == "t");
	assert(c.exec("SELECT count(*) FROM schema_migrations WHERE version = '0002_bad'").integer(0, 0) == 0);
	fs::remove_all(dir);
}

static void test_encrypted_columns(Connection& c) {
	FieldCipher cipher(KeyRing::from_text(Key::generate().to_hex()));

	c.exec("INSERT INTO assets (ip) VALUES ('10.1.2.3')");
	int64_t asset = c.exec("SELECT id FROM assets WHERE ip = '10.1.2.3'").integer(0, 0);

	std::string cookies = "sid=abc123; Secure; HttpOnly";
	c.exec("INSERT INTO http_endpoints (asset_id, port, scheme, cookies_enc) VALUES ($1, 443, 'https', $2)",
		{asset, cipher.seal(cookies, "http_endpoints.cookies")});

	Result r = c.exec("SELECT cookies_enc FROM http_endpoints WHERE asset_id = $1", {asset});
	auto blob = r.bytes(0, 0);
	assert(cipher.open(blob, "http_endpoints.cookies") == cookies);
	// plaintext never reaches the database
	assert(c.exec("SELECT count(*) FROM http_endpoints WHERE position(convert_to($1, 'UTF8') in cookies_enc) > 0",
		      {cookies}).integer(0, 0) == 0);

	// overrides are keyed per field and survive being rewritten
	auto set = [&](const std::string& v) {
		c.exec("INSERT INTO overrides (entity_type, entity_id, field, value_enc) VALUES ('asset', $1, 'owner', $2) "
		       "ON CONFLICT (entity_type, entity_id, field) DO UPDATE SET value_enc = EXCLUDED.value_enc",
			{asset, cipher.seal(v, "overrides.value")});
	};
	set("alice");
	set("bob");
	Result o = c.exec("SELECT value_enc FROM overrides WHERE entity_id = $1", {asset});
	assert(o.rows() == 1 && cipher.open(o.bytes(0, 0), "overrides.value") == "bob");

	// a blob moved to another column is rejected
	bool rejected = false;
	try {
		cipher.open(o.bytes(0, 0), "http_endpoints.cookies");
	} catch (const CryptoError&) {
		rejected = true;
	}
	assert(rejected);
}

static void test_work_queue(Connection& a) {
	Connection b(g_url);
	use_schema(b);

	a.exec("INSERT INTO scan_runs (status) VALUES ('running')");
	int64_t run = a.exec("SELECT max(id) FROM scan_runs").integer(0, 0);
	for (int i = 0; i < 3; i++)
		a.exec("INSERT INTO scan_chunks (run_id, stage, idx, targets, address_count) VALUES ($1, 'discovery', $2, '10.0.0.0/24', 256)",
			{run, i});

	const char* claim = "SELECT id FROM scan_chunks WHERE run_id = $1 AND status = 'pending' "
			    "ORDER BY idx LIMIT 1 FOR UPDATE SKIP LOCKED";
	Transaction ta(a);
	Transaction tb(b);
	Result ra = a.exec(claim, {run});
	Result rb = b.exec(claim, {run});
	assert(ra.rows() == 1 && rb.rows() == 1);
	assert(ra.integer(0, 0) != rb.integer(0, 0)); // two workers never get the same chunk
	a.exec("UPDATE scan_chunks SET status = 'running', claimed_by = 'a' WHERE id = $1", {ra.integer(0, 0)});
	b.exec("UPDATE scan_chunks SET status = 'running', claimed_by = 'b' WHERE id = $1", {rb.integer(0, 0)});
	ta.commit();
	tb.commit();
	assert(a.exec("SELECT count(*) FROM scan_chunks WHERE status = 'pending'").integer(0, 0) == 1);
}

static void test_constraints(Connection& c) {
	assert(sqlstate_of([&] { c.exec("INSERT INTO observations (run_id, ip, host_up, port) VALUES (1, '10.0.0.1', true, 70000)"); }) == "23514");
	assert(sqlstate_of([&] { c.exec("INSERT INTO targets (spec, kind) VALUES ('x', 'nonsense')"); }) == "23514");
	assert(sqlstate_of([&] { c.exec("INSERT INTO users (username, password_hash, role_id) VALUES ('A', 'h', 1), ('a', 'h', 1)"); }) == "23505");
	assert(sqlstate_of([&] { c.exec("INSERT INTO assets (ip) VALUES ('10.1.2.3')"); }) == "23505"); // duplicate ip
}

int main() {
	const char* url = std::getenv("PROCULUS_TEST_DB_URL");
	if (!url || !*url) {
		std::cout << "PROCULUS_TEST_DB_URL not set: skipping database tests\n";
		return 77;
	}
	g_url = url;

	Connection c(g_url);
	c.exec("CREATE SCHEMA " + schema_name());
	int rc = 0;
	try {
		use_schema(c);
		test_params_and_results(c);
		test_transactions(c);
		test_migrations(c);
		test_encrypted_columns(c);
		test_work_queue(c);
		test_constraints(c);
	} catch (const std::exception& e) {
		std::cerr << "FAILED: " << e.what() << "\n";
		rc = 1;
	}
	c.exec("DROP SCHEMA " + schema_name() + " CASCADE");
	return rc;
}
