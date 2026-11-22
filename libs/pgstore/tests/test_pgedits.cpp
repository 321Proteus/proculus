// Integration test against a live Postgres (PROCULUS_TEST_DB_URL); runs in a throw-away schema.
#undef NDEBUG
#include <unistd.h>

#include <cstdlib>
#include <iostream>

#include "../../edits/tests/edit_store_suite.hpp"
#include "proculus/db/connection.hpp"
#include "proculus/db/migrate.hpp"
#include "proculus/pgstore/pgedits.hpp"

static const char* kKey = "1:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char* kOtherKey = "1:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

int main() {
	const char* env = std::getenv("PROCULUS_TEST_DB_URL");
	if (!env || !*env) {
		std::cerr << "PROCULUS_TEST_DB_URL is not set: skipping the Postgres edit store tests\n";
		return 77;
	}
	const std::string url = env, schema = "pgedits_test_" + std::to_string(getpid());
	{
		db::Connection admin(url);
		admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
		admin.exec("CREATE SCHEMA " + schema);
	}
	const std::string scoped = url + (url.find('?') == std::string::npos ? "?" : "&") + "options=-csearch_path%3D" + schema;
	auto cleanup = [&] {
		db::Connection admin(url);
		admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
	};
	try {
		{
			db::Connection c(scoped);
			db::migrate(c, PROCULUS_MIGRATIONS_DIR);
		}
		auto store = make_pg_edit_store(scoped, db::FieldCipher(db::KeyRing::from_text(kKey)));
		run_edit_store_suite(*store);

		// what was edited is sealed; the key and who/when are readable
		store->apply(EditKey{"10.9.9.9", 0, ""}, json{{"note", "TOP-SECRET-NOTE"}, {"hostname", "secret-db.internal"}, {"tags", {"finance"}}}, "ann");
		db::Connection c(scoped);
		assert(c.exec("SELECT count(*) FROM entity_edits WHERE position('TOP-SECRET'::bytea in data_enc) > 0 OR position('secret-db'::bytea in data_enc) > 0 OR position('finance'::bytea in data_enc) > 0").integer(0, 0) == 0);
		assert(c.exec("SELECT count(*) FROM entity_edits WHERE ip = '10.9.9.9'::inet AND edited_by = 'ann'").integer(0, 0) == 1);

		// another key cannot read it, and a modified value is refused
		auto wrong = make_pg_edit_store(scoped, db::FieldCipher(db::KeyRing::from_text(kOtherKey)));
		bool threw = false;
		try {
			wrong->all();
		} catch (const db::CryptoError&) {
			threw = true;
		}
		assert(threw);
		c.exec("UPDATE entity_edits SET data_enc = set_byte(data_enc, 30, get_byte(data_enc, 30) # 1)");
		threw = false;
		try {
			store->all();
		} catch (const db::CryptoError&) {
			threw = true;
		}
		assert(threw);
	} catch (...) {
		cleanup();
		throw;
	}
	cleanup();
	return 0;
}
