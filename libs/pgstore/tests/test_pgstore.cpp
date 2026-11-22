// Integration test against a live Postgres. Set PROCULUS_TEST_DB_URL, e.g.
//   postgresql://proculus@127.0.0.1:5432/proculus_test
// Everything runs in a throw-away schema that is dropped at the end.
#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <set>
#include <thread>

#include "proculus/db/connection.hpp"
#include "proculus/db/migrate.hpp"
#include "proculus/pgstore/pgstore.hpp"

using namespace proculus;
namespace fs = std::filesystem;

static std::string g_url, g_scoped, g_schema;

static const char* kKey = "1:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char* kOtherKey = "1:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

static db::FieldCipher cipher(const char* key = kKey) { return db::FieldCipher(db::KeyRing::from_text(key)); }

static WebRecord sample_web() {
	WebRecord w;
	w.url = "https://10.20.0.12/";
	w.status = 200;
	w.title = "Welcome \xc5\xbc to SecretPortal";
	w.server = "nginx/1.24.0";
	w.content_type = "text/html";
	w.headers = {{"Server", "nginx/1.24.0"}, {"Set-Cookie", "sid=<redacted>; HttpOnly"}};
	w.cookies = {{"sid", false, true, "Lax"}};
	w.redirects = {"/login"};
	TlsRecord t;
	t.version = "TLSv1.3";
	t.cipher = "TLS_AES_256_GCM_SHA384";
	t.subject = "CN=secret-host.internal";
	t.issuer = "CN=secret-host.internal";
	t.not_after = "2027-01-01T00:00:00Z";
	t.sha256 = "ab";
	t.key_type = "RSA";
	t.key_bits = 2048;
	t.self_signed = true;
	t.hostname_match = false;
	t.san = {"secret-host.internal"};
	w.tls = t;
	w.favicon_hash = -1234567;
	DetectionRecord d;
	d.id = "nginx";
	d.name = "nginx";
	d.category = "server";
	d.confidence = 0.95;
	d.interest = 2;
	d.version = "1.24.0";
	d.builtin = true;
	d.tags = {"web"};
	d.evidence = {"+0.95 header:server regex"};
	w.detections = {d};
	return w;
}

static RunRecord sample() {
	RunRecord r;
	r.source = "nmap+web";
	r.started = "2026-11-21T22:00:00Z";
	r.finished = "2026-11-21T22:01:30Z";
	r.addresses_scanned = 12288 + 320;
	r.chunks = 18;
	r.pauses = 1;
	r.cancelled_chunks = 2;
	HostRecord h;
	h.ip = "10.20.0.12";
	h.hostname = "web-5.example.org";
	ServiceRecord s;
	s.port = 80;
	s.name = "http";
	s.product = "nginx";
	s.version = "1.24.0";
	s.extrainfo = "(Ubuntu)";
	s.confidence = 10;
	h.services.push_back(s);
	s.port = 443;
	s.name = "https";
	s.web = sample_web();
	h.services.push_back(s);
	r.hosts.push_back(h);
	HostRecord bare;
	bare.ip = "10.20.0.13"; // answered, exposes nothing
	r.hosts.push_back(bare);
	HostRecord later;
	later.ip = "10.20.0.100"; // 100 sorts after 13 by address, before it as text
	ServiceRecord db;
	db.port = 5432;
	db.name = "postgresql";
	db.product = "PostgreSQL DB";
	later.services.push_back(db);
	r.hosts.push_back(later);
	return r;
}

template <class F>
static bool throws_format(F f) {
	try {
		f();
	} catch (const FormatError&) {
		return true;
	}
	return false;
}

static void test_round_trip(PgResultStore& store) {
	assert(store.list().empty());
	assert(!store.load(1));

	RunRecord run = sample();
	const int64_t id = store.save(run);
	assert(id >= 1);
	const RunRecord back = *store.load(id);
	run.id = id;
	assert(dump_json(run_to_json(back), 2) == dump_json(run_to_json(run), 2)); // everything survives, web data included

	const auto list = store.list();
	assert(list.size() == 1 && list[0].id == id && list[0].source == "nmap+web" && list[0].started == "2026-11-21T22:00:00Z" && list[0].finished == "2026-11-21T22:01:30Z");
	assert(list[0].hosts == 3 && list[0].services == 3);

	// the same run through the file store reads back identically
	const fs::path dir = fs::temp_directory_path() / ("pgstore_files_" + std::to_string(getpid()));
	fs::remove_all(dir);
	FileResultStore files(dir);
	files.save(run);
	RunRecord from_file = *files.load(1);
	from_file.id = id;
	assert(dump_json(run_to_json(from_file)) == dump_json(run_to_json(back)));
	fs::remove_all(dir);

	// ids grow, runs are listed oldest first
	const int64_t second = store.save(sample());
	assert(second > id && store.list().size() == 2 && store.list()[1].id == second);
	assert(!store.load(second + 100));

	// unset times stay unset; text from the network cannot break storing
	RunRecord odd;
	odd.source = "import";
	HostRecord h;
	h.ip = "192.168.1.1";
	h.hostname = std::string("router\0x", 8);
	ServiceRecord s;
	s.port = 8080;
	s.extrainfo = "bad \xff\xfe bytes, a NUL \0 and fine \xc5\xbc";
	s.extrainfo.push_back('\0');
	s.web = WebRecord{};
	s.web->title = "title with \xff invalid utf-8";
	h.services.push_back(s);
	odd.hosts.push_back(h);
	const RunRecord odd_back = *store.load(store.save(odd));
	assert(odd_back.started.empty() && odd_back.finished.empty());
	assert(odd_back.hosts[0].hostname == "routerx");
	assert(odd_back.hosts[0].services[0].extrainfo.find('\0') == std::string::npos && odd_back.hosts[0].services[0].extrainfo.find("\xEF\xBF\xBD") != std::string::npos);
	assert(odd_back.hosts[0].services[0].web && odd_back.hosts[0].services[0].web->title.find("\xEF\xBF\xBD") != std::string::npos);
}

static void test_encryption(PgResultStore& store) {
	const int64_t id = store.save(sample());
	db::Connection c(g_scoped);

	// what is sensitive is sealed: no plaintext anywhere in the stored bytes
	for (const char* col : {"title_enc", "headers_enc", "cookies_enc", "tls_enc", "redirects_enc", "meta_enc", "detections_enc"}) {
		db::Result r = c.exec(std::string("SELECT count(*) FROM http_observations WHERE ") + col + " IS NOT NULL AND (position('SecretPortal'::bytea in " + col + ") > 0 OR position('secret-host'::bytea in " + col +
			") > 0 OR position('nginx'::bytea in " + col + ") > 0 OR position('sid'::bytea in " + col + ") > 0)", {});
		assert(r.integer(0, 0) == 0);
	}
	// addresses, ports and service names stay readable, so runs can be queried
	db::Result clear = c.exec("SELECT count(*) FROM observations WHERE run_id = $1 AND ip = '10.20.0.12'::inet AND product = 'nginx' AND port = 80", {id});
	assert(clear.integer(0, 0) == 1);
	assert(c.exec("SELECT count(*) FROM http_observations WHERE run_id = $1 AND status_code = 200 AND favicon_hash = -1234567", {id}).integer(0, 0) == 1);

	// another key cannot read it
	PgResultStore wrong(g_scoped, cipher(kOtherKey));
	assert(throws_format([&] { wrong.load(id); }));
	// the runs without web data do not need the key at all
	RunRecord plain = sample();
	for (HostRecord& h : plain.hosts)
		for (ServiceRecord& s : h.services) s.web.reset();
	const int64_t plain_id = store.save(plain);
	assert(wrong.load(plain_id)->hosts.size() == 3);

	// a sealed value moved to another column does not open (each is bound to its column)
	c.exec("UPDATE http_observations SET headers_enc = title_enc WHERE run_id = $1", {id});
	assert(throws_format([&] { store.load(id); }));
	// and a modified one does not either
	const int64_t id2 = store.save(sample());
	c.exec("UPDATE http_observations SET cookies_enc = set_byte(cookies_enc, 30, get_byte(cookies_enc, 30) # 1) WHERE run_id = $1", {id2});
	assert(throws_format([&] { store.load(id2); }));
}

static void test_failures_store_nothing(PgResultStore& store) {
	const size_t before = store.list().size();
	RunRecord bad_time = sample();
	bad_time.started = "last tuesday-ish";
	assert(throws_format([&] { store.save(bad_time); }));
	RunRecord bad_ip = sample();
	bad_ip.hosts[1].ip = "10.0.0.999";
	assert(throws_format([&] { store.save(bad_ip); }));
	RunRecord with_mask = sample();
	with_mask.hosts[1].ip = "10.0.0.1/8";
	assert(throws_format([&] { store.save(with_mask); }));
	RunRecord twice = sample();
	twice.hosts.push_back(twice.hosts[0]);
	assert(throws_format([&] { store.save(twice); }));
	RunRecord dup_service = sample();
	dup_service.hosts[0].services.push_back(dup_service.hosts[0].services[0]);
	assert(throws_format([&] { store.save(dup_service); }));
	assert(store.list().size() == before); // a failed save leaves no half-run behind (one transaction)
	db::Connection c(g_scoped);
	assert(c.exec("SELECT count(*) FROM scan_runs WHERE status = 'completed'").integer(0, 0) == static_cast<int64_t>(before));
}

static void test_concurrent_saves(PgResultStore& store) {
	const size_t before = store.list().size();
	std::vector<std::thread> threads;
	std::vector<int64_t> ids(8 * 5);
	for (int t = 0; t < 8; t++)
		threads.emplace_back([&, t] {
			for (int i = 0; i < 5; i++) ids[t * 5 + i] = store.save(sample());
		});
	for (auto& th : threads) th.join();
	assert(std::set<int64_t>(ids.begin(), ids.end()).size() == ids.size());
	assert(store.list().size() == before + ids.size());
	for (int64_t id : ids) assert(store.load(id)->hosts.size() == 3);
}

static void test_key_check() {
	// open_pg_store checks the key against the database: the right key opens, another is refused at start-up
	const std::string schema = g_schema + "_k";
	{
		db::Connection admin(g_url);
		admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
		admin.exec("CREATE SCHEMA " + schema);
	}
	const std::string scoped = g_url + (g_url.find('?') == std::string::npos ? "?" : "&") + "options=-csearch_path%3D" + schema;
	::unsetenv("PROCULUS_KEY_FILE");
	auto opens = [&](const char* key) {
		::setenv("PROCULUS_KEY", key, 1);
		try {
			open_pg_store(scoped, PROCULUS_MIGRATIONS_DIR);
		} catch (const db::CryptoError& e) {
			assert(std::string(e.what()).find("does not match") != std::string::npos);
			return false;
		}
		return true;
	};
	assert(opens(kKey));          // a new database: the first key becomes the database's key
	assert(opens(kKey));          // the same key again
	assert(!opens(kOtherKey));    // another key is refused, with a clear message
	assert(opens(kKey));

	// a database with sealed data but no canary (made before the check) is checked against that data
	{
		db::Connection c(scoped);
		c.exec("DELETE FROM settings WHERE key = 'key_check'");
		PgResultStore store(scoped, cipher(kKey));
		store.save(sample());
	}
	assert(!opens(kOtherKey));
	assert(opens(kKey));
	db::Connection admin(g_url);
	admin.exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
}

int main() {
	const char* env = std::getenv("PROCULUS_TEST_DB_URL");
	if (!env || !*env) {
		std::cerr << "PROCULUS_TEST_DB_URL is not set: skipping the Postgres store tests\n";
		return 77;
	}
	g_url = env;
	g_schema = "pgstore_test_" + std::to_string(getpid());
	{
		db::Connection admin(g_url);
		admin.exec("DROP SCHEMA IF EXISTS " + g_schema + " CASCADE");
		admin.exec("CREATE SCHEMA " + g_schema);
	}
	g_scoped = g_url + (g_url.find('?') == std::string::npos ? "?" : "&") + "options=-csearch_path%3D" + g_schema;
	{
		db::Connection c(g_scoped);
		const auto applied = db::migrate(c, PROCULUS_MIGRATIONS_DIR);
		assert(applied.size() >= 2); // the initial schema and the run records
	}

	try {
		PgResultStore store(g_scoped, cipher());
		test_round_trip(store);
		test_encryption(store);
		test_failures_store_nothing(store);
		test_concurrent_saves(store);
		test_key_check();
	} catch (...) {
		db::Connection admin(g_url);
		admin.exec("DROP SCHEMA IF EXISTS " + g_schema + " CASCADE");
		throw;
	}
	db::Connection admin(g_url);
	admin.exec("DROP SCHEMA IF EXISTS " + g_schema + " CASCADE");
	return 0;
}
