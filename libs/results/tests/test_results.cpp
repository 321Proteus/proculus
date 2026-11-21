#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <fstream>
#include <functional>
#include <set>
#include <sstream>
#include <thread>

#include "proculus/results/results.hpp"

using namespace proculus;
namespace fs = std::filesystem;

static fs::path fresh_dir(const char* name) {
	fs::path d = fs::temp_directory_path() / ("proculus_results_" + std::string(name) + "_" + std::to_string(getpid()));
	fs::remove_all(d);
	return d;
}

static RunRecord sample(const char* source = "sim") {
	RunRecord r;
	r.source = source;
	r.started = "2026-11-21T22:00:00Z";
	r.finished = "2026-11-21T22:01:30Z";
	r.addresses_scanned = 12288 + 320;
	r.chunks = 18;
	r.pauses = 1;
	r.cancelled_chunks = 2;
	HostRecord h;
	h.ip = "10.20.0.12";
	h.hostname = "web-5";
	ServiceRecord s;
	s.port = 80;
	s.name = "http";
	s.product = "nginx";
	s.version = "1.24.0";
	s.extrainfo = "(Ubuntu) \"quoted\" \xc5\xbc";
	s.confidence = 10;
	h.services.push_back(s);
	s.port = 443;
	s.name = "https";
	h.services.push_back(s);
	r.hosts.push_back(h);
	HostRecord bare;
	bare.ip = "10.20.0.13"; // answered, exposes nothing
	r.hosts.push_back(bare);
	return r;
}

static void expect_equal(const RunRecord& a, const RunRecord& b) {
	assert(a.id == b.id && a.source == b.source && a.started == b.started && a.finished == b.finished);
	assert(a.addresses_scanned == b.addresses_scanned && a.chunks == b.chunks && a.pauses == b.pauses &&
		a.cancelled_chunks == b.cancelled_chunks);
	assert(a.hosts.size() == b.hosts.size());
	for (size_t i = 0; i < a.hosts.size(); i++) {
		assert(a.hosts[i].ip == b.hosts[i].ip && a.hosts[i].hostname == b.hosts[i].hostname);
		assert(a.hosts[i].services.size() == b.hosts[i].services.size());
		for (size_t k = 0; k < a.hosts[i].services.size(); k++) {
			const ServiceRecord &x = a.hosts[i].services[k], &y = b.hosts[i].services[k];
			assert(x.port == y.port && x.protocol == y.protocol && x.state == y.state && x.name == y.name);
			assert(x.product == y.product && x.version == y.version && x.extrainfo == y.extrainfo && x.confidence == y.confidence);
		}
	}
}

static void test_json_roundtrip() {
	RunRecord r = sample();
	r.id = 7;
	expect_equal(run_from_json(Json::parse(dump_json(run_to_json(r)))), r);
	expect_equal(run_from_json(Json::parse(dump_json(run_to_json(r), 2))), r);

	RunSummary s = summarize(r);
	assert(s.id == 7 && s.hosts == 2 && s.services == 2 && s.source == "sim");

	// fields keep a readable order in the file, not alphabetical
	const std::string text = dump_json(run_to_json(r), 2);
	assert(text.find("\"id\"") < text.find("\"source\"") && text.find("\"source\"") < text.find("\"started\""));
	assert(text.find("\"started\"") < text.find("\"hosts\"") && text.find("\"addresses_scanned\"") < text.find("\"chunks\""));
}

static void test_big_numbers_and_hostile_text() {
	// integers beyond 2^53 survive exactly
	RunRecord r = sample();
	r.id = 1;
	r.addresses_scanned = (uint64_t{1} << 60) + 1;
	assert(run_from_json(Json::parse(dump_json(run_to_json(r)))).addresses_scanned == (uint64_t{1} << 60) + 1);

	// banners from the network may contain invalid UTF-8: saving must not fail
	r.hosts[0].services[0].extrainfo = std::string("bad \xff\xfe bytes \xc3");
	std::string text;
	try {
		text = dump_json(run_to_json(r), 2);
	} catch (...) {
		assert(false);
	}
	RunRecord back = run_from_json(Json::parse(text));
	assert(back.hosts[0].services[0].extrainfo.find("bad ") == 0 && back.hosts[0].services[0].extrainfo.find('\xff') == std::string::npos);

	// control characters and quotes round-trip
	r.hosts[0].hostname = "a\"b\\c\n\t\x01";
	assert(run_from_json(Json::parse(dump_json(run_to_json(r)))).hosts[0].hostname == r.hosts[0].hostname);

	// pathological nesting must not crash the process
	bool rejected = false;
	try {
		Json deep = Json::parse(std::string(200000, '[') + std::string(200000, ']'));
		(void)deep;
	} catch (const Json::exception&) {
		rejected = true;
	} catch (...) {
	}
	(void)rejected; // either a clean error or a clean parse is fine; a crash is not

	// invalid JSON text is an error, not a crash
	for (const char* bad : {"", "{", "{\"a\":}", "[1,]", "nul", "\"\xff\""}) {
		bool threw = false;
		try {
			Json parsed = Json::parse(bad);
			(void)parsed;
		} catch (const Json::exception&) {
			threw = true;
		}
		assert(threw);
	}
}

static void test_rejects_bad_documents() {
	auto bad = [](const std::function<void(Json&)>& damage) {
		RunRecord r = sample();
		r.id = 1;
		Json v = run_to_json(r);
		damage(v);
		try {
			run_from_json(v);
		} catch (const FormatError&) {
			return true;
		}
		return false;
	};
	assert(bad([](Json& v) { v["format"] = 2; }));                 // from the future
	assert(bad([](Json& v) { v["id"] = -1; }));
	assert(bad([](Json& v) { v["id"] = "one"; }));
	assert(bad([](Json& v) { v["id"] = 1.5; }));
	assert(bad([](Json& v) { v["id"] = nullptr; }));
	assert(bad([](Json& v) { v["source"] = 5; }));
	assert(bad([](Json& v) { v["hosts"] = "none"; }));
	assert(bad([](Json& v) { v["chunks"] = -3; }));
	assert(bad([](Json& v) { v.erase("hosts"); }));
	assert(bad([](Json& v) { v.erase("started"); }));
	assert(bad([](Json& v) { v["hosts"] = Json::array({5}); })); // host not an object
	assert(bad([](Json& v) {
		Json h = Json::object();
		h["ip"] = "1.2.3.4"; // no "services"
		v["hosts"] = Json::array({h});
	}));
	assert(bad([](Json& v) {
		Json s = Json::object({{"port", 70000}, {"protocol", "tcp"}, {"state", "open"}, {"confidence", 0}});
		Json h = Json::object({{"ip", "1.2.3.4"}, {"services", Json::array({s})}});
		v["hosts"] = Json::array({h}); // port out of range
	}));
	assert(bad([](Json& v) {
		Json s = Json::object({{"port", 80}, {"protocol", "tcp"}, {"state", "open"}, {"confidence", 11}});
		Json h = Json::object({{"ip", "1.2.3.4"}, {"services", Json::array({s})}});
		v["hosts"] = Json::array({h}); // confidence out of range
	}));
	for (const char* top : {"[]", "5", "\"x\"", "null"}) {
		try {
			run_from_json(Json::parse(top));
			assert(false);
		} catch (const FormatError&) {
		}
	}
	// unknown extra fields are tolerated (forward compatibility)
	RunRecord r = sample();
	Json v = run_to_json(r);
	v["future_field"] = "x";
	run_from_json(v);
}

static void test_store_basics() {
	fs::path dir = fresh_dir("basic");
	FileResultStore store(dir / "nested" / "results"); // created on first save
	assert(store.list().empty() && !store.load(1));

	RunRecord a = sample("sim"), b = sample("nmap");
	b.hosts.pop_back();
	assert(store.save(a) == 1 && store.save(b) == 2);
	assert(fs::exists(dir / "nested" / "results" / "run-000001.json"));

	a.id = 1;
	b.id = 2;
	expect_equal(*store.load(1), a);
	expect_equal(*store.load(2), b);
	assert(!store.load(3) && !store.load(0) && !store.load(-5));

	auto list = store.list();
	assert(list.size() == 2 && list[0].id == 1 && list[1].id == 2 && list[1].source == "nmap");
	assert(list[0].hosts == 2 && list[1].hosts == 1);

	// the id passed in is ignored; ids keep counting after the highest existing one
	RunRecord c = sample();
	c.id = 99;
	assert(store.save(c) == 3);
	fs::remove(store.path_for(2));
	assert(store.save(sample()) == 4); // never reuses or fills gaps below the maximum

	// no leftovers from writing
	for (const auto& e : fs::directory_iterator(dir / "nested" / "results"))
		assert(e.path().filename().string().rfind(".tmp-", 0) != 0);

	// a new store object over the same directory sees everything
	assert(FileResultStore(dir / "nested" / "results").list().size() == 3);
	fs::remove_all(dir);
}

static void test_store_ignores_foreign_files_and_rejects_damage() {
	fs::path dir = fresh_dir("damage");
	FileResultStore store(dir);
	store.save(sample());

	for (const char* name : {"notes.txt", "run-1.json", "run-abc123.json", "run-000009.json.bak", ".tmp-1-9", "RUN-000077.json"})
		std::ofstream(dir / name) << "junk";
	assert(store.list().size() == 1);
	assert(store.save(sample()) == 2); // the junk did not shift the numbering

	// a truncated file is reported, not silently skipped or half-read
	std::ofstream(store.path_for(5)) << "{\"format\":1,\"id\":5,";
	bool threw = false;
	try { store.load(5); } catch (const FormatError& e) { threw = std::string(e.what()).find("run-000005.json") != std::string::npos; }
	assert(threw);
	threw = false;
	try { store.list(); } catch (const FormatError&) { threw = true; }
	assert(threw);
	fs::remove(store.path_for(5));

	// a file renamed to another id is caught
	fs::copy_file(store.path_for(1), store.path_for(8));
	threw = false;
	try { store.load(8); } catch (const FormatError&) { threw = true; }
	assert(threw);
	fs::remove_all(dir);
}

static void test_concurrent_writers() {
	fs::path dir = fresh_dir("race");
	std::vector<std::thread> threads;
	std::vector<int64_t> got(40);
	for (size_t i = 0; i < got.size(); i++) {
		threads.emplace_back([&, i] {
			FileResultStore store(dir); // each writer has its own store object, as separate processes would
			RunRecord r = sample();
			r.chunks = static_cast<int>(i);
			got[i] = store.save(r);
		});
	}
	for (auto& t : threads) t.join();

	std::set<int64_t> unique(got.begin(), got.end());
	assert(unique.size() == got.size()); // no two writers got the same id
	FileResultStore store(dir);
	auto list = store.list();
	assert(list.size() == got.size()); // and no run was lost or overwritten
	std::set<int> chunks;
	for (size_t i = 0; i < got.size(); i++) chunks.insert(store.load(got[i])->chunks);
	assert(chunks.size() == got.size());
	fs::remove_all(dir);
}

static void test_unwritable_directory() {
	FileResultStore store("/proc/definitely/not/writable");
	bool threw = false;
	try { store.save(sample()); } catch (const std::runtime_error&) { threw = true; }
	assert(threw);
}

int main() {
	test_json_roundtrip();
	test_big_numbers_and_hostile_text();
	test_rejects_bad_documents();
	test_store_basics();
	test_store_ignores_foreign_files_and_rejects_damage();
	test_concurrent_writers();
	test_unwritable_directory();
	return 0;
}
