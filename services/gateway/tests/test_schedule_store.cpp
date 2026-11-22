#undef NDEBUG
#include <sys/stat.h>
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <fstream>

#include "schedule_store.hpp"

using namespace proculus;
namespace fs = std::filesystem;

static fs::path scratch(const char* name) {
	fs::path d = fs::temp_directory_path() / ("proculus_sched_" + std::string(name) + "_" + std::to_string(getpid()));
	fs::remove_all(d);
	return d;
}

static bool api_error(int status, const std::function<void()>& fn, const char* needle = "") {
	try {
		fn();
	} catch (const ApiError& e) {
		return e.status == status && std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

static const TimePoint kNow = parse_time("2026-11-22T10:00:00Z");

static Json nightly() {
	return Json::parse(R"({"name":"nightly","request":{"targets":["10.20.0.0/24"],"ports":"22,80","web":true},"window":"22:00-06:00","days":"mon-fri","utc_offset":"+01:00","interval":"24h"})");
}

static void test_formats() {
	Schedule s;
	parse_window("22:00-06:00", s);
	assert(format_window(s) == "22:00-06:00");
	parse_window("00:00-00:00", s);
	assert(format_window(s) == "00:00-00:00");
	assert(format_days(0x7f) == "all" && format_days(parse_days("mon-fri")) == "mon,tue,wed,thu,fri" && format_days(parse_days("sun,wed")) == "wed,sun");
	assert(format_offset(60) == "+01:00" && format_offset(-330) == "-05:30" && format_offset(0) == "+00:00");
	assert(parse_utc_offset(format_offset(-330)) == -330);
	assert(format_interval(Seconds(86400)) == "1d" && format_interval(Seconds(7200)) == "2h" && format_interval(Seconds(900)) == "15m" && format_interval(Seconds(90)) == "90s");
}

static void test_add_and_validate() {
	ScheduleStore store;
	const ScanSchedule a = store.add(nightly(), kNow);
	assert(a.id == "s1" && a.name == "nightly" && a.enabled && a.created == "2026-11-22T10:00:00Z");
	assert(a.when.window_start_min == 22 * 60 && a.when.window_end_min == 360 && a.when.utc_offset_min == 60 && a.when.interval == Seconds(86400));
	assert(a.when.days == parse_days("mon-fri") && a.request.web && a.request.ports == "22,80");
	const Json j = schedule_json(a);
	assert(j["window"] == "22:00-06:00" && j["days"] == "mon,tue,wed,thu,fri" && j["interval"] == "1d" && j["last"]["started"].is_null() && j["request"]["targets"][0] == "10.20.0.0/24");
	// the JSON shown can be sent back as it is
	Json again = j;
	for (const char* k : {"id", "created", "last"}) again.erase(k);
	assert(store.add(again, kNow).id == "s2");

	// defaults: nightly, every day
	const ScanSchedule d = store.add(Json::parse(R"({"name":"d","request":{"targets":["10.0.0.1"]}})"), kNow);
	assert(format_window(d.when) == "22:00-06:00" && d.when.days == 0x7f && d.when.interval == Seconds(86400));

	for (const char* bad : {R"([])", R"({"request":{"targets":["10.0.0.1"]}})", R"({"name":"x"})", R"({"name":"x","request":{"targets":[]}})", R"({"name":"","request":{"targets":["a"]}})",
	                         R"({"name":"x","request":{"targets":["a"]},"window":"25:00-06:00"})", R"({"name":"x","request":{"targets":["a"]},"window":"nonsense"})",
	                         R"({"name":"x","request":{"targets":["a"]},"days":"funday"})", R"({"name":"x","request":{"targets":["a"]},"interval":"1m"})",
	                         R"({"name":"x","request":{"targets":["a"]},"interval":"400d"})", R"({"name":"x","request":{"targets":["a"]},"interval":5})",
	                         R"({"name":"x","request":{"targets":["a"]},"utc_offset":"+30:00"})", R"({"name":"x","request":{"targets":["a"]},"enabled":"yes"})",
	                         R"({"name":"x","request":{"targets":["a"]},"id":"s9"})", R"({"name":"a\u0007b","request":{"targets":["a"]}})",
	                         R"({"name":"x","request":{"targets":["a"],"workers":0}})"}) {
		assert(api_error(400, [&] { store.add(Json::parse(bad), kNow); }));
	}
	assert(store.list().size() == 3); // nothing invalid was kept

	ScheduleStore many;
	for (size_t i = 0; i < kMaxSchedules; i++) many.add(Json::parse(R"({"name":"n","request":{"targets":["10.0.0.1"]}})"), kNow);
	assert(api_error(409, [&] { many.add(Json::parse(R"({"name":"n","request":{"targets":["10.0.0.1"]}})"), kNow); }, "at most"));
}

static void test_update_remove() {
	ScheduleStore store;
	store.add(nightly(), kNow);
	const ScanSchedule u = store.update("s1", Json::parse(R"({"interval":"12h","enabled":false})"));
	assert(u.when.interval == Seconds(43200) && !u.enabled && u.name == "nightly" && u.request.ports == "22,80"); // the rest stays
	assert(api_error(400, [&] { store.update("s1", Json::parse(R"({"interval":"1s"})")); }));
	assert(store.get("s1")->when.interval == Seconds(43200)); // a refused update changes nothing
	assert(api_error(404, [&] { store.update("s7", Json::object()); }));
	store.remove("s1");
	assert(store.list().empty() && !store.get("s1"));
	assert(api_error(404, [&] { store.remove("s1"); }));
	assert(store.add(nightly(), kNow).id == "s2"); // ids are not reused
}

static void test_persistence() {
	const fs::path dir = scratch("persist");
	const fs::path file = dir / "schedules.json";
	{
		ScheduleStore store(file);
		std::string problem;
		assert(!store.load(&problem) && problem.empty()); // no file yet
		store.add(nightly(), kNow);
		store.add(nightly(), kNow);
		store.remove("s1");
		store.record_started("s2", kNow);
		struct stat st;
		assert(::stat(file.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
		assert(!fs::exists(file.string() + ".tmp"));
	}
	{
		ScheduleStore store(file);
		assert(store.load());
		assert(store.list().size() == 1 && store.list()[0].id == "s2" && store.list()[0].name == "nightly");
		// a scan that was running when the gateway stopped did not finish
		assert(*store.list()[0].last_started == kNow && store.list()[0].last_status == "failed" && store.list()[0].last_message.find("stopped") != std::string::npos);
		store.record_finished("s2", "ok", "finished", 7, "2026-11-22T10:05:00Z");
		assert(store.add(nightly(), kNow).id == "s3"); // the counter continues
	}
	{
		ScheduleStore store(file);
		assert(store.load());
		const ScanSchedule s = *store.get("s2");
		assert(s.last_status == "ok" && s.last_run_id == 7 && s.last_finished == "2026-11-22T10:05:00Z" && store.list().size() == 2);
	}
	// a damaged file is not used, and not replaced until something changes
	{
		std::ofstream(file) << "{ not json";
		ScheduleStore store(file);
		std::string problem;
		assert(!store.load(&problem) && !problem.empty() && store.list().empty());
		std::ofstream(file) << R"({"format":1,"schedules":[{"id":"s1","name":"x","request":{"targets":[]},"window":"22:00-06:00"}]})";
		problem.clear();
		assert(!store.load(&problem) && !problem.empty() && store.list().empty());
	}
	fs::remove_all(dir);
}

int main() {
	test_formats();
	test_add_and_validate();
	test_update_remove();
	test_persistence();
	return 0;
}
