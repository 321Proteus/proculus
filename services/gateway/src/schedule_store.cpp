#include "schedule_store.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

namespace proculus {

namespace {

constexpr long long kMinInterval = 300, kMaxInterval = 366LL * 24 * 3600;

[[noreturn]] void bad(const std::string& why) { throw ApiError(400, why); }

std::string two(int v) { return (v < 10 ? "0" : "") + std::to_string(v); }

std::string text_field(const Json& v, const char* key, size_t max, bool allow_empty) {
	if (!v.is_string()) bad(std::string("\"") + key + "\" must be text");
	std::string s = v.get<std::string>();
	const size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t");
	s = a == std::string::npos ? "" : s.substr(a, b - a + 1);
	if (s.empty() && !allow_empty) bad(std::string("\"") + key + "\" must not be empty");
	if (s.size() > max) bad(std::string("\"") + key + "\" is too long");
	for (unsigned char c : s)
		if (c < 0x20 || c == 0x7f) bad(std::string("\"") + key + "\" has control characters");
	return s;
}

// Applies the keys of `body` to `s` (nothing else is validated here but the format).
void apply_body(ScanSchedule& s, const Json& body) {
	if (!body.is_object()) bad("the schedule must be a JSON object");
	static const std::set<std::string> known = {"name", "request", "window", "days", "utc_offset", "interval", "enabled"};
	for (auto it = body.begin(); it != body.end(); ++it)
		if (!known.count(it.key())) bad("unknown setting \"" + it.key().substr(0, 40) + "\"");
	try {
		if (auto it = body.find("name"); it != body.end()) s.name = text_field(*it, "name", 80, false);
		if (auto it = body.find("request"); it != body.end()) s.request = parse_scan_request(*it);
		if (auto it = body.find("window"); it != body.end()) parse_window(text_field(*it, "window", 20, false), s.when);
		if (auto it = body.find("days"); it != body.end()) s.when.days = parse_days(text_field(*it, "days", 40, false));
		if (auto it = body.find("utc_offset"); it != body.end()) s.when.utc_offset_min = parse_utc_offset(text_field(*it, "utc_offset", 10, false));
		if (auto it = body.find("interval"); it != body.end()) {
			s.when.interval = parse_duration(text_field(*it, "interval", 10, false));
			if (s.when.interval.count() < kMinInterval || s.when.interval.count() > kMaxInterval) bad("\"interval\" must be between 5 minutes and 366 days");
		}
		if (auto it = body.find("enabled"); it != body.end()) {
			if (!it->is_boolean()) bad("\"enabled\" must be true or false");
			s.enabled = it->get<bool>();
		}
		validate(s.when);
	} catch (const std::invalid_argument& e) {
		bad(e.what());
	}
	if (s.request.targets.empty()) bad("the schedule needs a request with at least one target");
}

} // namespace

std::string format_window(const Schedule& s) {
	return two(s.window_start_min / 60) + ":" + two(s.window_start_min % 60) + "-" + two(s.window_end_min / 60) + ":" + two(s.window_end_min % 60);
}

std::string format_days(uint8_t mask) {
	if ((mask & 0x7f) == 0x7f) return "all";
	static const char* names[] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};
	std::string out;
	for (int i = 0; i < 7; i++)
		if (mask & (1u << i)) out += (out.empty() ? "" : ",") + std::string(names[i]);
	return out;
}

std::string format_offset(int minutes) {
	const int a = minutes < 0 ? -minutes : minutes;
	return std::string(minutes < 0 ? "-" : "+") + two(a / 60) + ":" + two(a % 60);
}

std::string format_interval(Seconds s) {
	const long long n = s.count();
	if (n % 86400 == 0) return std::to_string(n / 86400) + "d";
	if (n % 3600 == 0) return std::to_string(n / 3600) + "h";
	if (n % 60 == 0) return std::to_string(n / 60) + "m";
	return std::to_string(n) + "s";
}

Json schedule_json(const ScanSchedule& s) {
	Json last = {{"status", s.last_status}, {"message", s.last_message}, {"run_id", s.last_run_id}, {"finished", s.last_finished}};
	last["started"] = s.last_started ? Json(format_time(*s.last_started)) : Json(nullptr);
	return {{"id", s.id}, {"name", s.name}, {"enabled", s.enabled}, {"request", scan_request_json(s.request)}, {"window", format_window(s.when)}, {"days", format_days(s.when.days)},
		{"utc_offset", format_offset(s.when.utc_offset_min)}, {"interval", format_interval(s.when.interval)}, {"created", s.created}, {"last", last}};
}

ScheduleStore::ScheduleStore(std::filesystem::path file) : file_(std::move(file)) {}

bool ScheduleStore::load(std::string* problem) {
	std::lock_guard<std::mutex> l(m_);
	std::error_code ec;
	if (file_.empty() || !std::filesystem::exists(file_, ec)) return false;
	try {
		std::ifstream in(file_, std::ios::binary);
		std::stringstream text;
		text << in.rdbuf();
		const Json doc = Json::parse(text.str());
		if (!doc.is_object() || !doc.contains("schedules") || !doc["schedules"].is_array()) throw std::runtime_error("not a schedules file");
		std::vector<ScanSchedule> items;
		std::set<std::string> ids;
		int next = 1;
		for (const Json& j : doc["schedules"]) {
			ScanSchedule s;
			s.id = j.at("id").get<std::string>();
			if (s.id.size() < 2 || s.id[0] != 's' || s.id.find_first_not_of("0123456789", 1) != std::string::npos || !ids.insert(s.id).second) throw std::runtime_error("bad schedule id");
			Json body = j;
			for (const char* k : {"id", "created", "last"}) body.erase(k);
			apply_body(s, body);
			s.created = j.value("created", "");
			if (j.contains("last") && j["last"].is_object()) {
				const Json& last = j["last"];
				if (last.contains("started") && last["started"].is_string()) s.last_started = parse_time(last["started"].get<std::string>());
				s.last_finished = last.value("finished", "");
				s.last_status = last.value("status", "");
				s.last_message = last.value("message", "");
				s.last_run_id = last.value("run_id", static_cast<int64_t>(0));
			}
			if (s.last_status == "running") { // the gateway stopped in the middle of that scan: nothing of it was saved
				s.last_status = "failed";
				s.last_message = "the gateway stopped during this scan; nothing was saved";
			}
			next = std::max(next, std::stoi(s.id.substr(1)) + 1);
			items.push_back(std::move(s));
		}
		if (items.size() > kMaxSchedules) throw std::runtime_error("too many schedules");
		items_ = std::move(items);
		next_ = next;
		return true;
	} catch (const std::exception& e) {
		if (problem) *problem = e.what();
		return false;
	}
}

void ScheduleStore::save_locked() const {
	if (file_.empty()) return;
	try {
		std::filesystem::create_directories(file_.parent_path());
		Json list = Json::array();
		for (const ScanSchedule& s : items_) list.push_back(schedule_json(s));
		const std::filesystem::path tmp = file_.string() + ".tmp";
		{
			std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
			if (!out) throw std::runtime_error("cannot write " + tmp.string());
			::chmod(tmp.c_str(), 0600);
			out << Json{{"format", 1}, {"schedules", list}}.dump(2) << "\n";
			out.flush();
			if (!out) throw std::runtime_error("cannot write " + tmp.string());
		}
		std::filesystem::rename(tmp, file_);
	} catch (const std::exception& e) {
		throw ApiError(500, std::string("the schedules could not be saved: ") + e.what());
	}
}

std::vector<ScanSchedule> ScheduleStore::list() const {
	std::lock_guard<std::mutex> l(m_);
	return items_;
}

std::optional<ScanSchedule> ScheduleStore::get(const std::string& id) const {
	std::lock_guard<std::mutex> l(m_);
	for (const ScanSchedule& s : items_)
		if (s.id == id) return s;
	return std::nullopt;
}

ScanSchedule ScheduleStore::add(const Json& body, TimePoint now) {
	ScanSchedule s;
	s.when.window_start_min = 22 * 60; // the defaults of a new schedule: nightly, every day
	s.when.window_end_min = 6 * 60;
	apply_body(s, body);
	if (s.name.empty()) bad("\"name\" is required");
	std::lock_guard<std::mutex> l(m_);
	if (items_.size() >= kMaxSchedules) throw ApiError(409, "at most " + std::to_string(kMaxSchedules) + " schedules are allowed");
	s.id = "s" + std::to_string(next_);
	s.created = format_time(now);
	items_.push_back(s);
	try {
		save_locked();
	} catch (...) {
		items_.pop_back();
		throw;
	}
	next_++;
	return s;
}

ScanSchedule ScheduleStore::update(const std::string& id, const Json& body) {
	std::lock_guard<std::mutex> l(m_);
	auto it = std::find_if(items_.begin(), items_.end(), [&](const ScanSchedule& s) { return s.id == id; });
	if (it == items_.end()) throw ApiError(404, "no such schedule");
	ScanSchedule next = *it;
	apply_body(next, body);
	const ScanSchedule old = *it;
	*it = next;
	try {
		save_locked();
	} catch (...) {
		*it = old;
		throw;
	}
	return next;
}

void ScheduleStore::remove(const std::string& id) {
	std::lock_guard<std::mutex> l(m_);
	auto it = std::find_if(items_.begin(), items_.end(), [&](const ScanSchedule& s) { return s.id == id; });
	if (it == items_.end()) throw ApiError(404, "no such schedule");
	const size_t at = static_cast<size_t>(it - items_.begin());
	const ScanSchedule old = *it;
	items_.erase(it);
	try {
		save_locked();
	} catch (...) {
		items_.insert(items_.begin() + static_cast<std::ptrdiff_t>(at), old);
		throw;
	}
}

void ScheduleStore::record_started(const std::string& id, TimePoint at) {
	std::lock_guard<std::mutex> l(m_);
	for (ScanSchedule& s : items_)
		if (s.id == id) {
			s.last_started = at;
			s.last_status = "running";
			s.last_message.clear();
			s.last_finished.clear();
			s.last_run_id = 0;
			try { save_locked(); } catch (const ApiError&) {}
		}
}

void ScheduleStore::record_finished(const std::string& id, const std::string& status, const std::string& message, int64_t run_id, const std::string& finished) {
	std::lock_guard<std::mutex> l(m_);
	for (ScanSchedule& s : items_)
		if (s.id == id) {
			s.last_status = status;
			s.last_message = message.substr(0, 300);
			s.last_run_id = run_id;
			s.last_finished = finished;
			try { save_locked(); } catch (const ApiError&) {}
		}
}

} // namespace proculus
