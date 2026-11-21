#include "schedule.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

namespace proculus {

namespace {

constexpr int64_t kDay = 86400;

int64_t floor_div(int64_t a, int64_t b) {
	int64_t q = a / b;
	return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q;
}

// Howard Hinnant's civil-date algorithms (public domain).
int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
	y -= m <= 2;
	const int64_t era = floor_div(y, 400);
	const unsigned yoe = static_cast<unsigned>(y - era * 400);
	const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
	const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void civil_from_days(int64_t z, int64_t& y, unsigned& m, unsigned& d) {
	z += 719468;
	const int64_t era = floor_div(z, 146097);
	const unsigned doe = static_cast<unsigned>(z - era * 146097);
	const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	y = static_cast<int64_t>(yoe) + era * 400;
	const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	const unsigned mp = (5 * doy + 2) / 153;
	d = doy - (153 * mp + 2) / 5 + 1;
	m = mp < 10 ? mp + 3 : mp - 9;
	y += m <= 2;
}

// 0 = Monday ... 6 = Sunday (1970-01-01 was a Thursday).
int weekday(int64_t day_index) { return static_cast<int>(((day_index + 3) % 7 + 7) % 7); }

int64_t to_unix(TimePoint t) { return std::chrono::duration_cast<Seconds>(t.time_since_epoch()).count(); }
TimePoint from_unix(int64_t s) { return TimePoint(Seconds(s)); }

int64_t window_length_seconds(const Schedule& s) {
	int minutes = ((s.window_end_min - s.window_start_min) % 1440 + 1440) % 1440;
	return minutes == 0 ? kDay : minutes * 60;
}

// The window that starts on local day `day`, if that weekday is enabled.
std::optional<Window> window_on_day(const Schedule& s, int64_t day) {
	if (!(s.days & (1u << weekday(day)))) return std::nullopt;
	const int64_t start = day * kDay + s.window_start_min * 60 - s.utc_offset_min * 60;
	return Window{from_unix(start), from_unix(start + window_length_seconds(s))};
}

int64_t local_day(const Schedule& s, TimePoint t) { return floor_div(to_unix(t) + s.utc_offset_min * 60, kDay); }

} // namespace

void validate(const Schedule& s) {
	if (s.window_start_min < 0 || s.window_start_min >= 1440 || s.window_end_min < 0 || s.window_end_min >= 1440)
		throw std::invalid_argument("window times must be within 00:00-23:59");
	if (s.utc_offset_min <= -24 * 60 || s.utc_offset_min >= 24 * 60) throw std::invalid_argument("UTC offset out of range");
	if (s.interval.count() <= 0) throw std::invalid_argument("interval must be positive");
	if (s.min_start_remaining.count() < 0) throw std::invalid_argument("min_start_remaining must not be negative");
	if ((s.days & 0x7f) == 0) throw std::invalid_argument("at least one weekday must be enabled");
}

std::optional<Window> window_containing(const Schedule& s, TimePoint t) {
	if (!s.enabled) return std::nullopt;
	const int64_t today = local_day(s, t);
	// A window is at most 24h long, so only today's and yesterday's can contain t.
	for (int64_t day : {today, today - 1}) {
		if (auto w = window_on_day(s, day); w && w->start <= t && t < w->end) return w;
	}
	return std::nullopt;
}

std::optional<Window> next_window_after(const Schedule& s, TimePoint t) {
	if (!s.enabled || (s.days & 0x7f) == 0) return std::nullopt;
	const int64_t today = local_day(s, t);
	for (int64_t day = today - 1; day <= today + 8; day++) {
		if (auto w = window_on_day(s, day); w && w->start > t) return w;
	}
	return std::nullopt;
}

std::vector<Window> upcoming_windows(const Schedule& s, TimePoint t, size_t n) {
	std::vector<Window> out;
	while (out.size() < n) {
		auto w = next_window_after(s, t);
		if (!w) break;
		out.push_back(*w);
		t = w->start;
	}
	return out;
}

Decision decide(const Schedule& s, const RunState& state, TimePoint now) {
	Decision d;
	if (!s.enabled) return d; // Wait with no wake-up time: the schedule is off

	const auto window = window_containing(s, now);
	const auto next = next_window_after(s, now);

	switch (state.phase) {
	case RunPhase::Running:
		if (window) {
			d.action = Action::Continue;
			d.deadline = window->end;
		} else {
			d.action = Action::Pause;
			if (next) d.at = next->start;
		}
		return d;

	case RunPhase::Paused:
		if (window) {
			d.action = Action::Resume;
			d.deadline = window->end;
		} else if (next) {
			d.at = next->start;
		}
		return d;

	case RunPhase::None:
		break;
	}

	const TimePoint due = state.last_started ? *state.last_started + s.interval : now;
	if (now >= due && window && window->end - now >= s.min_start_remaining) {
		d.action = Action::Start;
		d.deadline = window->end;
		return d;
	}

	// Not startable now: find the earliest moment that is both due and inside a
	// window with enough time left.
	TimePoint from = std::max(now, due);
	for (int guard = 0; guard < 400; guard++) {
		if (auto w = window_containing(s, from); w && w->end - from >= s.min_start_remaining) {
			d.at = from;
			return d;
		}
		auto n = next_window_after(s, from);
		if (!n) return d;
		if (n->end - n->start >= s.min_start_remaining) {
			d.at = n->start;
			return d;
		}
		from = n->start; // window too short to ever start in: try the following one
	}
	return d;
}

bool can_start_chunk(TimePoint now, TimePoint deadline, double estimate_seconds, double safety_factor, Seconds margin) {
	if (!(estimate_seconds >= 0) || !(safety_factor >= 1)) return false;
	const double needed = estimate_seconds * safety_factor + static_cast<double>(margin.count());
	const double left = std::chrono::duration<double>(deadline - now).count();
	return left >= needed;
}

std::vector<RunEvent> simulate_run(const Schedule& s, TimePoint now, Seconds work, size_t max_events) {
	std::vector<RunEvent> ev;
	RunState st;
	Seconds left = work;

	auto push = [&](RunEvent::Type type, TimePoint at) { ev.push_back({type, at}); };

	for (int guard = 0; guard < 100000 && ev.size() < max_events; guard++) {
		Decision d = decide(s, st, now);
		switch (d.action) {
		case Action::Wait:
			if (!d.at || *d.at <= now) return ev; // disabled / no windows: it never starts
			now = *d.at;
			continue;
		case Action::Start:
		case Action::Resume:
		case Action::Continue: {
			if (d.action == Action::Start) {
				push(RunEvent::Type::Started, now);
				st.last_started = now;
			} else if (d.action == Action::Resume) {
				push(RunEvent::Type::Resumed, now);
			}
			st.phase = RunPhase::Running;
			const Seconds room = std::chrono::duration_cast<Seconds>(*d.deadline - now);
			if (left <= room) {
				now += left;
				push(RunEvent::Type::Finished, now);
				return ev;
			}
			left -= room;
			now = *d.deadline;
			continue;
		}
		case Action::Pause:
			push(RunEvent::Type::Paused, now);
			st.phase = RunPhase::Paused;
			continue;
		}
	}
	return ev;
}

// ------------------------------------------------------------------ parsing

namespace {

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
	return s;
}

int parse_hhmm(const std::string& t) {
	const auto colon = t.find(':');
	const std::string hh = colon == std::string::npos ? "" : t.substr(0, colon);
	const std::string mm = colon == std::string::npos ? "" : t.substr(colon + 1);
	auto digits = [](const std::string& x) { return !x.empty() && x.find_first_not_of("0123456789") == std::string::npos; };
	if (!digits(hh) || !digits(mm) || hh.size() > 2 || mm.size() != 2 || std::atoi(hh.c_str()) > 23 || std::atoi(mm.c_str()) > 59)
		throw std::invalid_argument("bad time of day '" + t + "', expected HH:MM");
	return std::atoi(hh.c_str()) * 60 + std::atoi(mm.c_str());
}

int day_index(const std::string& name) {
	static const char* names[] = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"};
	for (int i = 0; i < 7; i++)
		if (name == names[i]) return i;
	throw std::invalid_argument("unknown weekday '" + name + "'");
}

} // namespace

void parse_window(const std::string& text, Schedule& s) {
	auto dash = text.find('-');
	if (dash == std::string::npos) throw std::invalid_argument("window must look like 22:00-06:00");
	s.window_start_min = parse_hhmm(text.substr(0, dash));
	s.window_end_min = parse_hhmm(text.substr(dash + 1));
}

uint8_t parse_days(const std::string& text) {
	const std::string t = lower(text);
	if (t == "all" || t == "daily") return 0x7f;
	uint8_t mask = 0;
	size_t pos = 0;
	while (pos <= t.size()) {
		size_t comma = t.find(',', pos);
		std::string part = t.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
		if (part.empty()) throw std::invalid_argument("empty weekday in '" + text + "'");
		if (auto dash = part.find('-'); dash != std::string::npos) {
			int a = day_index(part.substr(0, dash)), b = day_index(part.substr(dash + 1));
			for (int i = a;; i = (i + 1) % 7) {
				mask |= static_cast<uint8_t>(1u << i);
				if (i == b) break;
			}
		} else {
			mask |= static_cast<uint8_t>(1u << day_index(part));
		}
		if (comma == std::string::npos) break;
		pos = comma + 1;
	}
	return mask;
}

Seconds parse_duration(const std::string& text) {
	if (text.size() < 2) throw std::invalid_argument("bad duration '" + text + "' (use e.g. 90s, 15m, 24h, 2d)");
	const char unit = text.back();
	const std::string num = text.substr(0, text.size() - 1);
	if (num.find_first_not_of("0123456789") != std::string::npos)
		throw std::invalid_argument("bad duration '" + text + "' (use e.g. 90s, 15m, 24h, 2d)");
	const long long n = std::atoll(num.c_str());
	long long mult;
	switch (unit) {
	case 's': mult = 1; break;
	case 'm': mult = 60; break;
	case 'h': mult = 3600; break;
	case 'd': mult = 86400; break;
	default: throw std::invalid_argument("bad duration unit in '" + text + "' (use s, m, h or d)");
	}
	if (n <= 0 || n > 3650LL * 86400 / mult) throw std::invalid_argument("duration out of range: " + text);
	return Seconds(n * mult);
}

int parse_utc_offset(const std::string& text) {
	if (text == "Z" || text == "z") return 0;
	if (text.size() < 3 || (text[0] != '+' && text[0] != '-')) throw std::invalid_argument("bad UTC offset '" + text + "'");
	std::string digits;
	for (size_t i = 1; i < text.size(); i++) {
		if (text[i] == ':') continue;
		if (!std::isdigit(static_cast<unsigned char>(text[i]))) throw std::invalid_argument("bad UTC offset '" + text + "'");
		digits += text[i];
	}
	if (digits.size() != 2 && digits.size() != 4) throw std::invalid_argument("bad UTC offset '" + text + "'");
	const int h = std::atoi(digits.substr(0, 2).c_str());
	const int m = digits.size() == 4 ? std::atoi(digits.substr(2).c_str()) : 0;
	if (h > 23 || m > 59) throw std::invalid_argument("bad UTC offset '" + text + "'");
	const int v = h * 60 + m;
	return text[0] == '-' ? -v : v;
}

TimePoint parse_time(const std::string& text) {
	int y, mo, d, h, mi, sec;
	char z = 0;
	int n = 0;
	if (std::sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d%c%n", &y, &mo, &d, &h, &mi, &sec, &z, &n) != 7 || z != 'Z' ||
		static_cast<size_t>(n) != text.size() || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 59)
		throw std::invalid_argument("bad time '" + text + "', expected 2026-11-21T12:00:00Z");
	const int64_t days = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
	// reject dates like Feb 31 by round-tripping
	int64_t ry;
	unsigned rm, rd;
	civil_from_days(days, ry, rm, rd);
	if (ry != y || static_cast<int>(rm) != mo || static_cast<int>(rd) != d) throw std::invalid_argument("no such date: " + text);
	return from_unix(days * kDay + h * 3600 + mi * 60 + sec);
}

std::string format_time(TimePoint t) {
	const int64_t u = to_unix(t);
	const int64_t day = floor_div(u, kDay);
	const int64_t secs = u - day * kDay;
	int64_t y;
	unsigned m, d;
	civil_from_days(day, y, m, d);
	char buf[40];
	std::snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02lld:%02lld:%02lldZ", static_cast<long long>(y), m, d,
		static_cast<long long>(secs / 3600), static_cast<long long>(secs / 60 % 60), static_cast<long long>(secs % 60));
	return buf;
}

} // namespace proculus
