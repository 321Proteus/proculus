#undef NDEBUG
#include <cassert>
#include <stdexcept>

#include "schedule.hpp"

using namespace proculus;

static TimePoint T(const char* s) { return parse_time(s); }
static std::string F(TimePoint t) { return format_time(t); }

template <class F>
static bool throws(F f) {
	try {
		f();
	} catch (const std::invalid_argument&) {
		return true;
	}
	return false;
}

// Nightly 22:00-06:00 UTC, every day, once a day.
static Schedule nightly() {
	Schedule s;
	parse_window("22:00-06:00", s);
	return s;
}

static void test_time_parsing() {
	assert(F(T("2026-11-21T12:00:00Z")) == "2026-11-21T12:00:00Z");
	assert(F(T("1970-01-01T00:00:00Z")) == "1970-01-01T00:00:00Z");
	assert(F(T("2024-02-29T23:59:59Z")) == "2024-02-29T23:59:59Z"); // leap day
	assert(F(T("1969-12-31T23:59:59Z")) == "1969-12-31T23:59:59Z"); // before the epoch
	assert(T("2026-11-21T00:00:00Z") - T("2026-11-20T00:00:00Z") == Seconds(86400));
	for (const char* bad : {"", "2026-11-21", "2026-11-21 12:00:00Z", "2026-11-21T12:00:00", "2026-13-01T00:00:00Z",
		     "2026-02-30T00:00:00Z", "2025-02-29T00:00:00Z", "2026-11-21T24:00:00Z", "2026-11-21T12:00:00Zjunk"})
		assert(throws([&] { parse_time(bad); }));

	assert(parse_duration("90s") == Seconds(90) && parse_duration("15m") == Seconds(900));
	assert(parse_duration("24h") == Seconds(86400) && parse_duration("2d") == Seconds(172800));
	for (const char* bad : {"", "h", "10", "10x", "0s", "-5m", "1.5h", "abc", "99999d"})
		assert(throws([&] { parse_duration(bad); }));

	assert(parse_utc_offset("Z") == 0 && parse_utc_offset("+01:00") == 60 && parse_utc_offset("-0530") == -330);
	assert(parse_utc_offset("+02") == 120);
	for (const char* bad : {"", "01:00", "+1", "+25:00", "+01:60", "+0a:00", "+01:00:00"})
		assert(throws([&] { parse_utc_offset(bad); }));

	assert(parse_days("mon-fri") == 0x1f && parse_days("all") == 0x7f && parse_days("sat,sun") == 0x60);
	assert(parse_days("MON,wed") == 0x05 && parse_days("fri-mon") == (0x10 | 0x20 | 0x40 | 0x01)); // wraps the week
	for (const char* bad : {"", "funday", "mon,", "mon-", ",mon"}) assert(throws([&] { parse_days(bad); }));

	Schedule s;
	parse_window("08:30-17:05", s);
	assert(s.window_start_min == 510 && s.window_end_min == 1025);
	for (const char* bad : {"", "22:00", "25:00-06:00", "22:00-06:60", "2200-0600", "22:0-06:00", "a:00-06:00"})
		assert(throws([&] { parse_window(bad, s); }));
}

static void test_windows() {
	Schedule s = nightly(); // crosses midnight
	// 2026-11-21 is a Saturday
	auto w = window_containing(s, T("2026-11-21T23:00:00Z"));
	assert(w && F(w->start) == "2026-11-21T22:00:00Z" && F(w->end) == "2026-11-22T06:00:00Z");
	w = window_containing(s, T("2026-11-22T05:59:59Z")); // after midnight, same window
	assert(w && F(w->start) == "2026-11-21T22:00:00Z");
	assert(!window_containing(s, T("2026-11-22T06:00:00Z")));   // end is exclusive
	assert(window_containing(s, T("2026-11-21T22:00:00Z")));    // start is inclusive
	assert(!window_containing(s, T("2026-11-21T12:00:00Z")));

	auto n = next_window_after(s, T("2026-11-21T12:00:00Z"));
	assert(F(n->start) == "2026-11-21T22:00:00Z");
	n = next_window_after(s, T("2026-11-21T22:00:00Z")); // strictly after
	assert(F(n->start) == "2026-11-22T22:00:00Z");

	auto ws = upcoming_windows(s, T("2026-11-21T12:00:00Z"), 3);
	assert(ws.size() == 3 && F(ws[2].start) == "2026-11-23T22:00:00Z");

	// same-day window, start == end means open all day
	Schedule day;
	parse_window("09:00-17:00", day);
	assert(window_containing(day, T("2026-11-21T09:00:00Z")) && !window_containing(day, T("2026-11-21T17:00:00Z")));
	Schedule all;
	parse_window("00:00-00:00", all);
	assert(window_containing(all, T("2026-11-21T03:33:33Z")));
	assert(F(window_containing(all, T("2026-11-21T03:33:33Z"))->end) == "2026-11-22T00:00:00Z");
}

static void test_timezone_and_weekdays() {
	Schedule s;
	parse_window("22:00-06:00", s);
	s.utc_offset_min = 60; // local = UTC+1: window 21:00-05:00 UTC
	auto w = window_containing(s, T("2026-11-21T21:30:00Z"));
	assert(w && F(w->start) == "2026-11-21T21:00:00Z" && F(w->end) == "2026-11-22T05:00:00Z");
	s.utc_offset_min = -330; // UTC-05:30: window 03:30-11:30 UTC next day
	w = window_containing(s, T("2026-11-22T04:00:00Z"));
	assert(w && F(w->start) == "2026-11-22T03:30:00Z");

	// Weekday applies to the day the window STARTS: Mon-Fri nights.
	Schedule wk = nightly();
	wk.days = parse_days("mon-fri");
	// Saturday 2026-11-21 night is not allowed, Friday 2026-11-20 night runs into Saturday morning
	assert(window_containing(wk, T("2026-11-21T03:00:00Z")));      // Fri night, after midnight
	assert(!window_containing(wk, T("2026-11-21T23:00:00Z")));     // Sat night
	assert(!window_containing(wk, T("2026-11-22T03:00:00Z")));     // Sun morning (Sat window disabled)
	auto n = next_window_after(wk, T("2026-11-21T12:00:00Z"));     // Saturday noon -> Monday night
	assert(F(n->start) == "2026-11-23T22:00:00Z");

	Schedule off = nightly();
	off.enabled = false;
	assert(!window_containing(off, T("2026-11-21T23:00:00Z")) && !next_window_after(off, T("2026-11-21T12:00:00Z")));
	assert(upcoming_windows(off, T("2026-11-21T12:00:00Z"), 5).empty());
	off.enabled = true;
	off.days = 0;
	assert(!next_window_after(off, T("2026-11-21T12:00:00Z")));
	assert(throws([&] { validate(off); }));
}

static void test_validate() {
	Schedule s = nightly();
	validate(s);
	Schedule b = s;
	b.window_start_min = 1440;
	assert(throws([&] { validate(b); }));
	b = s;
	b.utc_offset_min = 24 * 60;
	assert(throws([&] { validate(b); }));
	b = s;
	b.interval = Seconds(0);
	assert(throws([&] { validate(b); }));
	b = s;
	b.min_start_remaining = Seconds(-1);
	assert(throws([&] { validate(b); }));
}

static void test_decide_new_run() {
	Schedule s = nightly();
	RunState none;

	Decision d = decide(s, none, T("2026-11-21T12:00:00Z")); // outside the window
	assert(d.action == Action::Wait && F(*d.at) == "2026-11-21T22:00:00Z");

	d = decide(s, none, T("2026-11-21T23:00:00Z")); // inside
	assert(d.action == Action::Start && F(*d.deadline) == "2026-11-22T06:00:00Z");

	// too little of the window left to be worth starting
	d = decide(s, none, T("2026-11-22T05:58:00Z"));
	assert(d.action == Action::Wait && F(*d.at) == "2026-11-22T22:00:00Z");
	s.min_start_remaining = Seconds(60);
	assert(decide(s, none, T("2026-11-22T05:58:00Z")).action == Action::Start);
	s.min_start_remaining = Seconds(300);

	// frequency: started last night, due 24h later
	RunState done;
	done.last_started = T("2026-11-21T22:30:00Z");
	d = decide(s, done, T("2026-11-22T22:00:00Z")); // window open but not yet due (22:30)
	assert(d.action == Action::Wait && F(*d.at) == "2026-11-22T22:30:00Z");
	assert(decide(s, done, T("2026-11-22T22:30:00Z")).action == Action::Start);

	// due, but only during the day: wait for the next window
	done.last_started = T("2026-11-20T10:00:00Z");
	d = decide(s, done, T("2026-11-21T12:00:00Z"));
	assert(d.action == Action::Wait && F(*d.at) == "2026-11-21T22:00:00Z");

	// a longer interval skips whole nights
	Schedule weekly = nightly();
	weekly.interval = Seconds(7 * 86400);
	done.last_started = T("2026-11-21T22:00:00Z");
	d = decide(weekly, done, T("2026-11-22T22:00:00Z"));
	assert(d.action == Action::Wait && F(*d.at) == "2026-11-28T22:00:00Z");

	Schedule off = nightly();
	off.enabled = false;
	d = decide(off, none, T("2026-11-21T23:00:00Z"));
	assert(d.action == Action::Wait && !d.at);
}

static void test_decide_running_and_paused() {
	Schedule s = nightly();
	RunState running{RunPhase::Running, T("2026-11-21T22:00:00Z")};

	Decision d = decide(s, running, T("2026-11-22T02:00:00Z"));
	assert(d.action == Action::Continue && F(*d.deadline) == "2026-11-22T06:00:00Z");

	// the window has closed on a running run: pause it, resume tomorrow night
	d = decide(s, running, T("2026-11-22T06:00:00Z"));
	assert(d.action == Action::Pause && F(*d.at) == "2026-11-22T22:00:00Z");

	RunState paused{RunPhase::Paused, T("2026-11-21T22:00:00Z")};
	d = decide(s, paused, T("2026-11-22T12:00:00Z"));
	assert(d.action == Action::Wait && F(*d.at) == "2026-11-22T22:00:00Z");
	d = decide(s, paused, T("2026-11-22T22:00:00Z"));
	assert(d.action == Action::Resume && F(*d.deadline) == "2026-11-23T06:00:00Z");

	// a paused run resumes even though the next run would already be due
	paused.last_started = T("2026-11-19T22:00:00Z");
	assert(decide(s, paused, T("2026-11-22T23:00:00Z")).action == Action::Resume);
}

static void test_chunk_gate() {
	TimePoint now = T("2026-11-22T05:00:00Z"), deadline = T("2026-11-22T06:00:00Z");
	assert(can_start_chunk(now, deadline, 1800));              // 30 min of an hour: fits
	assert(!can_start_chunk(now, deadline, 3000));             // 50 min * 1.25 > 60 min
	assert(can_start_chunk(now, deadline, 2800, 1.0));         // no padding: fits
	assert(!can_start_chunk(now, deadline, 3598, 1.0));        // margin of 5 s does not fit
	assert(!can_start_chunk(deadline, deadline, 0));           // nothing fits at the deadline
	assert(!can_start_chunk(deadline + Seconds(1), deadline, 0));
	assert(!can_start_chunk(now, deadline, -1));               // nonsense input
	assert(!can_start_chunk(now, deadline, 10, 0.5));
}

static void test_simulation() {
	Schedule s = nightly(); // 8 h per night

	// fits in one night
	auto ev = simulate_run(s, T("2026-11-21T12:00:00Z"), Seconds(3 * 3600));
	assert(ev.size() == 2 && ev[0].type == RunEvent::Type::Started && F(ev[0].at) == "2026-11-21T22:00:00Z");
	assert(ev[1].type == RunEvent::Type::Finished && F(ev[1].at) == "2026-11-22T01:00:00Z");

	// 20 h of work over 8 h nights: 22:00 + 8h, then 8h, then 4h
	ev = simulate_run(s, T("2026-11-21T12:00:00Z"), Seconds(20 * 3600));
	assert(ev.size() == 6);
	assert(ev[0].type == RunEvent::Type::Started && F(ev[0].at) == "2026-11-21T22:00:00Z");
	assert(ev[1].type == RunEvent::Type::Paused && F(ev[1].at) == "2026-11-22T06:00:00Z");
	assert(ev[2].type == RunEvent::Type::Resumed && F(ev[2].at) == "2026-11-22T22:00:00Z");
	assert(ev[3].type == RunEvent::Type::Paused && F(ev[3].at) == "2026-11-23T06:00:00Z");
	assert(ev[4].type == RunEvent::Type::Resumed && F(ev[4].at) == "2026-11-23T22:00:00Z");
	assert(ev[5].type == RunEvent::Type::Finished && F(ev[5].at) == "2026-11-24T02:00:00Z");

	// exactly one window of work finishes at the window end, without a pause
	ev = simulate_run(s, T("2026-11-21T22:00:00Z"), Seconds(8 * 3600));
	assert(ev.size() == 2 && ev[1].type == RunEvent::Type::Finished && F(ev[1].at) == "2026-11-22T06:00:00Z");

	// disabled schedule never starts
	Schedule off = s;
	off.enabled = false;
	assert(simulate_run(off, T("2026-11-21T12:00:00Z"), Seconds(60)).empty());

	// weekdays only: Saturday start is pushed to Monday night
	Schedule wk = s;
	wk.days = parse_days("mon-fri");
	ev = simulate_run(wk, T("2026-11-21T12:00:00Z"), Seconds(3600));
	assert(F(ev[0].at) == "2026-11-23T22:00:00Z");

	// the event cap holds for runs that would pause forever
	assert(simulate_run(s, T("2026-11-21T12:00:00Z"), Seconds(3650LL * 86400), 10).size() == 10);
}

int main() {
	test_time_parsing();
	test_windows();
	test_timezone_and_weekdays();
	test_validate();
	test_decide_new_run();
	test_decide_running_and_paused();
	test_chunk_gate();
	test_simulation();
	return 0;
}
