#ifndef PROCULUS_SCHEDULE_HPP
#define PROCULUS_SCHEDULE_HPP

// Scan scheduling: when scans may run (daily windows, on chosen weekdays), how
// often a new one is due, and what to do when a run does not fit in its window.
//
// Everything here is a pure function of its inputs (the current time is always
// passed in), so it is deterministic and easy to test. Time zones are fixed UTC
// offsets: daylight-saving transitions are not modelled.

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace proculus {

using TimePoint = std::chrono::system_clock::time_point;
using Seconds = std::chrono::seconds;

struct Schedule {
	// The daily window, in minutes after local midnight, [0, 1440). If end <=
	// start the window crosses midnight (22:00-06:00); start == end means the
	// window is open all day.
	int window_start_min = 0;
	int window_end_min = 0;
	// Local time = UTC + utc_offset_min.
	int utc_offset_min = 0;
	// Weekdays a window may START on; bit 0 = Monday ... bit 6 = Sunday.
	uint8_t days = 0x7f;
	// Minimum time between the starts of two runs (the scan frequency).
	Seconds interval{24 * 3600};
	// A new run is not started when less than this is left of the window.
	Seconds min_start_remaining{300};
	bool enabled = true;
};

struct Window {
	TimePoint start;
	TimePoint end;
};

// Throws std::invalid_argument if the schedule is malformed.
void validate(const Schedule& s);

// The window containing `t` (start <= t < end), if any.
std::optional<Window> window_containing(const Schedule& s, TimePoint t);

// The first window that starts strictly after `t`. nullopt if the schedule has
// no usable days or is disabled.
std::optional<Window> next_window_after(const Schedule& s, TimePoint t);

// The next `n` windows starting after `t`.
std::vector<Window> upcoming_windows(const Schedule& s, TimePoint t, size_t n);

// --- run lifecycle -----------------------------------------------------------

enum class RunPhase {
	None,    // no unfinished run
	Running, // a run is active
	Paused,  // a run was stopped at the end of its window and is waiting to resume
};

struct RunState {
	RunPhase phase = RunPhase::None;
	// Start of the most recent run (resuming does not change it). Drives the frequency.
	std::optional<TimePoint> last_started;
};

enum class Action {
	Wait,     // do nothing until `at`
	Start,    // begin a new run; stop it by `deadline`
	Resume,   // continue the paused run; stop it by `deadline`
	Continue, // the running run is inside its window; stop it by `deadline`
	Pause,    // the window closed on a running run: stop it now, resume at `at`
};

struct Decision {
	Action action = Action::Wait;
	std::optional<TimePoint> at;       // Wait: wake-up time. Pause: when to resume.
	std::optional<TimePoint> deadline; // Start/Resume/Continue: end of the current window
};

// What should happen at `now`?
//  * A running run keeps going while its window is open, and is paused when it closes.
//  * A paused run resumes in the next window, before any new run is started.
//  * A new run starts when `interval` has passed since the previous start and a
//    window with enough time left is open.
Decision decide(const Schedule& s, const RunState& state, TimePoint now);

// Should a worker begin a chunk expected to take `estimate_seconds`, given the
// window closes at `deadline`? The estimate is padded by `safety_factor` plus a
// fixed margin; nothing is started that is expected to overrun.
bool can_start_chunk(TimePoint now, TimePoint deadline, double estimate_seconds, double safety_factor = 1.25,
	Seconds margin = Seconds(5));

// --- simulation --------------------------------------------------------------

struct RunEvent {
	enum class Type { Started, Paused, Resumed, Finished } type;
	TimePoint at;
};

// Replays a run that needs `work` seconds of scanning, beginning at `now` under
// `schedule`: shows when it would start, be paused at window ends, resume, and
// finish. `max_events` bounds the output. Intended for previews and tests.
std::vector<RunEvent> simulate_run(const Schedule& s, TimePoint now, Seconds work, size_t max_events = 50);

// --- text helpers (CLI and config) -------------------------------------------

// "22:00-06:00" -> window minutes. Throws std::invalid_argument.
void parse_window(const std::string& text, Schedule& s);
// "mon-fri", "mon,wed,sun", "all" -> days mask.
uint8_t parse_days(const std::string& text);
// "90s", "15m", "24h", "2d" -> seconds.
Seconds parse_duration(const std::string& text);
// "+01:00", "-0530", "Z" -> minutes.
int parse_utc_offset(const std::string& text);
// "2026-11-21T12:00:00Z" (UTC) -> time point.
TimePoint parse_time(const std::string& text);
// Time point -> "2026-11-21T12:00:00Z".
std::string format_time(TimePoint t);

} // namespace proculus

#endif // PROCULUS_SCHEDULE_HPP
