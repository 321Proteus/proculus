#ifndef PROCULUS_GATEWAY_SCHEDULE_STORE_HPP
#define PROCULUS_GATEWAY_SCHEDULE_STORE_HPP

// Recurring scans: what to scan (the same request as the New scan form), and when
// (a daily window, weekdays, a UTC offset and how often). The schedules are kept in
// one JSON file (0600, replaced atomically) next to the scan settings, so they survive a restart.
//
// A schedule never carries any authority of its own: when it is due, the scanner (ScanController)
// checks the request against the administrator's current policy exactly as it does for a scan
// started by hand. Tightening the policy therefore stops a schedule that no longer fits.

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "api.hpp"
#include "scan_control.hpp"
#include "schedule.hpp"

namespace proculus {

struct ScanSchedule {
	std::string id;      // s1, s2, ...
	std::string name;
	ScanRequest request;
	Schedule when;
	bool enabled = true;
	std::string created; // UTC, 2026-11-21T22:00:00Z
	// What happened last (kept by the scheduler):
	std::optional<TimePoint> last_started;
	std::string last_finished;
	std::string last_status;  // "", "ok", "failed", "stopped", "refused"
	std::string last_message;
	int64_t last_run_id = 0;
};

constexpr size_t kMaxSchedules = 50;

class ScheduleStore {
public:
	// `file` empty: nothing is kept on disk.
	explicit ScheduleStore(std::filesystem::path file = {});

	// Reads the file, if there is one. A file that cannot be used is ignored with a message in
	// `problem` (and left alone on disk until the next change).
	bool load(std::string* problem = nullptr);

	std::vector<ScanSchedule> list() const;
	std::optional<ScanSchedule> get(const std::string& id) const;

	// `body`: {name, request:{...as POST /api/scan}, window:"22:00-06:00", days:"mon-fri", utc_offset:"+01:00", interval:"24h", enabled}.
	// ApiError 400 for anything invalid, unknown keys included; 409 when there are too many.
	ScanSchedule add(const Json& body, TimePoint now);
	// The keys present in `body` replace those of the schedule (same rules as add).
	ScanSchedule update(const std::string& id, const Json& body);
	void remove(const std::string& id); // ApiError 404
	// What the scheduler records; keeps the rest as it is. No effect for an id that no longer exists.
	void record_started(const std::string& id, TimePoint at);
	void record_finished(const std::string& id, const std::string& status, const std::string& message, int64_t run_id, const std::string& finished);

private:
	void save_locked() const; // ApiError 500
	std::filesystem::path file_;
	mutable std::mutex m_;
	std::vector<ScanSchedule> items_;
	int next_ = 1;
};

// The JSON the API shows (the same keys add() reads, plus id, created and the last result).
Json schedule_json(const ScanSchedule& s);
// "22:00-06:00", "mon,tue", "+01:00", "24h"
std::string format_window(const Schedule& s);
std::string format_days(uint8_t mask);
std::string format_offset(int minutes);
std::string format_interval(Seconds s);

} // namespace proculus

#endif
