#ifndef PROCULUS_GATEWAY_SCAN_SCHEDULER_HPP
#define PROCULUS_GATEWAY_SCAN_SCHEDULER_HPP

// Starts the scans of the schedules (ScheduleStore) when they are due.
//
// Once in a while (and on request) every enabled schedule is looked at with the same
// decide() the command-line runner uses: it is due when its interval has passed since the
// last start and a scan window with enough time left is open. A scan that was missed (the
// gateway was down) is run once when the gateway is back and a window is open, not repeatedly.
// Schedules go through ScanController::start(), so the administrator's policy is checked again
// for every scan; one that no longer fits is recorded as refused and tried again after its interval.
// One scan runs at a time: when something else is running, a due schedule waits for the next look.
// A scan that does not fit its window pauses at its end and resumes in the next one.

#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "schedule_store.hpp"

namespace proculus {

class ScanScheduler {
public:
	// `store` and `scans` must outlive the scheduler. It takes over the controller's finish callback.
	ScanScheduler(ScheduleStore& store, ScanController& scans);
	~ScanScheduler();

	// Called for what happened to a schedule: ("scheduled scan started", "daily (s1)"), ... For the audit log.
	void set_event_sink(std::function<void(const std::string& action, const std::string& detail)> sink);

	// A background thread that looks every `period`.
	void start(std::chrono::seconds period = std::chrono::seconds(15));
	void stop();

	// One look at `now`: starts at most one due scan. Returns the id of the schedule it started ("" if none).
	std::string tick(TimePoint now);
	// Wakes the thread up (after a change to a schedule).
	void poke();

	// Starts the schedule's scan now, whatever its window (a person asked for it). ApiError 404/403/400/409.
	void run_now(const std::string& id, TimePoint now);

	// When the schedule is next due: now if it can start at once, nullopt if it never will (disabled).
	std::optional<TimePoint> next_run(const ScanSchedule& s, TimePoint now) const;
	// The schedule as the API shows it, plus next_run and whether it is the one running.
	Json describe(const ScanSchedule& s, TimePoint now) const;
	// The next `n` windows of a schedule: [{start, end}].
	static Json upcoming(const ScanSchedule& s, TimePoint now, size_t n);

private:
	void event(const std::string& action, const std::string& detail);
	void finished(const std::string& origin, const Json& result);
	ScheduleStore& store_;
	ScanController& scans_;
	std::function<void(const std::string&, const std::string&)> sink_;
	mutable std::mutex m_;
	std::mutex start_m_; // held from starting a scan until it is recorded, so a very quick scan is not recorded as finished first
	std::condition_variable cv_;
	std::thread thread_;
	bool stopping_ = false, poked_ = false;
	std::string running_; // id of the schedule whose scan is running
};

} // namespace proculus

#endif
