#ifndef PROCULUS_RUNNER_CLOCK_HPP
#define PROCULUS_RUNNER_CLOCK_HPP

#include <atomic>

#include "schedule.hpp"

namespace proculus {

// Time as the runner sees it. The real one is the system clock; tests use a
// virtual one so a "night-long" scan window takes no time.
class Clock {
public:
	virtual ~Clock() = default;
	virtual TimePoint now() = 0;
	// Waits until `t`, or until `stop` becomes true. Returns false if it was stopped.
	virtual bool sleep_until(TimePoint t, const std::atomic<bool>& stop) = 0;
};

class SystemClock : public Clock {
public:
	TimePoint now() override;
	bool sleep_until(TimePoint t, const std::atomic<bool>& stop) override;
};

} // namespace proculus

#endif // PROCULUS_RUNNER_CLOCK_HPP
