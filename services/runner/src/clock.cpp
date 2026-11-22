#include "clock.hpp"

#include <algorithm>
#include <thread>

namespace proculus {

TimePoint SystemClock::now() { return std::chrono::system_clock::now(); }

bool SystemClock::sleep_until(TimePoint t, const std::atomic<bool>& stop) {
	// short slices, so a stop request is noticed quickly
	for (;;) {
		if (stop.load()) return false;
		const auto left = t - std::chrono::system_clock::now();
		if (left <= std::chrono::milliseconds(0)) return true;
		std::this_thread::sleep_for(std::min<std::chrono::system_clock::duration>(left, std::chrono::milliseconds(200)));
	}
}

} // namespace proculus
