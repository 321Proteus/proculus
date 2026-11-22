#include "scan_scheduler.hpp"

namespace proculus {

namespace {
const std::string kOrigin = "schedule:";
}

ScanScheduler::ScanScheduler(ScheduleStore& store, ScanController& scans) : store_(store), scans_(scans) {
	scans_.set_on_finished([this](const std::string& origin, const Json& result) { finished(origin, result); });
}

ScanScheduler::~ScanScheduler() {
	stop();
	scans_.set_on_finished({});
}

void ScanScheduler::set_event_sink(std::function<void(const std::string&, const std::string&)> sink) {
	std::lock_guard<std::mutex> l(m_);
	sink_ = std::move(sink);
}

void ScanScheduler::event(const std::string& action, const std::string& detail) {
	std::function<void(const std::string&, const std::string&)> sink;
	{
		std::lock_guard<std::mutex> l(m_);
		sink = sink_;
	}
	if (sink) {
		try {
			sink(action, detail);
		} catch (...) {
		}
	}
}

void ScanScheduler::start(std::chrono::seconds period) {
	std::lock_guard<std::mutex> l(m_);
	if (thread_.joinable()) return;
	stopping_ = false;
	thread_ = std::thread([this, period] {
		std::unique_lock<std::mutex> l(m_);
		while (!stopping_) {
			l.unlock();
			try {
				tick(std::chrono::system_clock::now());
			} catch (...) { // a bad look must never end the scheduler
			}
			l.lock();
			cv_.wait_for(l, period, [this] { return stopping_ || poked_; });
			poked_ = false;
		}
	});
}

void ScanScheduler::stop() {
	{
		std::lock_guard<std::mutex> l(m_);
		stopping_ = true;
	}
	cv_.notify_all();
	if (thread_.joinable()) thread_.join();
}

void ScanScheduler::poke() {
	{
		std::lock_guard<std::mutex> l(m_);
		poked_ = true;
	}
	cv_.notify_all();
}

std::string ScanScheduler::tick(TimePoint now) {
	if (!scans_.enabled()) return "";
	std::lock_guard<std::mutex> order(start_m_);
	for (const ScanSchedule& s : store_.list()) {
		if (!s.enabled) continue;
		RunState state;
		state.last_started = s.last_started;
		if (decide(s.when, state, now).action != Action::Start) continue;
		try {
			scans_.start(s.request, s.when, kOrigin + s.id);
		} catch (const ApiError& e) {
			if (e.status == 409) return ""; // busy: the next look tries again (and the others wait their turn)
			// the policy no longer allows it: say so, and try again after the interval, not at every look
			store_.record_started(s.id, now);
			store_.record_finished(s.id, "refused", e.what(), 0, format_time(now));
			event("scheduled scan refused", s.name + " (" + s.id + "): " + e.what());
			continue;
		}
		store_.record_started(s.id, now);
		{
			std::lock_guard<std::mutex> l(m_);
			running_ = s.id;
		}
		event("scheduled scan started", s.name + " (" + s.id + ")");
		return s.id;
	}
	return "";
}

void ScanScheduler::run_now(const std::string& id, TimePoint now) {
	const auto s = store_.get(id);
	if (!s) throw ApiError(404, "no such schedule");
	std::lock_guard<std::mutex> order(start_m_);
	// no window: a person asked for it. The scan counts as the schedule's last one.
	scans_.start(s->request, std::nullopt, kOrigin + id);
	store_.record_started(id, now);
	{
		std::lock_guard<std::mutex> l(m_);
		running_ = id;
	}
	event("scheduled scan started (by hand)", s->name + " (" + id + ")");
}

void ScanScheduler::finished(const std::string& origin, const Json& result) {
	if (origin.compare(0, kOrigin.size(), kOrigin) != 0) return;
	const std::string id = origin.substr(kOrigin.size());
	{
		std::lock_guard<std::mutex> order(start_m_); // the start of this scan has been recorded
	}
	const bool ok = result.value("ok", false);
	const std::string message = result.value("message", "");
	const bool stopped = !ok && message.compare(0, 7, "stopped") == 0;
	store_.record_finished(id, ok ? "ok" : stopped ? "stopped" : "failed", message, result.value("run_id", static_cast<int64_t>(0)), result.value("finished", ""));
	{
		std::lock_guard<std::mutex> l(m_);
		if (running_ == id) running_.clear();
	}
	event(ok ? "scheduled scan finished" : "scheduled scan did not finish", id + ": " + message);
}

std::optional<TimePoint> ScanScheduler::next_run(const ScanSchedule& s, TimePoint now) const {
	if (!s.enabled) return std::nullopt;
	RunState state;
	state.last_started = s.last_started;
	const Decision d = decide(s.when, state, now);
	if (d.action == Action::Start) return now;
	return d.at;
}

Json ScanScheduler::describe(const ScanSchedule& s, TimePoint now) const {
	Json j = schedule_json(s);
	const auto next = next_run(s, now);
	j["next_run"] = next ? Json(format_time(*next)) : Json(nullptr);
	std::string running;
	{
		std::lock_guard<std::mutex> l(m_);
		running = running_;
	}
	j["running"] = running == s.id;
	return j;
}

Json ScanScheduler::upcoming(const ScanSchedule& s, TimePoint now, size_t n) {
	Json out = Json::array();
	for (const Window& w : upcoming_windows(s.when, now, n)) out.push_back({{"start", format_time(w.start)}, {"end", format_time(w.end)}});
	return out;
}

} // namespace proculus
