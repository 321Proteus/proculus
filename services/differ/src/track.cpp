#include "track.hpp"

#include <algorithm>
#include <cstdio>
#include <set>
#include <stdexcept>

#include "proculus/netutil/cidr.h"

namespace proculus {

const char* to_string(HostState s) {
	switch (s) {
	case HostState::New: return "new";
	case HostState::Active: return "active";
	case HostState::Flapping: return "flapping";
	case HostState::Stale: return "stale";
	case HostState::Gone: return "gone";
	}
	return "?";
}

const char* to_string(ServiceState s) {
	switch (s) {
	case ServiceState::New: return "new";
	case ServiceState::Active: return "active";
	case ServiceState::Changed: return "changed";
	case ServiceState::Gone: return "gone";
	}
	return "?";
}

const char* to_string(EventKind k) {
	switch (k) {
	case EventKind::HostNew: return "host_new";
	case EventKind::HostReturned: return "host_returned";
	case EventKind::HostStale: return "host_stale";
	case EventKind::HostGone: return "host_gone";
	case EventKind::HostFlapping: return "host_flapping";
	case EventKind::HostStable: return "host_stable";
	case EventKind::ServiceNew: return "service_new";
	case EventKind::ServiceChanged: return "service_changed";
	case EventKind::ServiceGone: return "service_gone";
	}
	return "?";
}

namespace {

int hour_of(TimePoint t) {
	const int64_t s = std::chrono::duration_cast<Seconds>(t.time_since_epoch()).count();
	return static_cast<int>(((s % 86400) + 86400) % 86400 / 3600);
}

std::string describe(const ServiceRecord& s) {
	std::string d = s.product;
	if (!s.version.empty()) d += (d.empty() ? "" : " ") + s.version;
	return d.empty() ? s.name : d;
}

std::string fixed(double v, int digits = 2) {
	char buf[32];
	std::snprintf(buf, sizeof buf, "%.*f", digits, v);
	return buf;
}

// Do the recent observations switch between answered and missed often?
bool alternates(const HostTrack& h, const DifferConfig& c) {
	int transitions = 0;
	for (size_t i = 1; i < h.recent.size(); i++) transitions += h.recent[i] != h.recent[i - 1];
	return transitions >= c.flap_transitions;
}

// Answers reliably at some hours of the day and consistently not at others.
bool hour_dependent(const HostTrack& h) {
	int high = 0, low = 0;
	for (size_t i = 0; i < 24; i++) {
		if (h.hour_total[i] < 2) continue;
		const double rate = static_cast<double>(h.hour_hits[i]) / h.hour_total[i];
		if (rate >= 0.8) high++;
		else if (rate <= 0.2) low++;
	}
	return high >= 1 && low >= 1;
}

void push_recent(HostTrack& h, bool answered, int window) {
	h.recent.push_back(answered);
	while (static_cast<int>(h.recent.size()) > window) h.recent.pop_front();
}

} // namespace

// ----------------------------------------------------------------- tracks

double ServiceTrack::confidence() const {
	const double match = nmap_confidence > 0 ? nmap_confidence / 10.0 : 0.5;
	const double confirmed = static_cast<double>(times_seen_current) / (times_seen_current + 1);
	return match * confirmed;
}

double HostTrack::response_rate(int hour, double prior_rate, double prior_weight) const {
	const double a = prior_rate * prior_weight; // pseudo-answers
	if (hour >= 0 && hour < 24 && hour_total[static_cast<size_t>(hour)] >= 2)
		return (hour_hits[static_cast<size_t>(hour)] + a) / (hour_total[static_cast<size_t>(hour)] + prior_weight);
	return (sightings + a) / (observations + prior_weight);
}

// ---------------------------------------------------------------- tracker

Tracker::Tracker(DifferConfig config) : config_(config) {
	if (!(config_.stale_below > 0 && config_.stale_below < 1) || !(config_.gone_below > 0 && config_.gone_below < config_.stale_below))
		throw std::invalid_argument("need 0 < gone_below < stale_below < 1");
	if (!(config_.max_confidence > 0.5 && config_.max_confidence < 1)) throw std::invalid_argument("max_confidence must be in (0.5, 1)");
	if (config_.flap_window < 2 || config_.flap_transitions < 1 || config_.flap_transitions >= config_.flap_window)
		throw std::invalid_argument("need 1 <= flap_transitions < flap_window");
	if (!(config_.prior_response_rate > 0 && config_.prior_response_rate < 1) || !(config_.prior_weight > 0))
		throw std::invalid_argument("need 0 < prior_response_rate < 1 and prior_weight > 0");
	if (config_.service_gone_after < 1) throw std::invalid_argument("service_gone_after must be >= 1");
	if (config_.gone_after.count() < 0) throw std::invalid_argument("gone_after must not be negative");
}

const HostTrack* Tracker::find(const std::string& ip) const {
	uint32_t v;
	if (pc_ip_parse(ip.c_str(), &v) != 0) return nullptr;
	auto it = hosts_.find(v);
	return it == hosts_.end() ? nullptr : &it->second;
}

size_t Tracker::count(HostState s) const {
	return static_cast<size_t>(std::count_if(hosts_.begin(), hosts_.end(), [&](const auto& kv) { return kv.second.state == s; }));
}

std::vector<std::string> Tracker::reprobe_candidates() const {
	std::vector<std::string> out;
	for (const auto& kv : hosts_)
		if (kv.second.state == HostState::Flapping || kv.second.state == HostState::Stale) out.push_back(kv.second.ip);
	return out; // map order is numeric by address
}

RunUpdate Tracker::apply(const RunRecord& run) {
	// --- validate everything before touching any state
	const TimePoint t = parse_time(run.started); // throws std::invalid_argument
	if (have_last_ && t <= last_time_)
		throw std::invalid_argument("run " + std::to_string(run.id) + " starts at or before the previous run (" + format_time(last_time_) +
			"): runs must be applied in chronological order");
	std::map<uint32_t, const HostRecord*> seen;
	for (const HostRecord& h : run.hosts) {
		uint32_t ip;
		if (pc_ip_parse(h.ip.c_str(), &ip) != 0) throw std::invalid_argument("invalid host address \"" + h.ip + "\" in run " + std::to_string(run.id));
		if (!seen.emplace(ip, &h).second) throw std::invalid_argument("host " + h.ip + " is listed twice in run " + std::to_string(run.id));
	}

	RunUpdate up;
	up.run_id = run.id;
	up.when = t;
	up.hosts_seen = seen.size();
	const int hour = hour_of(t);
	auto emit = [&](EventKind k, const std::string& ip, std::string detail, uint16_t port = 0) {
		up.events.push_back({k, ip, port, std::move(detail)});
	};

	// --- hosts that answered
	for (const auto& [ip, rec] : seen) {
		auto [it, created] = hosts_.try_emplace(ip);
		HostTrack& h = it->second;
		const HostState before = h.state == HostState::New ? HostState::Active : h.state;

		if (created) {
			h.ip = rec->ip;
			h.first_seen = t;
			h.first_run = run.id;
		}
		if (!rec->hostname.empty()) h.hostname = rec->hostname;
		h.last_seen = t;
		h.last_run = run.id;
		h.sightings++;
		h.observations++;
		h.hour_hits[static_cast<size_t>(hour)]++;
		h.hour_total[static_cast<size_t>(hour)]++;
		h.consecutive_misses = 0;
		h.existence = config_.max_confidence;
		push_recent(h, true, config_.flap_window);
		h.time_dependent = hour_dependent(h);

		if (created) {
			h.state = HostState::New;
			emit(EventKind::HostNew, h.ip, h.hostname);
		} else {
			if (before == HostState::Stale || before == HostState::Gone)
				emit(EventKind::HostReturned, h.ip, std::string("was ") + to_string(before));
			const bool flapping = alternates(h, config_) && !h.time_dependent;
			h.state = flapping ? HostState::Flapping : HostState::Active;
			if (h.state == HostState::Flapping && before != HostState::Flapping)
				emit(EventKind::HostFlapping, h.ip, "answered " + std::to_string(std::count(h.recent.begin(), h.recent.end(), true)) + " of last " +
					std::to_string(h.recent.size()) + " scans");
			if (h.state == HostState::Active && before == HostState::Flapping) emit(EventKind::HostStable, h.ip, "");
		}

		// --- its services
		std::set<std::pair<uint16_t, std::string>> present;
		for (const ServiceRecord& sv : rec->services) {
			const auto key = std::make_pair(sv.port, sv.protocol);
			present.insert(key);
			auto [sit, screated] = h.services.try_emplace(key);
			ServiceTrack& s = sit->second;
			const std::string desc = describe(sv);
			const ServiceState prev = s.state;

			if (screated || prev == ServiceState::Gone) {
				const bool returned = !screated; // was Gone, now open again
				s = ServiceTrack{};
				s.port = sv.port;
				s.protocol = sv.protocol;
				s.state = ServiceState::New;
				s.description = desc;
				s.first_seen = t;
				s.times_seen = 1;
				s.times_seen_current = 1;
				emit(EventKind::ServiceNew, h.ip, desc + (returned ? " (reappeared)" : ""), sv.port);
			} else if (desc != s.description) {
				emit(EventKind::ServiceChanged, h.ip, s.description + " -> " + desc, sv.port);
				s.previous_description = s.description;
				s.description = desc;
				s.state = ServiceState::Changed;
				s.times_seen++;
				s.times_seen_current = 1;
			} else {
				s.state = ServiceState::Active;
				s.times_seen++;
				s.times_seen_current++;
			}
			s.misses = 0;
			s.last_seen = t;
			s.nmap_confidence = sv.confidence;
		}
		for (auto& [key, s] : h.services) {
			if (present.count(key) || s.state == ServiceState::Gone) continue;
			// Only a host that was seen gives evidence about its services.
			if (++s.misses >= config_.service_gone_after) {
				s.state = ServiceState::Gone;
				emit(EventKind::ServiceGone, h.ip, s.description, s.port);
			}
		}
	}

	// --- known hosts that did not answer
	for (auto& [ip, h] : hosts_) {
		if (seen.count(ip)) continue;
		up.hosts_missed++;
		const HostState before = h.state == HostState::New ? HostState::Active : h.state;

		// How surprising is this miss? Judge it by what was known before this scan.
		const double p = h.response_rate(hour, config_.prior_response_rate, config_.prior_weight);
		h.observations++;
		h.hour_total[static_cast<size_t>(hour)]++;
		h.consecutive_misses++;
		push_recent(h, false, config_.flap_window);
		h.time_dependent = hour_dependent(h);

		const double odds = h.existence / (1.0 - h.existence) * (1.0 - p);
		h.existence = std::min(odds / (1.0 + odds), config_.max_confidence);

		const bool unseen_long = (t - h.last_seen) >= config_.gone_after;
		HostState now;
		if (before == HostState::Gone) {
			now = HostState::Gone;
		} else if (h.existence < config_.gone_below && unseen_long) {
			now = HostState::Gone;
		} else if (h.existence < config_.stale_below) {
			now = HostState::Stale;
		} else {
			// A flapper stays a flapper while it is merely quiet: its recent window fills
			// with misses and stops looking like alternation, but that says nothing new.
			now = (before == HostState::Flapping || (alternates(h, config_) && !h.time_dependent)) ? HostState::Flapping : HostState::Active;
		}

		if (now == HostState::Gone && before != HostState::Gone)
			emit(EventKind::HostGone, h.ip, "unseen since " + format_time(h.last_seen) + ", confidence " + fixed(h.existence));
		else if (now == HostState::Stale && before != HostState::Stale && before != HostState::Gone)
			emit(EventKind::HostStale, h.ip, "missed " + std::to_string(h.consecutive_misses) + " scans in a row, confidence " + fixed(h.existence));
		else if (now == HostState::Flapping && before != HostState::Flapping && before != HostState::Stale)
			emit(EventKind::HostFlapping, h.ip, "answered " + std::to_string(std::count(h.recent.begin(), h.recent.end(), true)) + " of last " +
				std::to_string(h.recent.size()) + " scans");
		h.state = now;
	}

	runs_++;
	have_last_ = true;
	last_time_ = t;
	return up;
}

} // namespace proculus
