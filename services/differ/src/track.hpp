#ifndef PROCULUS_TRACK_HPP
#define PROCULUS_TRACK_HPP

// Following hosts and services across scan runs.
//
// A single scan is a snapshot; the interesting facts are in how snapshots
// differ: a host that is new, one that has disappeared, a service that changed
// version. Hosts also come and go for harmless reasons (they flap, they only
// answer during office hours), so "it did not answer this time" is not
// evidence that it is gone. The Tracker turns the sequence of runs into
// states and events while accounting for how reliably each host answered
// before.
//
// How a miss is judged. Every host carries an existence confidence: how likely
// it is that the host still exists. A scan that sees it resets that to near
// certainty. A scan that does not see it is a Bayesian update: the odds that
// the host exists are multiplied by (1 - p), where p is how often the host
// normally answers (at that hour of the day, once there is enough history).
//   * The longer a host answered reliably, the less patience it gets: after 10
//     sightings it is Stale after 2 misses in a row and Gone after 4; after 30
//     sightings it is Gone after 2. A host seen only once is Stale after 5.
//   * A flapping host (answers about half the time) is Stale after about 6
//     misses in a row and Gone after about 14.
//   * A host that never answers at night loses nothing when it is absent at night.
// Gone additionally requires the host to have been unseen for a minimum time,
// so a burst of scans during a short outage cannot declare it gone.

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "proculus/results/results.hpp"
#include "schedule.hpp" // TimePoint, Seconds

namespace proculus {

enum class HostState {
	New,      // first seen in the latest run
	Active,   // answers
	Flapping, // answers unpredictably
	Stale,    // missed repeatedly: probably down, may return
	Gone,     // missed for long enough that it is considered gone
};

enum class ServiceState {
	New,     // first seen in the latest run (or came back)
	Active,
	Changed, // identification changed in the latest run
	Gone,
};

const char* to_string(HostState s);
const char* to_string(ServiceState s);

struct DifferConfig {
	double stale_below = 0.5; // existence confidence under which a host is Stale
	double gone_below = 0.05; // ... and under which it may be Gone
	Seconds gone_after{12 * 3600}; // Gone also needs this long without a sighting
	double max_confidence = 0.99;  // confidence is never certain

	// What a host with no history is assumed to be like: it answers about
	// `prior_response_rate` of the time, and that belief is worth `prior_weight`
	// observations. Real history takes over quickly; the prior only matters for
	// hosts seen a handful of times (a host seen once and never again must not
	// stay "probably alive" forever).
	double prior_response_rate = 0.8;
	double prior_weight = 2;

	int flap_window = 8;      // how many recent observations are inspected
	int flap_transitions = 3; // answered/missed changes in that window that make a host Flapping

	int service_gone_after = 2; // scans of a seen host without the service before it is Gone
};

struct ServiceTrack {
	uint16_t port = 0;
	std::string protocol;
	ServiceState state = ServiceState::New;
	std::string description;          // "nginx 1.24.0", or the service name when nothing more is known
	std::string previous_description; // before the latest change
	TimePoint first_seen, last_seen;
	int times_seen = 0;
	int times_seen_current = 0; // consecutive sightings with the current description
	int misses = 0;             // consecutive scans of a seen host without this service
	int nmap_confidence = 0;    // 0-10, as reported by nmap; 0 = unknown

	// 0..1: nmap's match confidence (0.5 when unknown), scaled by how often the
	// same identification has been confirmed in a row (1st: x0.5, 2nd: x0.67, ...).
	double confidence() const;
};

struct HostTrack {
	std::string ip;
	std::string hostname;
	HostState state = HostState::New;
	TimePoint first_seen, last_seen;
	int64_t first_run = 0, last_run = 0; // ids of the first / last run that saw it
	int sightings = 0;                   // runs that saw it
	int observations = 0;                // runs that could have seen it (since it first appeared)
	int consecutive_misses = 0;
	double existence = 0;                // confidence that the host still exists, 0..1
	bool time_dependent = false;         // answers at some hours and consistently not at others
	std::array<int, 24> hour_hits{}, hour_total{}; // per hour of day (UTC)
	std::deque<bool> recent;             // latest observations, true = answered
	std::map<std::pair<uint16_t, std::string>, ServiceTrack> services;

	// Chance that the host answers a scan started in `hour` (0-23): its own
	// record at that hour once it has two observations there, otherwise its
	// overall record, in both cases blended with the prior (see DifferConfig).
	double response_rate(int hour, double prior_rate = 0.8, double prior_weight = 2) const;
};

enum class EventKind {
	HostNew,
	HostReturned, // seen again after being Stale or Gone
	HostStale,
	HostGone,
	HostFlapping, // started flapping
	HostStable,   // stopped flapping
	ServiceNew,
	ServiceChanged,
	ServiceGone,
};

const char* to_string(EventKind k);

struct Event {
	EventKind kind;
	std::string ip;
	uint16_t port = 0;   // services only
	std::string detail;  // human-readable, e.g. "nginx 1.24.0 -> nginx 1.25.3"
};

struct RunUpdate {
	int64_t run_id = 0;
	TimePoint when;
	size_t hosts_seen = 0;
	size_t hosts_missed = 0; // known hosts that did not answer
	std::vector<Event> events;
};

class Tracker {
public:
	explicit Tracker(DifferConfig config = {});

	// Feeds the next run. Runs must arrive in chronological order. A run counts
	// as observing every known host (a host absent from it is a miss), so apply
	// only complete runs. Throws std::invalid_argument for a run that starts
	// at or before the previous one, has an unparsable time or address, or
	// lists a host twice. The tracker is unchanged when it throws.
	RunUpdate apply(const RunRecord& run);

	const std::map<uint32_t, HostTrack>& hosts() const { return hosts_; }
	const HostTrack* find(const std::string& ip) const;
	size_t count(HostState s) const;
	size_t runs_applied() const { return runs_; }

	// Hosts worth probing again before the next scheduled run: Flapping hosts
	// and Stale ones (their state is uncertain), as sorted IP strings.
	std::vector<std::string> reprobe_candidates() const;

	const DifferConfig& config() const { return config_; }

private:
	DifferConfig config_;
	std::map<uint32_t, HostTrack> hosts_;
	size_t runs_ = 0;
	bool have_last_ = false;
	TimePoint last_time_;
};

} // namespace proculus

#endif // PROCULUS_TRACK_HPP
