#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <map>
#include <set>

#include "proculus/netutil/cidr.h"
#include "sim_network.hpp"
#include "track.hpp"

using namespace proculus;

// ------------------------------------------------------------------ helpers

static std::string at(int day, int hour = 22) {
	return format_time(parse_time("2026-11-01T00:00:00Z") + Seconds(day * 86400 + hour * 3600));
}

static ServiceRecord S(uint16_t port, const char* product, const char* version, int confidence = 10) {
	ServiceRecord s;
	s.port = port;
	s.name = port == 22 ? "ssh" : "http";
	s.product = product;
	s.version = version;
	s.confidence = confidence;
	return s;
}

static HostRecord H(const std::string& ip, std::vector<ServiceRecord> services = {}) {
	HostRecord h;
	h.ip = ip;
	h.services = std::move(services);
	return h;
}

static RunRecord R(int64_t id, const std::string& when, std::vector<HostRecord> hosts) {
	RunRecord r;
	r.id = id;
	r.started = when;
	r.finished = when;
	r.source = "test";
	r.hosts = std::move(hosts);
	return r;
}

static size_t count_events(const RunUpdate& u, EventKind k) {
	return static_cast<size_t>(std::count_if(u.events.begin(), u.events.end(), [&](const Event& e) { return e.kind == k; }));
}

template <class F>
static bool throws_invalid(F f) {
	try {
		f();
	} catch (const std::invalid_argument&) {
		return true;
	}
	return false;
}

// ------------------------------------------------------------------- tests

static void test_new_then_active() {
	Tracker t;
	RunUpdate u1 = t.apply(R(1, at(0), {H("10.0.0.1"), H("10.0.0.2")}));
	assert(u1.hosts_seen == 2 && u1.hosts_missed == 0 && count_events(u1, EventKind::HostNew) == 2);
	assert(t.find("10.0.0.1")->state == HostState::New && t.find("10.0.0.1")->first_run == 1);

	RunUpdate u2 = t.apply(R(2, at(1), {H("10.0.0.1"), H("10.0.0.2"), H("10.0.0.3")}));
	assert(u2.events.size() == 1 && u2.events[0].kind == EventKind::HostNew && u2.events[0].ip == "10.0.0.3");
	assert(t.find("10.0.0.1")->state == HostState::Active && t.find("10.0.0.3")->state == HostState::New);
	assert(t.count(HostState::Active) == 2 && t.count(HostState::New) == 1 && t.runs_applied() == 2);
	assert(t.find("10.9.9.9") == nullptr && t.find("junk") == nullptr);
}

static void test_a_reliable_host_going_away() {
	Tracker t;
	for (int d = 0; d < 10; d++) t.apply(R(d + 1, at(d), {H("10.0.0.1")}));
	assert(t.find("10.0.0.1")->state == HostState::Active && t.find("10.0.0.1")->existence > 0.98);

	// one miss is not news for a host that always answered
	RunUpdate u = t.apply(R(11, at(10), {}));
	assert(u.hosts_missed == 1 && u.events.empty() && t.find("10.0.0.1")->state == HostState::Active);
	const double after_one = t.find("10.0.0.1")->existence;
	assert(after_one < 0.99 && after_one > 0.5);

	// the second makes it Stale
	u = t.apply(R(12, at(11), {}));
	assert(count_events(u, EventKind::HostStale) == 1 && t.find("10.0.0.1")->state == HostState::Stale);
	assert(u.events[0].detail.find("missed 2 scans in a row") != std::string::npos);
	assert(t.find("10.0.0.1")->existence < after_one);
	assert(t.reprobe_candidates() == std::vector<std::string>{"10.0.0.1"});

	// the fourth is Gone (the runs are a day apart, well over the minimum unseen time)
	assert(t.apply(R(13, at(12), {})).events.empty() && t.find("10.0.0.1")->state == HostState::Stale);
	u = t.apply(R(14, at(13), {}));
	assert(count_events(u, EventKind::HostGone) == 1 && t.find("10.0.0.1")->state == HostState::Gone);
	assert(t.find("10.0.0.1")->existence < 0.05 && t.reprobe_candidates().empty());

	// Gone is quiet: no repeated events while it stays away
	assert(t.apply(R(15, at(14), {})).events.empty() && t.find("10.0.0.1")->state == HostState::Gone);

	// it comes back
	u = t.apply(R(16, at(15), {H("10.0.0.1")}));
	assert(count_events(u, EventKind::HostReturned) == 1 && u.events[0].detail == "was gone");
	assert(t.find("10.0.0.1")->state == HostState::Active && t.find("10.0.0.1")->existence > 0.98);
	assert(t.find("10.0.0.1")->consecutive_misses == 0);
}

static void test_less_history_or_more_changes_the_patience() {
	// long history: two misses are enough to be Gone
	Tracker t;
	for (int d = 0; d < 30; d++) t.apply(R(d + 1, at(d), {H("10.0.0.1")}));
	t.apply(R(31, at(30), {}));
	assert(t.find("10.0.0.1")->state == HostState::Active);
	RunUpdate u = t.apply(R(32, at(31), {}));
	assert(t.find("10.0.0.1")->state == HostState::Gone && count_events(u, EventKind::HostGone) == 1);

	// seen once: still declared stale eventually, not believed forever
	Tracker once;
	once.apply(R(1, at(0), {H("10.0.0.1")}));
	int misses = 0;
	while (once.find("10.0.0.1")->state != HostState::Stale && once.find("10.0.0.1")->state != HostState::Gone && misses < 50) {
		misses++;
		once.apply(R(1 + misses, at(misses), {}));
	}
	assert(once.find("10.0.0.1")->state == HostState::Stale && misses >= 3 && misses <= 8);

	// the prior is configurable: expecting a host to answer almost always makes a
	// miss more telling (written off sooner), expecting it to answer rarely makes it more patient
	DifferConfig c;
	c.prior_response_rate = 0.95;
	Tracker optimistic(c);
	optimistic.apply(R(1, at(0), {H("10.0.0.1")}));
	int m2 = 0;
	while (optimistic.find("10.0.0.1")->state != HostState::Stale && optimistic.find("10.0.0.1")->state != HostState::Gone && m2 < 50) {
		m2++;
		optimistic.apply(R(1 + m2, at(m2), {}));
	}
	assert(m2 < misses);

	DifferConfig low;
	low.prior_response_rate = 0.3;
	Tracker patient(low);
	patient.apply(R(1, at(0), {H("10.0.0.1")}));
	int m3 = 0;
	while (patient.find("10.0.0.1")->state != HostState::Stale && patient.find("10.0.0.1")->state != HostState::Gone && m3 < 50) {
		m3++;
		patient.apply(R(1 + m3, at(m3), {}));
	}
	assert(m3 > misses);
}

static void test_gone_needs_minimum_unseen_time() {
	// A burst of scans an hour apart during a short outage must not declare the host gone.
	Tracker t;
	for (int d = 0; d < 10; d++) t.apply(R(d + 1, at(d), {H("10.0.0.1")}));
	for (int i = 1; i <= 8; i++) t.apply(R(10 + i, at(9, 22 + i), {})); // hours 23.. of day 9 and beyond
	const HostTrack* h = t.find("10.0.0.1");
	assert(h->existence < 0.05);               // statistically it looks gone...
	assert(h->state == HostState::Stale);      // ...but only 8 hours have passed
	t.apply(R(19, at(10, 12), {}));            // 14 h after the last sighting
	assert(t.find("10.0.0.1")->state == HostState::Gone);
}

static void test_flapping_hosts_get_more_patience() {
	Tracker t;
	// A answers on odd runs only; B always answers. Neither answers from run 11 on.
	for (int i = 1; i <= 10; i++) {
		std::vector<HostRecord> hosts = {H("10.0.0.2")};
		if (i % 2 == 1) hosts.push_back(H("10.0.0.1"));
		t.apply(R(i, at(i), hosts));
	}
	assert(t.find("10.0.0.1")->state == HostState::Flapping);
	assert(t.find("10.0.0.2")->state == HostState::Active);

	size_t flapping_events = 0, stale_a = 0;
	for (int i = 11; i <= 14; i++) {
		RunUpdate u = t.apply(R(i, at(i), {}));
		flapping_events += count_events(u, EventKind::HostFlapping);
		for (const Event& e : u.events) stale_a += e.ip == "10.0.0.1" && (e.kind == EventKind::HostStale || e.kind == EventKind::HostGone);
	}
	(void)flapping_events;
	// the reliable host is gone after four misses; the flapper, with the same silence, has not even gone stale
	assert(t.find("10.0.0.2")->state == HostState::Gone);
	assert(t.find("10.0.0.1")->state != HostState::Gone && t.find("10.0.0.1")->state != HostState::Stale && stale_a == 0);
	assert(t.find("10.0.0.1")->existence > 0.5);
}

static void test_flapping_events_and_stabilising() {
	Tracker t;
	size_t started = 0, stopped = 0;
	// answers on 1,3,5,7 then every run from 8 on
	for (int i = 1; i <= 24; i++) {
		std::vector<HostRecord> hosts;
		if (i >= 8 || i % 2 == 1) hosts.push_back(H("10.0.0.1"));
		RunUpdate u = t.apply(R(i, at(i), hosts));
		started += count_events(u, EventKind::HostFlapping);
		stopped += count_events(u, EventKind::HostStable);
	}
	assert(started == 1 && stopped == 1);                       // exactly one flapping episode, reported once each way
	assert(t.find("10.0.0.1")->state == HostState::Active);
}

static void test_time_of_day_host_is_not_flapping_or_gone() {
	Tracker t;
	// Scans every 6 hours (03, 09, 15, 21 UTC). The host only answers at 09 and 15.
	size_t bad_events = 0, late_flapping = 0;
	int id = 0;
	for (int day = 0; day < 8; day++) {
		for (int hour : {3, 9, 15, 21}) {
			std::vector<HostRecord> hosts;
			if (hour == 9 || hour == 15) hosts.push_back(H("10.0.0.1"));
			RunUpdate u = t.apply(R(++id, at(day, hour), hosts));
			bad_events += count_events(u, EventKind::HostStale) + count_events(u, EventKind::HostGone);
			if (day >= 3) late_flapping += count_events(u, EventKind::HostFlapping);
		}
	}
	const HostTrack* h = t.find("10.0.0.1");
	assert(h->time_dependent && h->state == HostState::Active);
	assert(bad_events == 0 && late_flapping == 0);
	assert(h->existence > 0.9);                                  // last scan was 21:00, a miss that was expected
	assert(h->response_rate(9) > 0.8 && h->response_rate(21) < 0.2);
	assert(t.count(HostState::Active) == 1);
}

static void test_a_real_outage_is_still_noticed_for_time_dependent_hosts() {
	Tracker t;
	int id = 0;
	for (int day = 0; day < 6; day++)
		for (int hour : {3, 9, 15, 21}) {
			std::vector<HostRecord> hosts;
			if (hour == 9 || hour == 15) hosts.push_back(H("10.0.0.1"));
			t.apply(R(++id, at(day, hour), hosts));
		}
	// now it also stays silent during its usual hours, for three days
	for (int day = 6; day < 9; day++)
		for (int hour : {3, 9, 15, 21}) t.apply(R(++id, at(day, hour), {}));
	assert(t.find("10.0.0.1")->state == HostState::Stale || t.find("10.0.0.1")->state == HostState::Gone);
}

static void test_services_over_time() {
	Tracker t;
	t.apply(R(1, at(0), {H("10.0.0.1", {S(80, "nginx", "1.24.0"), S(22, "OpenSSH", "8.2p1")})}));
	const HostTrack* h = t.find("10.0.0.1");
	const auto http = std::make_pair(uint16_t{80}, std::string("tcp"));
	const auto ssh = std::make_pair(uint16_t{22}, std::string("tcp"));
	assert(h->services.at(http).state == ServiceState::New && h->services.at(http).description == "nginx 1.24.0");
	assert(h->services.at(http).confidence() == 0.5); // first sighting: nmap 10/10 x 1/2

	RunUpdate u = t.apply(R(2, at(1), {H("10.0.0.1", {S(80, "nginx", "1.24.0"), S(22, "OpenSSH", "8.2p1")})}));
	assert(u.events.empty() && h->services.at(http).state == ServiceState::Active);
	assert(h->services.at(http).times_seen == 2 && h->services.at(http).confidence() > 0.66 && h->services.at(http).confidence() < 0.67);

	// upgrade
	u = t.apply(R(3, at(2), {H("10.0.0.1", {S(80, "nginx", "1.25.3"), S(22, "OpenSSH", "8.2p1")})}));
	assert(u.events.size() == 1 && u.events[0].kind == EventKind::ServiceChanged && u.events[0].port == 80);
	assert(u.events[0].detail == "nginx 1.24.0 -> nginx 1.25.3");
	assert(h->services.at(http).state == ServiceState::Changed && h->services.at(http).previous_description == "nginx 1.24.0");
	assert(h->services.at(http).confidence() == 0.5);                          // a new identification starts over
	t.apply(R(4, at(3), {H("10.0.0.1", {S(80, "nginx", "1.25.3"), S(22, "OpenSSH", "8.2p1")})}));
	assert(h->services.at(http).state == ServiceState::Active);               // "Changed" lasts one run

	// ssh closes: one miss is tolerated, the second reports it
	u = t.apply(R(5, at(4), {H("10.0.0.1", {S(80, "nginx", "1.25.3")})}));
	assert(u.events.empty() && h->services.at(ssh).misses == 1 && h->services.at(ssh).state == ServiceState::Active);
	u = t.apply(R(6, at(5), {H("10.0.0.1", {S(80, "nginx", "1.25.3")})}));
	assert(u.events.size() == 1 && u.events[0].kind == EventKind::ServiceGone && u.events[0].port == 22);
	assert(h->services.at(ssh).state == ServiceState::Gone);
	assert(t.apply(R(7, at(6), {H("10.0.0.1", {S(80, "nginx", "1.25.3")})})).events.empty()); // not reported again

	// a host that does not answer says nothing about its services
	t.apply(R(8, at(7), {}));
	assert(h->services.at(http).misses == 0 && h->services.at(http).state == ServiceState::Active);

	// ssh is back
	u = t.apply(R(9, at(8), {H("10.0.0.1", {S(80, "nginx", "1.25.3"), S(22, "OpenSSH", "9.6p1")})}));
	assert(count_events(u, EventKind::ServiceNew) == 1 && u.events[0].detail == "OpenSSH 9.6p1 (reappeared)");
	assert(h->services.at(ssh).state == ServiceState::New && h->services.at(ssh).times_seen == 1);
}

static void test_service_descriptions_and_confidence_edge_cases() {
	Tracker t;
	ServiceRecord noversion = S(8080, "", "", 0);
	noversion.name = "http-proxy";
	ServiceRecord product_only = S(25, "Postfix smtpd", "", 5);
	t.apply(R(1, at(0), {H("10.0.0.1", {noversion, product_only})}));
	const HostTrack* h = t.find("10.0.0.1");
	assert(h->services.at({8080, "tcp"}).description == "http-proxy");               // falls back to the service name
	assert(h->services.at({25, "tcp"}).description == "Postfix smtpd");
	assert(h->services.at({8080, "tcp"}).confidence() == 0.25);                      // unknown nmap confidence counts as 0.5
	assert(h->services.at({25, "tcp"}).confidence() == 0.25);                        // 5/10 x 1/2

	// same port, different protocol, is a different service
	ServiceRecord udp = S(53, "BIND", "9.18");
	udp.protocol = "udp";
	ServiceRecord tcp = S(53, "BIND", "9.18");
	t.apply(R(2, at(1), {H("10.0.0.1", {udp, tcp})}));
	assert(h->services.count({53, "tcp"}) == 1 && h->services.count({53, "udp"}) == 1);
}

static void test_input_validation_leaves_state_untouched() {
	Tracker t;
	t.apply(R(1, at(1), {H("10.0.0.1")}));

	assert(throws_invalid([&] { t.apply(R(2, at(0), {H("10.0.0.1")})); }));                      // earlier than the last run
	assert(throws_invalid([&] { t.apply(R(3, at(1), {H("10.0.0.1")})); }));                      // same instant
	assert(throws_invalid([&] { t.apply(R(4, "yesterday", {})); }));                              // bad time
	assert(throws_invalid([&] { t.apply(R(5, at(2), {H("10.0.0.300")})); }));                    // bad address
	assert(throws_invalid([&] { t.apply(R(6, at(2), {H("10.0.0.1"), H("10.0.0.1")})); }));       // listed twice
	assert(throws_invalid([&] { t.apply(R(7, at(2), {H("10.0.0.5"), H("")})); }));               // one bad host spoils the run

	// none of that changed anything: the next good run behaves as if they never happened
	assert(t.runs_applied() == 1 && t.hosts().size() == 1 && t.find("10.0.0.5") == nullptr);
	RunUpdate u = t.apply(R(8, at(2), {H("10.0.0.1"), H("10.0.0.5")}));
	assert(u.events.size() == 1 && u.events[0].ip == "10.0.0.5" && t.find("10.0.0.1")->sightings == 2);
}

static void test_config_validation() {
	auto bad = [](DifferConfig c) { return throws_invalid([&] { Tracker t(c); }); };
	DifferConfig c;
	assert(!bad(c));
	c = {}; c.stale_below = 0; assert(bad(c));
	c = {}; c.stale_below = 1; assert(bad(c));
	c = {}; c.gone_below = 0.6; assert(bad(c));          // must be below stale_below
	c = {}; c.max_confidence = 1.0; assert(bad(c));
	c = {}; c.max_confidence = 0.4; assert(bad(c));
	c = {}; c.flap_window = 1; assert(bad(c));
	c = {}; c.flap_transitions = 8; assert(bad(c));      // cannot exceed the window
	c = {}; c.service_gone_after = 0; assert(bad(c));
	c = {}; c.prior_response_rate = 0; assert(bad(c));
	c = {}; c.prior_response_rate = 1; assert(bad(c));
	c = {}; c.prior_weight = 0; assert(bad(c));
	c = {}; c.gone_after = Seconds(-1); assert(bad(c));

	// the thresholds really are configurable
	DifferConfig impatient;
	impatient.stale_below = 0.9;
	Tracker t(impatient);
	for (int d = 0; d < 10; d++) t.apply(R(d + 1, at(d), {H("10.0.0.1")}));
	t.apply(R(11, at(10), {}));
	assert(t.find("10.0.0.1")->state == HostState::Stale); // one miss is enough here
}

// ------------------------------------------------- against the emulated network

static RunRecord run_from_sim(const SimNetwork& net, int round) {
	RunRecord r = R(round, at(round), {});
	for (const SimHost& h : net.hosts()) {
		if (!net.is_up(h.ip, round)) continue;
		char buf[PC_IP_STR_MAX];
		pc_ip_format(h.ip, buf);
		HostRecord rec = H(buf);
		rec.hostname = h.hostname;
		for (const SimService& s : net.services(h.ip, round)) {
			ServiceRecord sv = S(s.port, s.product.c_str(), s.version.c_str());
			sv.name = s.name;
			rec.services.push_back(sv);
		}
		r.hosts.push_back(std::move(rec));
	}
	return r;
}

static void test_against_ground_truth() {
	SimNetwork net = SimNetwork::generate(99, "10.50.0.0/20", 0.15);
	Tracker t;
	std::map<std::string, std::vector<std::pair<int, EventKind>>> history; // ip -> (round, kind)
	const int rounds = 30;
	for (int r = 1; r <= rounds; r++) {
		RunUpdate u = t.apply(run_from_sim(net, r));
		for (const Event& e : u.events) history[e.ip].push_back({r, e.kind});
	}

	size_t always = 0, flapping = 0, from = 0, until = 0;
	size_t flapping_ended_flapping = 0, flapping_gone = 0;
	for (const SimHost& sh : net.hosts()) {
		char buf[PC_IP_STR_MAX];
		pc_ip_format(sh.ip, buf);
		const HostTrack* h = t.find(buf);
		const auto& events = history[buf];
		auto has = [&](EventKind k) {
			return std::any_of(events.begin(), events.end(), [&](const auto& e) { return e.second == k; });
		};

		switch (sh.availability) {
		case SimAvailability::Always:
			// never reported as missing, never flagged as unstable
			always++;
			assert(h && h->state == HostState::Active && h->sightings == rounds);
			assert(!has(EventKind::HostStale) && !has(EventKind::HostGone) && !has(EventKind::HostFlapping));
			break;
		case SimAvailability::FromRound: {
			from++;
			// new exactly when it appeared, and then stays
			assert(h && h->first_run == sh.edge_round);
			assert(std::count_if(events.begin(), events.end(), [](const auto& e) { return e.second == EventKind::HostNew; }) == 1);
			assert(std::find(events.begin(), events.end(), std::make_pair(sh.edge_round, EventKind::HostNew)) != events.end());
			assert(h->state == HostState::Active);
			break;
		}
		case SimAvailability::UntilRound:
			// stale first, then gone, and it ends gone
			until++;
			assert(h && h->state == HostState::Gone && has(EventKind::HostStale) && has(EventKind::HostGone));
			assert(h->last_run == sh.edge_round);
			break;
		case SimAvailability::Flapping:
			flapping++;
			flapping_ended_flapping += h && (h->state == HostState::Flapping);
			flapping_gone += has(EventKind::HostGone);
			assert(h && has(EventKind::HostFlapping));
			break;
		}
	}
	assert(always > 50 && flapping > 10 && from > 5 && until > 5);

	// a coin-flipping host is only flagged while its recent history alternates enough:
	// most of them, most of the time
	assert(flapping_ended_flapping * 100 >= flapping * 55);
	// and flapping hosts are essentially never declared gone
	assert(flapping_gone * 100 <= flapping * 5);

	// reprobe candidates are exactly the hosts in an uncertain state
	for (const std::string& ip : t.reprobe_candidates()) {
		const HostState s = t.find(ip)->state;
		assert(s == HostState::Flapping || s == HostState::Stale);
	}
	size_t expected = t.count(HostState::Flapping) + t.count(HostState::Stale);
	assert(t.reprobe_candidates().size() == expected);

	// services: upgrades reported once, in the round they happen
	size_t upgrades = 0;
	for (const SimHost& sh : net.hosts())
		for (const SimService& s : sh.services) {
			if (s.upgrade_round == 0 || sh.availability != SimAvailability::Always) continue;
			upgrades++;
			char buf[PC_IP_STR_MAX];
			pc_ip_format(sh.ip, buf);
			size_t changes = 0;
			for (const auto& e : history[buf])
				changes += e.first == s.upgrade_round && e.second == EventKind::ServiceChanged;
			assert(changes == 1);
		}
	assert(upgrades > 0);
}

int main() {
	test_new_then_active();
	test_a_reliable_host_going_away();
	test_less_history_or_more_changes_the_patience();
	test_gone_needs_minimum_unseen_time();
	test_flapping_hosts_get_more_patience();
	test_flapping_events_and_stabilising();
	test_time_of_day_host_is_not_flapping_or_gone();
	test_a_real_outage_is_still_noticed_for_time_dependent_hosts();
	test_services_over_time();
	test_service_descriptions_and_confidence_edge_cases();
	test_input_validation_leaves_state_untouched();
	test_config_validation();
	test_against_ground_truth();
	return 0;
}
