#ifndef PROCULUS_COMPARE_HPP
#define PROCULUS_COMPARE_HPP

// A plain comparison of two scan runs: what is in one and not the other.
// No history is involved, so it says nothing about *why* a host is missing
// (see Tracker for that); it is the "diff these two scans" view.

#include <string>
#include <vector>

#include "proculus/results/results.hpp"

namespace proculus {

struct ServiceChange {
	std::string ip;
	uint16_t port = 0;
	std::string protocol;
	std::string before; // empty if the service is new
	std::string after;  // empty if the service is gone
};

// Something about a web service changed between two runs. Only services that
// were probed as web services in both runs are compared (a first probe is not a
// change: there is nothing to compare with).
struct WebChange {
	std::string ip;
	uint16_t port = 0;
	std::string protocol;
	std::string what;   // status, title, server, redirect, cookies, tls certificate, tls problems,
	                    // technology added / removed / version
	std::string before; // empty if it appeared
	std::string after;  // empty if it disappeared
};

struct Comparison {
	int64_t before_id = 0, after_id = 0;
	std::vector<std::string> new_hosts;  // answered only in `after`
	std::vector<std::string> gone_hosts; // answered only in `before`
	std::vector<ServiceChange> new_services;     // on hosts present in both runs
	std::vector<ServiceChange> gone_services;
	std::vector<ServiceChange> changed_services; // same port, different identification
	std::vector<WebChange> web_changes;          // same service, different web behaviour (see WebChange)
};

// Hosts and services are compared by address and (port, protocol); a service
// counts as changed when its product or version differs. Services of hosts
// that appear or disappear are not listed separately. Results are sorted by
// address, then port.
Comparison compare_runs(const RunRecord& before, const RunRecord& after);

} // namespace proculus

#endif // PROCULUS_COMPARE_HPP
