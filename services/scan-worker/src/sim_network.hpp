#ifndef PROCULUS_SIM_NETWORK_HPP
#define PROCULUS_SIM_NETWORK_HPP

// An emulated network for demos and tests: a deterministic population of hosts
// and services over some address ranges, behaving the way real infrastructure
// does between scans: stable hosts, hosts that answer only some of the time,
// hosts that appear or disappear, services that get upgraded or newly exposed.
//
// Everything is derived from a seed, so the same seed always describes the
// same network. "Time" is a scan round number: round 1 is the first scan.

#include <climits>
#include <cstdint>
#include <string>
#include <vector>

#include "backend.hpp"

namespace proculus {

struct SimService {
	uint16_t port = 0;
	std::string name, product, version, extrainfo;
	int from_round = 1;           // exposed from this round on
	int until_round = INT_MAX;    // ... through this round
	int upgrade_round = 0;        // 0 = never; from this round the version below applies
	std::string upgraded_version;
};

enum class SimAvailability {
	Always,    // answers every time
	Flapping,  // answers about half of the probes, unpredictably
	FromRound, // does not exist until edge_round, then always answers
	UntilRound // always answers through edge_round, then is gone
};

struct SimHost {
	uint32_t ip = 0;
	std::string hostname;
	std::string role;
	SimAvailability availability = SimAvailability::Always;
	int edge_round = 0;
	std::vector<SimService> services;
};

class SimNetwork {
public:
	// Populates the address ranges in `networks` (comma-separated IP/CIDR/range
	// list). About `density` of the addresses become hosts.
	static SimNetwork generate(uint64_t seed, const std::string& networks, double density = 0.04);

	size_t host_count() const { return hosts_.size(); }
	const std::vector<SimHost>& hosts() const { return hosts_; }
	const SimHost* find(uint32_t ip) const;

	// Does the host answer a probe in this round? `attempt` numbers repeated
	// probes within a round, which can differ for flapping hosts.
	bool is_up(uint32_t ip, int round, int attempt = 1) const;

	// Open services in this round, versions as of this round.
	std::vector<SimService> services(uint32_t ip, int round) const;

	// Ground truth for checking a scanner: hosts that exist (not necessarily answering) in `round`.
	std::vector<uint32_t> existing_hosts(int round) const;

private:
	uint64_t seed_ = 0;
	std::vector<SimHost> hosts_; // sorted by ip
};

// How fast the emulated network is scanned, on a virtual clock.
struct SimSpeed {
	double discovery_addresses_per_sec = 200;
	double service_seconds_per_host = 1.5;
	double silent_seconds_per_host = 0.02; // a host that does not answer a service scan
};

// Answers scan commands from a SimNetwork instead of sending packets.
// The reported elapsed_seconds is modelled time, so a caller can run a virtual clock.
class SimBackend : public ScanBackend {
public:
	explicit SimBackend(const SimNetwork& net, SimSpeed speed = {}) : net_(net), speed_(speed) {}

	void set_round(int round) { round_ = round; }
	int round() const { return round_; }

	NmapResult run(const NmapCommand& cmd, const ScanJob& job) override;

private:
	const SimNetwork& net_;
	SimSpeed speed_;
	int round_ = 1;
};

} // namespace proculus

#endif // PROCULUS_SIM_NETWORK_HPP
