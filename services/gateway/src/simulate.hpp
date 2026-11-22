#ifndef PROCULUS_GATEWAY_SIMULATE_HPP
#define PROCULUS_GATEWAY_SIMULATE_HPP

// `gateway serve --simulate`: the whole system against an emulated network. Scans started from the UI go
// through the real controller, runner, planner, safety checks and web stage, but the "network" is a
// SimNetwork (hosts that come and go, services that get upgraded) and the web answers are made up, so
// nothing is ever sent anywhere. Scans are paced in real time (a second or a few per chunk) so the live
// view, the per-host progress bars and the stop button behave the way they do with nmap.

#include <atomic>
#include <memory>
#include <string>

#include "runner.hpp"
#include "sim_network.hpp"

namespace proculus {

struct Simulation {
	SimNetwork net;
	std::string networks;                 // what the emulated network covers
	std::string allowed_ports;            // a sensible port list for it
	std::atomic<int> rounds{0};           // scans started so far: the emulated network changes from scan to scan
	double speedup = 20;                  // modelled seconds per real second
	std::unique_ptr<HttpTransport> transport; // the made-up web servers

	Simulation(uint64_t seed, const std::string& networks, double density);
	// Runner dependencies that use this simulation (the scan backend and the HTTP transport).
	// The returned deps keep the simulation alive.
	static RunnerDeps deps(const std::shared_ptr<Simulation>& sim);
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_SIMULATE_HPP
