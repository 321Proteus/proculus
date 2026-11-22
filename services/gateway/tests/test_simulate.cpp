#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>

#include "scan_control.hpp"
#include "simulate.hpp"

using namespace proculus;
namespace fs = std::filesystem;

int main() {
	const fs::path dir = fs::temp_directory_path() / ("proculus_sim_" + std::to_string(getpid()));
	fs::remove_all(dir);
	FileResultStore store(dir);
	auto sim = std::make_shared<Simulation>(42, "10.20.0.0/22", 0.05);
	assert(sim->net.host_count() > 0);

	ScanPolicy policy;
	policy.enabled = true;
	policy.simulated = true;
	policy.scope = policy.ceiling = sim->networks;
	policy.allowed_ports = sim->allowed_ports;
	policy.max_rate = 10000;
	ScanController ctl(policy, &store, Simulation::deps(sim));
	assert(ctl.status()["simulated"] == true);

	// real addresses are refused whatever the form says
	ScanRequest outside;
	outside.targets = {"192.168.1.0/24"};
	bool refused = false;
	try { ctl.start(outside); } catch (const ApiError& e) { refused = e.status == 400; }
	assert(refused);

	// a scan of the emulated network: found hosts, services, made-up web answers, saved as a run
	ScanRequest r;
	r.targets = {"10.20.0.0/22"};
	r.web = true;
	r.rate = 500;
	ctl.start(r);
	ctl.wait_idle();
	const Json st = ctl.status();
	assert(st["last"]["ok"] == true && st["last"]["hosts"].get<int>() > 0 && st["last"]["services"].get<int>() > 0 && st["last"]["web_responding"].get<int>() > 0);
	const auto runs = store.list();
	assert(runs.size() == 1 && runs[0].hosts > 0);

	// stopping works while the paced backend is "scanning"
	ctl.start(r);
	ctl.stop();
	ctl.wait_idle();
	assert(ctl.status()["last"]["ok"] == false && store.list().size() == 1);
	fs::remove_all(dir);
	return 0;
}
