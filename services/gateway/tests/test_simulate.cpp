#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "api.hpp"
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

	// a custom signature saved after the first scan is used by the next one (the file is read for every scan)
	{
		const fs::path sigfile = dir / "custom-signatures.json";
		ctl.set_custom_signatures(sigfile);
		{ // the Minecraft example (a service that is not a web service) next to a web signature
			std::ifstream mc(fs::path(PROCULUS_EXAMPLES_DIR) / "minecraft.json");
			std::stringstream text;
			text << mc.rdbuf();
			Json doc = Json::parse(text.str());
			doc["signatures"].push_back(Json::parse(R"({"id":"sim-welcome","name":"Welcome page","category":"other","interest":2,"threshold":0.5,
			  "signals":[{"weight":0.8,"match":{"field":"title","op":"equals","value":"Welcome"}}],
			  "examples":[{"name":"t","evidence":{"title":"Welcome"}},{"name":"n","evidence":{"title":"Other"},"expect":"no-match"}]})"));
			std::ofstream(sigfile) << doc.dump(2);
		}
		ctl.start(r);
		ctl.wait_idle();
		assert(ctl.status()["last"]["ok"] == true);
		const auto all = store.list();
		const RunRecord second = *store.load(all.back().id);
		bool found = false;
		for (const HostRecord& h : second.hosts)
			for (const ServiceRecord& s : h.services)
				if (s.web)
					for (const DetectionRecord& d : s.web->detections) found = found || d.id == "sim-welcome";
		assert(found);
		// the Minecraft servers: recognised from the port and what nmap said, with the version, and not mistaken for web services
		int minecraft = 0;
		for (const HostRecord& h : second.hosts)
			for (const ServiceRecord& s : h.services)
				if (s.port == 25565) {
					assert(s.web && s.web->status == 0 && s.web->detections.size() == 1 && s.web->detections[0].id == "minecraft-server");
					assert(s.web->detections[0].category == "other" && s.web->detections[0].confidence > 0.9 && !s.web->detections[0].version.empty());
					minecraft++;
				}
		assert(minecraft == 2);
		Api api(store);
		const Json found_services = api.services("latest", ServicesQuery{});
		bool listed = false;
		for (const Json& f : found_services["services"])
			if (f["port"] == 25565) {
				listed = true;
				assert(f["technologies"][0]["name"] == "Minecraft server" && f["technologies"][0]["category"] == "other" && f["score"].get<int>() > 0);
				for (const Json& reason : f["reasons"]) assert(reason.get<std::string>().find("unusual port") == std::string::npos);
			}
		assert(listed);
		assert(api.dashboard("latest")["web_services"].get<size_t>() < api.dashboard("latest")["run"]["services"].get<size_t>()); // not every service with a detection is a web service
	}

	// stopping works while the paced backend is "scanning"
	ctl.start(r);
	ctl.stop();
	ctl.wait_idle();
	assert(ctl.status()["last"]["ok"] == false && store.list().size() == 2);
	fs::remove_all(dir);
	return 0;
}
