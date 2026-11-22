#include "simulate.hpp"

#include <algorithm>
#include <chrono>
#include <thread>

#include "proculus/netutil/cidr.h"

namespace proculus {

namespace {

// Runs the SimBackend, then takes a believable amount of real time over it, reporting progress as nmap does.
class PacedSimBackend : public ScanBackend {
public:
	PacedSimBackend(std::shared_ptr<Simulation> sim, std::atomic<bool>* cancel) : sim_(std::move(sim)), cancel_(cancel), inner_(sim_->net, SimSpeed{}) {
		inner_.set_round(std::max(1, sim_->rounds.load()));
	}

	NmapResult run(const NmapCommand& cmd, const ScanJob& job) override {
		NmapResult r = inner_.run(cmd, job);
		const double real = std::clamp(r.elapsed_seconds / sim_->speedup, 0.8, 6.0);
		const auto start = std::chrono::steady_clock::now();
		for (;;) {
			if (cancel_ && cancel_->load()) throw ScanFailed("scan was cancelled", false, true);
			const double f = std::min(1.0, std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() / real);
			if (job.on_progress) job.on_progress(std::min(1.0, f / 0.7), f < 0.7 ? 0.0 : (f - 0.7) / 0.3); // 70 % port scan, then identification
			if (f >= 1.0) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(80));
		}
		r.elapsed_seconds = real;
		return r;
	}

private:
	std::shared_ptr<Simulation> sim_;
	std::atomic<bool>* cancel_;
	SimBackend inner_;
};

// Made-up web servers: what the page says depends on the host's role in the emulated network.
class SimTransport : public HttpTransport {
public:
	explicit SimTransport(const Simulation* sim) : sim_(sim) {} // the simulation owns the transport and outlives it

	Exchange get(const Endpoint& ep, const std::string& path, const TransportLimits&) override {
		Exchange ex;
		uint32_t ip = 0;
		const SimHost* host = pc_ip_parse(ep.ip.c_str(), &ip) == 0 ? sim_->net.find(ip) : nullptr;
		HttpResponse r;
		r.version = "HTTP/1.1";
		std::string server = "nginx/1.24.0", title = "Welcome", extra;
		if (host) {
			for (const SimService& s : host->services)
				if (s.port == ep.port && !s.product.empty()) server = s.product + "/" + s.version;
			if (host->role == "apache") title = "Apache2 Ubuntu Default Page: It works";
			else if (host->role == "app") title = "Apache Tomcat";
			else if (host->role == "camera") title = "Network Camera - login";
			else if (host->role == "staging") title = "phpMyAdmin", extra = "<!-- phpMyAdmin staging -->";
			else if (ip % 3 == 0) title = "Blog", extra = "<meta name=\"generator\" content=\"WordPress 6.4.2\">";
		}
		r.headers = {{"Content-Type", "text/html"}, {"Server", server}};
		if (path == "/") {
			r.status = 200;
			r.reason = "OK";
			r.body = "<html><head><title>" + title + "</title>" + extra + "</head><body>" + title + "</body></html>";
		} else {
			r.status = 404;
			r.reason = "Not Found";
			r.body = "not found";
		}
		ex.response = r;
		return ex;
	}

private:
	const Simulation* sim_;
};

} // namespace

Simulation::Simulation(uint64_t seed, const std::string& nets, double density)
	: net(SimNetwork::generate(seed, nets, density)), networks(nets), allowed_ports("22,25,80,443,554,993,3306,5432,8080,8443"), transport(std::make_unique<SimTransport>(this)) {}

RunnerDeps Simulation::deps(const std::shared_ptr<Simulation>& sim) {
	RunnerDeps d;
	d.deadline_watchdog = false;
	d.make_backend = [sim](std::atomic<bool>& cancel) {
		sim->rounds++;
		return std::make_unique<PacedSimBackend>(sim, &cancel);
	};
	d.transport = sim->transport.get();
	return d;
}

} // namespace proculus
