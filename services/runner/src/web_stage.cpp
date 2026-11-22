#include "web_stage.hpp"

#include <algorithm>
#include <mutex>
#include <thread>

#include "evidence.hpp"
#include "proculus/sig/engine.hpp"
#include "web_record.hpp"

namespace proculus {

WebStageResult run_web_stage(RunRecord& run, const RunnerConfig& cfg, HttpTransport& transport, const sig::SignatureSet& signatures,
	const std::map<std::string, std::string>& hostnames, const std::atomic<bool>& stop, std::ostream* log) {
	WebStageResult out;

	struct Task {
		size_t host, service;
		ProbeTarget target;
	};
	std::vector<Task> tasks;
	for (size_t hi = 0; hi < run.hosts.size(); hi++)
		for (size_t si = 0; si < run.hosts[hi].services.size(); si++) {
			const HostRecord& h = run.hosts[hi];
			const ServiceRecord& s = h.services[si];
			const auto tls = web_service_scheme(s.name, s.port);
			if (!tls) continue;
			ProbeTarget t(h.ip, s.port, *tls);
			if (auto it = hostnames.find(h.ip); it != hostnames.end()) t.host = it->second;
			t.service = {s.name, s.product, s.version, {}};
			if (!t.host.empty()) t.service.hostnames.push_back(t.host);
			tasks.push_back({hi, si, std::move(t)});
		}
	if (tasks.empty()) return out;

	const unsigned workers = std::max(1u, std::min<unsigned>(cfg.web.workers, static_cast<unsigned>(tasks.size())));
	ProbeLimits limits;
	limits.scope = cfg.scope;
	limits.allowed_ports = cfg.allowed_ports;
	limits.allow_reserved = cfg.allow_reserved;
	limits.max_requests_per_second = std::max(0.5, cfg.web.requests_per_second / workers); // the total stays within the configured rate
	if (cfg.web.max_paths > 0) limits.probe_paths = signatures.required_paths(cfg.web.max_paths);

	std::atomic<size_t> next{0};
	std::mutex m;
	auto work = [&] {
		HttpProber prober(transport, limits);
		for (;;) {
			const size_t i = next.fetch_add(1);
			if (i >= tasks.size() || stop.load()) return;
			Task& t = tasks[i];
			try {
				const HttpObservation o = prober.probe(t.target);
				std::vector<sig::Detection> found;
				if (o.status > 0) found = sig::evaluate(signatures, to_evidence(o));
				std::lock_guard<std::mutex> lock(m);
				out.probed++;
				if (o.status > 0) {
					out.responding++;
					out.detections += found.size();
					run.hosts[t.host].services[t.service].web = to_web_record(o, found); // each task owns its element
				}
			} catch (const ProbeRefused& e) {
				std::lock_guard<std::mutex> lock(m);
				out.warnings.push_back(t.target.ip + ":" + std::to_string(t.target.port) + " not probed: " + e.what());
			}
		}
	};
	std::vector<std::thread> pool;
	for (unsigned i = 0; i < workers; i++) pool.emplace_back(work);
	for (std::thread& t : pool) t.join();
	if (log) *log << "  web: " << out.responding << " of " << out.probed << " web services answered, " << out.detections << " detections\n";
	return out;
}

} // namespace proculus
