#include "demo.hpp"

#include <algorithm>
#include <deque>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>

#include "backend.hpp"
#include "job.hpp"
#include "planner.hpp"
#include "proculus/netutil/ipset.hpp"
#include "proculus/results/results.hpp"
#include "proculus/timing/rate.hpp"

namespace proculus {

namespace {

std::string ip_text(uint32_t ip) {
	char buf[PC_IP_STR_MAX];
	pc_ip_format(ip, buf);
	return buf;
}

std::string duration_text(double seconds) {
	const long long s = static_cast<long long>(seconds + 0.5);
	std::ostringstream o;
	if (s >= 3600) o << s / 3600 << "h";
	if (s >= 60)
		o << std::setw(s >= 3600 ? 2 : 1) << std::setfill('0') << s / 60 % 60
		  << "m";
	o << std::setw(s >= 60 ? 2 : 1) << std::setfill('0') << s % 60 << "s";
	return o.str();
}

double seconds_between(TimePoint a, TimePoint b) {
	return std::chrono::duration<double>(b - a).count();
}

// What one round learned: answering hosts and their open services.
struct Snapshot {
	std::map<uint32_t, std::map<uint16_t, std::string>>
		hosts; // ip -> port -> "product version"
};

struct Diff {
	size_t new_hosts = 0, gone_hosts = 0, new_services = 0, gone_services = 0,
		   changed_services = 0;
	std::vector<std::string> examples;
};

Diff compare(const Snapshot& before, const Snapshot& after) {
	Diff d;
	auto note = [&](const std::string& s) {
		if (d.examples.size() < 6) d.examples.push_back(s);
	};
	for (const auto& [ip, svcs] : after.hosts) {
		auto it = before.hosts.find(ip);

		if (it == before.hosts.end()) {
			d.new_hosts++;
			d.new_services += svcs.size();
			note("new host " + ip_text(ip));
			continue;
		}

		for (const auto& [port, desc] : svcs) {
			auto old = it->second.find(port);
			if (old == it->second.end()) {
				d.new_services++;
				note("new service " + ip_text(ip) + ":" + std::to_string(port) +
					" " + desc);
			} else if (old->second != desc) {
				d.changed_services++;
				note("changed " + ip_text(ip) + ":" + std::to_string(port) +
					"  " + old->second + " -> " + desc);
			}
		}

		for (const auto& [port, desc] : it->second) {
			if (!svcs.count(port)) {
				d.gone_services++;
				note("service gone " + ip_text(ip) + ":" +
					std::to_string(port) + " " + desc);
			}
		}
	}

	for (const auto& [ip, svcs] : before.hosts) {
		if (!after.hosts.count(ip)) {
			d.gone_hosts++;
			d.gone_services += svcs.size();
			note("host gone " + ip_text(ip));
		}
	}

	return d;
}

// Cuts a chunk into two halves (by address count).
std::pair<Chunk, Chunk> split(const Chunk& c) {
	IpSet all;
	all.add_list(c.cidrs);
	const uint64_t half = c.count / 2;
	IpSet a = all.slice(0, half), b = all.slice(half, c.count - half);
	Chunk x = c, y = c;

	x.count = half;
	x.cidrs = a.format(',');
	y.count = c.count - half;
	y.offset = c.offset + half;
	y.cidrs = b.format(',');

	return { x, y };
}

// Runs one scan round on a virtual clock.
class Round {
public:
	Round(const DemoConfig& cfg, const Schedule& sched, const JobLimits& limits,
		SimBackend& backend, std::ostream& out)
		: cfg_(cfg), sched_(sched), limits_(limits), backend_(backend),
		  out_(out) {}

	// Executes all `chunks` of `stage`; the answers are passed to `collect`.
	template <class Collect>
	void execute(Stage stage, const std::vector<Chunk>& planned,
		RateEstimator& rate, Collect collect) {
		std::deque<Chunk> queue(planned.begin(), planned.end());

		for (int guard = 0; !queue.empty(); guard++) {
			if (guard > 1000000)
				throw std::runtime_error("scan made no progress");
			const size_t w = static_cast<size_t>(
				std::min_element(free_at.begin(), free_at.end()) -
				free_at.begin());
			const TimePoint t = free_at[w];
			const Chunk chunk = queue.front();

			const double estimate =
				rate.estimate_seconds(chunk.count).value_or(0);

			if (!can_start_chunk(t, deadline, estimate)) {
				if (t <= window_open) {
					// Not even a whole, fresh window is enough for this chunk
					// at the measured speed: cut it in half and try the halves.
					if (chunk.count <= 1)
						throw std::runtime_error(
							"a single address takes longer than the scan "
							"window; use a longer window");
					auto [first, second] = split(chunk);
					queue.pop_front();
					queue.push_front(second);
					queue.push_front(first);
					report.splits++;

					say("  chunk of " + std::to_string(chunk.count) +
						" (est. " + duration_text(estimate) +
						") is too big for a window at the measured speed: "
						"split in two");
					continue;
				}

				pause(t,
					"next chunk (" + std::to_string(chunk.count) + ", est. " +
						duration_text(estimate) +
						") would not finish before the window closes");
				continue;
			}

			ScanJob job;
			job.stage = stage;
			job.targets = chunk.cidrs;
			NmapCommand cmd =
				build_command(job, limits_); // the usual safety gate
			NmapResult result = backend_.run(cmd, job);
			const TimePoint end = t +
				std::chrono::duration_cast<Seconds>(
					std::chrono::duration<double>(result.elapsed_seconds));

			if (end > deadline) {
				// The window closed while this chunk was running: it is cut off
				// and retried. What it managed to do before that still tells us
				// the scan speed.
				const double ran = std::max(1.0, seconds_between(t, deadline));
				const double fraction =
					std::min(1.0, ran / std::max(result.elapsed_seconds, 1e-9));
				rate.record(std::max<uint64_t>(1,
								static_cast<uint64_t>(fraction *
									static_cast<double>(chunk.count))),
					ran);
				report.cancelled_chunks++;
				free_at[w] = deadline;
				say("  " + format_time(deadline) + "  worker " +
					std::to_string(w + 1) + ": chunk of " +
					std::to_string(chunk.count) +
					" cut off by the closing window, will retry");
				continue;
			}

			rate.record(chunk.count, result.elapsed_seconds);
			free_at[w] = end;
			report.chunks++;
			report.addresses += chunk.count;
			finished = std::max(finished, end);
			collect(result);
			queue.pop_front();
		}
	}

	void begin(TimePoint start, TimePoint window_end) {
		free_at.assign(cfg_.workers, start);
		window_open = start;
		deadline = window_end;
		finished = start;
	}

	// All workers stop; the run resumes when the scheduler's next window opens.
	void pause(TimePoint t, const std::string& why) {
		RunState st;
		st.phase = RunPhase::Paused;
		// Workers stop when the window closes, even if it is still open now:
		// ask the scheduler what happens from that moment, which is the next
		// window.
		t = std::max(t, deadline);
		Decision d = decide(sched_, st, t);
		while (d.action == Action::Wait) {
			if (!d.at)
				throw std::runtime_error(
					"no further scan window: the schedule is disabled");
			t = *d.at;
			d = decide(sched_, st, t);
		}
		report.pauses++;
		say("  " + format_time(deadline) + "  paused: " + why);
		say("  " + format_time(t) + "  resumed in the next window");
		std::fill(free_at.begin(), free_at.end(), t);
		window_open = t;
		deadline = *d.deadline;
	}

	void say(const std::string& s) {
		if (!cfg_.quiet) out_ << s << "\n";
	}

	RoundReport report;
	std::vector<TimePoint> free_at;
	TimePoint window_open; // when the current window opened (or the round began
						   // in it)
	TimePoint deadline;
	TimePoint finished;

private:
	const DemoConfig& cfg_;
	const Schedule& sched_;
	const JobLimits& limits_;
	SimBackend& backend_;
	std::ostream& out_;
};

} // namespace

std::vector<RoundReport> run_demo(const DemoConfig& cfg, std::ostream& out) {
	if (cfg.rounds < 1) throw std::invalid_argument("rounds must be >= 1");
	if (cfg.workers < 1) throw std::invalid_argument("workers must be >= 1");

	Schedule sched;
	parse_window(cfg.window, sched);
	sched.interval = cfg.interval;
	sched.min_start_remaining = Seconds(10);
	validate(sched);

	std::unique_ptr<ResultStore> store;
	if (!cfg.store_dir.empty())
		store = std::make_unique<FileResultStore>(cfg.store_dir);

	SimNetwork net = SimNetwork::generate(cfg.seed, cfg.networks, cfg.density);
	SimBackend backend(net, cfg.speed);

	JobLimits limits;
	limits.scope = cfg.networks;
	limits.allowed_ports = cfg.allowed_ports;

	IpSet space;
	space.add_list(cfg.networks);
	const uint64_t address_count = space.count();

	auto say = [&](const std::string& s) {
		if (!cfg.quiet) out << s << "\n";
	};
	say("Proculus demo: emulated network with " +
		std::to_string(address_count) + " addresses, " +
		std::to_string(net.host_count()) + " hosts; " +
		std::to_string(cfg.workers) + " workers");
	say("scan window " + cfg.window + " UTC, at most every " +
		duration_text(static_cast<double>(cfg.interval.count())) +
		"; time is virtual, so nothing waits");

	RateEstimator discovery_rate(0.4, cfg.assumed_discovery_rate);
	RateEstimator services_rate(0.4, cfg.assumed_services_rate);

	std::string target_lines; // one network per line, as the planner reads them
	{
		std::istringstream ss(cfg.networks);
		std::string item;
		while (std::getline(ss, item, ','))
			target_lines += item + "\n";
	}

	std::vector<RoundReport> reports;
	Snapshot previous;
	TimePoint now = parse_time(cfg.start);
	std::optional<TimePoint> last_started;

	for (int round = 1; round <= cfg.rounds; round++) {
		// Wait for the scheduler to allow a new run.
		RunState state;
		state.last_started = last_started;
		Decision d = decide(sched, state, now);
		while (d.action == Action::Wait) {
			if (!d.at)
				throw std::runtime_error(
					"the schedule never allows a run (disabled?)");
			now = *d.at;
			d = decide(sched, state, now);
		}
		last_started = now;
		backend.set_round(round);

		Round r(cfg, sched, limits, backend, out);
		r.report.round = round;
		r.report.started = now;
		r.begin(now, *d.deadline);
		say("");
		say("=== round " + std::to_string(round) + " ===  started " +
			format_time(now) + ", window closes " + format_time(*d.deadline));

		// --- stage 1: which addresses answer?
		PlannerConfig pc;
		pc.workers = cfg.workers;
		pc.chunk_seconds = cfg.chunk_seconds;
		pc.rate_hosts_per_sec = cfg.assumed_discovery_rate;
		pc.set_rate_from(discovery_rate);
		std::istringstream target_in(target_lines);
		Plan discovery_plan = make_plan(target_in, pc);
		r.say("  discovery: " + std::to_string(discovery_plan.chunks.size()) +
			" chunks of ~" + std::to_string(discovery_plan.chunk_size) +
			" addresses, spread over " +
			std::to_string(discovery_plan.chunks.empty()
					? 0
					: discovery_plan.chunks[0].networks) +
			" networks each (planned at " +
			std::to_string(static_cast<long long>(pc.rate_hosts_per_sec)) +
			" addresses/s per worker)");

		std::vector<uint32_t> live;
		std::map<uint32_t, std::string> names;
		r.execute(Stage::Discovery, discovery_plan.chunks, discovery_rate,
			[&](const NmapResult& res) {
				for (const HostResult& h : res.hosts) {
					uint32_t ip;
					if (pc_ip_parse(h.address.c_str(), &ip) != 0) continue;
					live.push_back(ip);
					if (!h.hostnames.empty()) names[ip] = h.hostnames[0];
				}
			});
		std::sort(live.begin(), live.end());
		r.say("  discovery done: " + std::to_string(live.size()) +
			" hosts answered; measured " +
			std::to_string(static_cast<long long>(discovery_rate.rate())) +
			" addresses/s per worker");

		// --- stage 2: what runs on the hosts that answered?
		std::map<uint32_t, HostRecord> records; // everything learned this round
		for (uint32_t ip : live) {
			// hosts that answered but expose nothing are still hosts
			records[ip].ip = ip_text(ip);
			records[ip].hostname = names[ip];
		}
		if (!live.empty()) {
			std::string live_lines;
			for (uint32_t ip : live)
				live_lines += ip_text(ip) + "\n";
			PlannerConfig sc = pc;
			sc.rate_hosts_per_sec = cfg.assumed_services_rate;
			sc.set_rate_from(services_rate);
			std::istringstream live_in(live_lines);
			Plan services_plan = make_plan(live_in, sc);
			r.say("  services: " + std::to_string(services_plan.chunks.size()) +
				" chunks of ~" + std::to_string(services_plan.chunk_size) +
				" hosts");

			r.execute(Stage::Services, services_plan.chunks, services_rate,
				[&](const NmapResult& res) {
					for (const HostResult& h : res.hosts) {
						uint32_t ip;
						if (pc_ip_parse(h.address.c_str(), &ip) != 0) continue;
						HostRecord& rec = records[ip];
						for (const PortResult& p : h.ports) {
							ServiceRecord sv;
							sv.port = p.port;
							sv.protocol = p.protocol;
							sv.state = p.state;
							sv.name = p.service.name;
							sv.product = p.service.product;
							sv.version = p.service.version;
							sv.extrainfo = p.service.extrainfo;
							sv.confidence = p.service.confidence;
							rec.services.push_back(std::move(sv));
						}
					}
				});
		}

		Snapshot snapshot;
		for (const auto& [ip, rec] : records) {
			auto& ports = snapshot.hosts[ip];
			for (const ServiceRecord& sv : rec.services)
				ports[sv.port] =
					sv.product + (sv.version.empty() ? "" : " " + sv.version);
		}

		// --- what changed?
		RoundReport& rep = r.report;
		rep.finished = r.finished;
		rep.existing_hosts = net.existing_hosts(round).size();
		rep.hosts_found = snapshot.hosts.size();
		for (const auto& kv : snapshot.hosts)
			rep.services_found += kv.second.size();
		rep.discovery_rate = discovery_rate.rate();
		rep.services_rate = services_rate.rate();
		if (round > 1) {
			Diff diff = compare(previous, snapshot);
			rep.new_hosts = diff.new_hosts;
			rep.gone_hosts = diff.gone_hosts;
			rep.new_services = diff.new_services;
			rep.gone_services = diff.gone_services;
			rep.changed_services = diff.changed_services;
			r.say("  changes since round " + std::to_string(round - 1) + ": +" +
				std::to_string(diff.new_hosts) + " hosts, -" +
				std::to_string(diff.gone_hosts) + " hosts, +" +
				std::to_string(diff.new_services) + " services, -" +
				std::to_string(diff.gone_services) + " services, " +
				std::to_string(diff.changed_services) + " changed");
			for (const auto& e : diff.examples)
				r.say("      " + e);
		}
		r.say("  round " + std::to_string(round) + " finished " +
			format_time(rep.finished) + " (took " +
			duration_text(seconds_between(rep.started, rep.finished)) + ", " +
			std::to_string(rep.pauses) + " pauses, " +
			std::to_string(rep.cancelled_chunks) + " chunks cut off)");
		r.say("  found " + std::to_string(rep.hosts_found) + " of " +
			std::to_string(rep.existing_hosts) +
			" existing hosts (flapping hosts can miss a round), " +
			std::to_string(rep.services_found) + " open services");

		if (store) {
			RunRecord run;
			run.source = "sim";
			run.started = format_time(rep.started);
			run.finished = format_time(rep.finished);
			run.addresses_scanned = rep.addresses;
			run.chunks = rep.chunks;
			run.pauses = rep.pauses;
			run.cancelled_chunks = rep.cancelled_chunks;
			for (auto& kv : records)
				run.hosts.push_back(std::move(kv.second));
			rep.run_id = store->save(std::move(run));
			r.say("  saved as run " + std::to_string(rep.run_id) + " in " +
				cfg.store_dir);
		}

		reports.push_back(rep);
		previous = std::move(snapshot);
		now = rep.finished;
	}
	return reports;
}

} // namespace proculus
