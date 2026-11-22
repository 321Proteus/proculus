#include "runner.hpp"

#include <algorithm>
#include <climits>
#include <deque>
#include <iomanip>
#include <mutex>
#include <ostream>
#include <set>
#include <sstream>
#include <thread>

#include "proculus/netutil/ipset.hpp"
#include "proculus/netutil/portset.hpp"
#include "proculus/sig/builtin.hpp"
#include "socket_transport_include.hpp"
#include "web_stage.hpp"

namespace proculus {

namespace {

std::string join_lines(const std::vector<std::string>& v) {
	std::string out;
	for (const std::string& s : v) out += s + "\n";
	return out;
}

std::string ip_text(uint32_t ip) {
	char buf[PC_IP_STR_MAX];
	pc_ip_format(ip, buf);
	return buf;
}

// Cuts a chunk into two halves (by address count).
std::pair<Chunk, Chunk> split_chunk(const Chunk& c) {
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
	return {x, y};
}

struct StageStats {
	int chunks = 0, cancelled = 0, splits = 0, retries = 0;
	uint64_t addresses = 0;
};

} // namespace

struct Runner::Impl {
	RunnerConfig cfg;
	RunnerDeps deps;
	Schedule schedule;
	bool scheduled = false;
	sig::SignatureSet signatures;
	std::unique_ptr<HttpTransport> own_transport;
	sig::SignatureSet custom_signatures; // the custom files only, for services that are not web services (see run_service_detections)

	std::atomic<bool> stop{false};
	std::atomic<bool> cancel{false};
	std::unique_ptr<ScanBackend> backend;
	RateEstimator discovery_rate, services_rate;

	// the scan window, if any
	std::atomic<long long> deadline_s{LLONG_MAX};
	TimePoint window_open;
	std::optional<TimePoint> last_started;
	int pauses = 0;

	Impl(RunnerConfig c, RunnerDeps d)
		: cfg(std::move(c)), deps(std::move(d)), discovery_rate(0.4, cfg.assumed_discovery_rate), services_rate(0.4, cfg.assumed_services_rate) {}

	ScanProgress prog;
	// keeps the last few answering hosts for the live view (called under the stage lock)
	void note_host(const std::string& ip, const std::vector<int>& ports = {}) {
		auto it = std::find_if(prog.recent.begin(), prog.recent.end(), [&](const LiveHost& h) { return h.ip == ip; });
		if (it == prog.recent.end()) {
			LiveHost h;
			h.ip = ip;
			h.ports = ports;
			prog.recent.push_back(std::move(h));
			if (prog.recent.size() > 16) prog.recent.erase(prog.recent.begin());
		} else if (!ports.empty()) {
			it->ports = ports;
		}
	}
	// the live entry of a host, or null when it has already scrolled out of the short list
	LiveHost* live_host(const std::string& ip) {
		auto it = std::find_if(prog.recent.begin(), prog.recent.end(), [&](const LiveHost& h) { return h.ip == ip; });
		return it == prog.recent.end() ? nullptr : &*it;
	}
	std::mutex web_progress_m; // the web stage reports from several threads
	void emit() {
		if (deps.on_progress) deps.on_progress(prog);
	}
	std::string stage_name;
	void set_stage(const std::string& name, size_t total = 0) {
		stage_name = name;
		prog.stage = name;
		prog.chunks_done = 0;
		prog.chunks_total = total;
		prog.pauses = pauses;
		emit();
	}

	void say(const std::string& s) {
		if (deps.log) *deps.log << s << "\n" << std::flush;
	}

	std::optional<TimePoint> deadline() const {
		const long long s = deadline_s.load();
		if (s == LLONG_MAX) return std::nullopt;
		return TimePoint(std::chrono::seconds(s));
	}
	void set_deadline(std::optional<TimePoint> t) {
		deadline_s.store(t ? std::chrono::duration_cast<std::chrono::seconds>(t->time_since_epoch()).count() : LLONG_MAX);
	}

	JobLimits limits() const {
		JobLimits l;
		l.scope = cfg.scope;
		l.allowed_ports = cfg.allowed_ports;
		l.max_rate = cfg.rate;
		l.allow_reserved = cfg.allow_reserved;
		return l;
	}

	PlannerConfig planner_config(double assumed_rate, const RateEstimator& est) const {
		PlannerConfig pc;
		pc.exclusions = cfg.exclusions;
		pc.workers = cfg.workers;
		pc.chunk_seconds = cfg.chunk_seconds;
		pc.rate_hosts_per_sec = assumed_rate;
		pc.set_rate_from(est);
		pc.allow_reserved = cfg.allow_reserved;
		return pc;
	}

	// ---- the scan window

	void begin_window() {
		if (!scheduled) return;
		RunState st;
		st.last_started = last_started;
		TimePoint now = deps.clock->now();
		Decision d = decide(schedule, st, now);
		while (d.action == Action::Wait) {
			if (!d.at) throw ScanError("the schedule never allows a run (is it disabled?)");
			say("  waiting for the scan window until " + format_time(*d.at));
			set_stage("waiting for the window");
			if (!deps.clock->sleep_until(*d.at, stop)) throw RunAborted();
			now = deps.clock->now();
			d = decide(schedule, st, now);
		}
		last_started = now;
		window_open = now;
		set_deadline(d.deadline);
		say("  scan window open until " + format_time(*d.deadline));
	}

	// All workers have stopped: wait for the next window and carry on there.
	void pause(const std::string& why) {
		const auto dl = deadline();
		if (!scheduled || !dl) return;
		RunState st;
		st.phase = RunPhase::Paused;
		st.last_started = last_started;
		TimePoint t = std::max(deps.clock->now(), *dl); // workers stop when the window closes
		Decision d = decide(schedule, st, t);
		while (d.action == Action::Wait) {
			if (!d.at) throw ScanError("no further scan window: the schedule is disabled");
			t = *d.at;
			d = decide(schedule, st, t);
		}
		pauses++;
		prog.pauses = pauses;
		prog.stage = "paused until the next window";
		emit();
		say("  paused: " + why + "; resuming at " + format_time(t));
		if (!deps.clock->sleep_until(t, stop)) throw RunAborted();
		window_open = deps.clock->now();
		set_deadline(d.deadline);
		prog.stage = stage_name;
		emit();
	}

	// ---- one stage: scan all chunks with the worker pool

	// `hosts_of` (services stage) names the hosts of a chunk, so their port progress can be shown while nmap works.
	StageStats run_stage(Stage stage, std::vector<Chunk> chunks, RateEstimator& rate, const std::function<void(const NmapResult&)>& collect,
		const std::function<std::vector<std::string>(const Chunk&)>& hosts_of = {}) {
		struct Item {
			Chunk chunk;
			int attempts = 0; // failed runs (not cancellations)
			int cancels = 0;  // times it was cut off by a closing window
		};
		std::deque<Item> queue;
		for (Chunk& c : chunks) queue.push_back({std::move(c), 0, 0});

		StageStats stats;
		std::mutex m;
		std::string fatal;
		set_stage(stage == Stage::Discovery ? "discovery" : "services", queue.size());

		auto job_for = [&](const Chunk& c) {
			ScanJob j;
			j.stage = stage;
			j.targets = c.cidrs;
			if (stage == Stage::Services) j.ports = cfg.ports;
			j.rate = cfg.rate;
			j.timing = cfg.timing;
			j.retries = cfg.retries;
			j.host_timeout_s = cfg.host_timeout_s;
			j.timeout_s = static_cast<int>(std::max(300.0, cfg.chunk_seconds * 6));
			j.version_detect = cfg.version_detect;
			j.privileged = cfg.privileged;
			return j;
		};

		for (;;) {
			{
				std::lock_guard<std::mutex> lock(m);
				if (queue.empty()) break;
			}
			if (stop.load()) throw RunAborted();

			const bool fresh = !scheduled || (deps.clock->now() - window_open) <= std::chrono::seconds(10);
			cancel.store(stop.load());
			bool wave_closed = false;
			size_t started = 0;
			std::atomic<bool> wave_done{false};

			std::thread watchdog;
			if (const auto dl = deadline(); dl && deps.deadline_watchdog) {
				watchdog = std::thread([&, dl] {
					if (deps.clock->sleep_until(*dl, wave_done)) cancel.store(true); // the window closed with the wave still running
				});
			}

			auto worker = [&] {
				for (;;) {
					Item item;
					{
						std::lock_guard<std::mutex> lock(m);
						if (stop.load() || wave_closed || !fatal.empty() || queue.empty()) return;
						const double estimate = rate.estimate_seconds(queue.front().chunk.count).value_or(0);
						if (const auto dl = deadline(); dl && !can_start_chunk(deps.clock->now(), *dl, estimate)) {
							wave_closed = true;
							return;
						}
						item = std::move(queue.front());
						queue.pop_front();
						started++;
					}

					try {
						ScanJob job = job_for(item.chunk);
						std::vector<std::string> chunk_hosts;
						if (stage == Stage::Services && hosts_of) chunk_hosts = hosts_of(item.chunk);
						const NmapCommand cmd = build_command(job, limits(), cfg.nmap_path); // the scope / port / rate gate
						int ports_total = 0;
						if (!chunk_hosts.empty()) {
							PortSet scanned_ports;
							scanned_ports.add_list(cmd.ports);
							ports_total = static_cast<int>(std::min<uint32_t>(scanned_ports.count(), 65536));
							{
								std::lock_guard<std::mutex> lock(m);
								for (const std::string& ip : chunk_hosts) {
									note_host(ip);
									if (LiveHost* h = live_host(ip)) {
										h->ports_total = ports_total;
										h->ports_done = 0;
									}
								}
								emit();
							}
							job.on_progress = [this, &m, chunk_hosts, ports_total](double scanned, double) {
								std::lock_guard<std::mutex> lock(m);
								for (const std::string& ip : chunk_hosts)
									if (LiveHost* h = live_host(ip)) h->ports_done = static_cast<int>(scanned * ports_total + 0.5);
								emit();
							};
						}
						const NmapCommand cmd2 = chunk_hosts.empty() ? cmd : build_command(job, limits(), cfg.nmap_path); // same command plus --stats-every
						const NmapResult result = backend->run(cmd2, job);
						std::lock_guard<std::mutex> lock(m);
						if (result.elapsed_seconds > 0) rate.record(item.chunk.count, result.elapsed_seconds);
						stats.chunks++;
						stats.addresses += item.chunk.count;
						collect(result);
						for (const std::string& ip : chunk_hosts) { // the chunk is finished: every port of its hosts has been scanned
							LiveHost* h = live_host(ip);
							if (!h) continue;
							if (h->ports_total == 0) h->ports_total = ports_total; // re-added by collect() after scrolling out of the list
							h->ports_done = h->ports_total;
							h->explored = std::min<int>(h->explored, static_cast<int>(h->ports.size()));
						}
						prog.chunks_done++;
						prog.pauses = pauses;
						emit();
					} catch (const ScanFailed& e) {
						std::lock_guard<std::mutex> lock(m);
						if (e.cancelled) {
							if (stop.load()) return;
							// cut off by the closing window: back to the queue; one that was cut off twice cannot fit and is split
							stats.cancelled++;
							item.cancels++;
							if (item.cancels >= 2 && item.chunk.count > 1) {
								auto [a, b] = split_chunk(item.chunk);
								stats.splits++;
							prog.chunks_total++;
								queue.push_front({b, 0, 0});
								queue.push_front({a, 0, 0});
								say("  a chunk of " + std::to_string(item.chunk.count) + " does not fit a window: split in two");
							} else if (item.cancels >= 4) {
								fatal = "one address cannot be scanned within a scan window; use a longer window";
							} else {
								queue.push_front(std::move(item));
							}
						} else if (e.timed_out && item.chunk.count > 1) {
							auto [a, b] = split_chunk(item.chunk);
							stats.splits++;
							prog.chunks_total++;
							queue.push_front({b, 0, 0});
							queue.push_front({a, 0, 0});
							say("  a chunk of " + std::to_string(item.chunk.count) + " timed out: split in two");
						} else if (++item.attempts >= cfg.max_attempts) {
							fatal = "chunk " + item.chunk.cidrs.substr(0, 80) + " failed " + std::to_string(item.attempts) + " times: " + e.what();
						} else {
							stats.retries++;
							say(std::string("  chunk failed (") + e.what() + "), retrying");
							queue.push_back(std::move(item));
						}
					} catch (const JobRejected& e) {
						std::lock_guard<std::mutex> lock(m);
						fatal = std::string("the scan was refused by the safety checks: ") + e.what();
					}
				}
			};
			std::vector<std::thread> pool;
			for (unsigned i = 0; i < std::max(1u, cfg.workers); i++) pool.emplace_back(worker);
			for (std::thread& t : pool) t.join();
			wave_done.store(true);
			if (watchdog.joinable()) watchdog.join();

			if (stop.load()) throw RunAborted();
			if (!fatal.empty()) throw ScanError(fatal);

			std::lock_guard<std::mutex> lock(m);
			if (queue.empty()) break;
			if (started == 0 && fresh) {
				// not even a whole window is enough for this chunk at the measured speed
				Item front = std::move(queue.front());
				queue.pop_front();
				if (front.chunk.count <= 1) throw ScanError("one address takes longer than the scan window; use a longer window");
				auto [a, b] = split_chunk(front.chunk);
				stats.splits++;
							prog.chunks_total++;
				queue.push_front({b, 0, 0});
				queue.push_front({a, 0, 0});
				say("  a chunk of " + std::to_string(front.chunk.count) + " is too big for a window at the measured speed: split in two");
			} else {
				// (the lock is held while pausing: no worker is running)
				pause("the next chunk would not finish before the window closes");
			}
		}
		return stats;
	}
};

Runner::Runner(RunnerConfig config, RunnerDeps deps) : impl_(std::make_unique<Impl>(std::move(config), std::move(deps))) {
	Impl& i = *impl_;
	if (!i.deps.clock) throw std::invalid_argument("a clock is required");
	if (i.cfg.scope.empty()) throw std::invalid_argument("no scope configured: refusing to scan");
	if (i.cfg.allowed_ports.empty()) throw std::invalid_argument("no allowed ports configured: refusing to scan");
	if (i.cfg.workers < 1 || i.cfg.workers > 64) throw std::invalid_argument("workers must be 1..64");
	if (i.cfg.rate < 1) throw std::invalid_argument("rate must be >= 1");
	if (i.cfg.max_attempts < 1) throw std::invalid_argument("max_attempts must be >= 1");
	if (!(i.cfg.chunk_seconds > 0)) throw std::invalid_argument("chunk_seconds must be > 0");
	if (i.cfg.targets.empty()) throw std::invalid_argument("no targets");
	if (i.cfg.schedule) {
		i.schedule = *i.cfg.schedule;
		validate(i.schedule);
		i.scheduled = true;
	}
	if (!i.deps.resolver) i.deps.resolver = system_resolve;
	if (!i.deps.make_backend) i.deps.make_backend = [](std::atomic<bool>& cancel) { return std::make_unique<NmapBackend>(&cancel); };
	i.backend = i.deps.make_backend(i.cancel);

	if (i.cfg.web.enabled) {
		if (!i.deps.transport) {
			i.own_transport = make_socket_transport();
			i.deps.transport = i.own_transport.get();
		}
		if (i.cfg.web.builtin_signatures) i.signatures = sig::builtin_signatures();
		std::string problems;
		for (const std::string& path : i.cfg.web.signature_paths) {
			std::error_code ec;
			const std::filesystem::path fp(path);
			const bool dir = std::filesystem::is_directory(fp, ec);
			sig::LoadResult r = dir ? i.signatures.add_directory(fp) : i.signatures.add_file(fp);
			if (dir) i.custom_signatures.add_directory(fp); else i.custom_signatures.add_file(fp); // the same files, kept apart from the built-in ones
			for (const sig::Diagnostic& d : r.diagnostics)
				if (d.level == sig::Diagnostic::Level::Error) problems += d.source + ": " + d.signature + ": " + d.where + ": " + d.message + "\n";
		}
		if (!problems.empty()) throw std::invalid_argument("custom signatures have errors:\n" + problems);
	}
}

Runner::~Runner() = default;

void Runner::request_stop() {
	impl_->stop.store(true);
	impl_->cancel.store(true);
}

std::optional<TimePoint> Runner::deadline() const { return impl_->deadline(); }

RoundReport Runner::run_round() {
	Impl& s = *impl_;
	RoundReport report;
	if (s.stop.load()) throw RunAborted();
	s.pauses = 0;

	s.prog = ScanProgress();
	s.set_stage("starting");
	s.begin_window();
	report.started = s.deps.clock->now();

	// ---- targets: resolve domains (every address must be in scope), then plan discovery
	IpSet scope;
	try {
		scope.add_list(s.cfg.scope);
	} catch (const std::invalid_argument&) {
		throw std::invalid_argument("invalid scope: " + s.cfg.scope);
	}

	std::vector<std::string> lines = s.cfg.targets;
	std::map<std::string, std::string> hostnames; // address -> the domain it came from
	{
		std::istringstream in(join_lines(lines));
		const Plan first = make_plan(in, s.planner_config(s.cfg.assumed_discovery_rate, s.discovery_rate));
		for (const LineError& e : first.errors) report.warnings.push_back("target line " + std::to_string(e.line) + " ignored (" + e.reason + "): " + e.text);
		for (const std::string& domain : first.domains) {
			const std::vector<std::string> ips = s.deps.resolver(domain);
			if (ips.empty()) {
				report.warnings.push_back("domain " + domain + " does not resolve");
				continue;
			}
			for (const std::string& ip : ips) {
				uint32_t v;
				if (pc_ip_parse(ip.c_str(), &v) != 0) continue;
				if (!scope.contains(v)) {
					report.warnings.push_back("domain " + domain + " resolves to " + ip + ", outside the allowed scope: not scanned");
					continue;
				}
				lines.push_back(ip);
				hostnames.emplace(ip, domain);
			}
		}
	}
	std::istringstream plan_in(join_lines(lines));
	Plan discovery_plan = make_plan(plan_in, s.planner_config(s.cfg.assumed_discovery_rate, s.discovery_rate));
	if (discovery_plan.total_addresses == 0) throw std::invalid_argument("nothing to scan: no targets left after exclusions and reserved addresses");

	// every target must lie inside the scope: refuse the round up front, not chunk by chunk
	{
		IpSet planned;
		for (const Chunk& c : discovery_plan.chunks) planned.add_list(c.cidrs);
		planned.subtract(scope);
		if (planned.count() > 0)
			throw std::invalid_argument(std::to_string(planned.count()) + " target address(es) outside the allowed scope, e.g. " + planned.slice(0, 1).format());
	}
	s.say("plan: " + std::to_string(discovery_plan.total_addresses) + " addresses in " + std::to_string(discovery_plan.chunks.size()) + " chunks, " +
		std::to_string(s.cfg.workers) + " workers x " + std::to_string(s.cfg.rate) + " packets/s");

	// ---- stage 1: which addresses answer?
	std::vector<uint32_t> live;
	StageStats total;
	auto add = [&](const StageStats& st) {
		total.chunks += st.chunks;
		total.cancelled += st.cancelled;
		total.splits += st.splits;
		total.retries += st.retries;
		total.addresses += st.addresses;
	};
	uint64_t scanned_addresses = 0;
	{
		StageStats st = s.run_stage(Stage::Discovery, discovery_plan.chunks, s.discovery_rate, [&](const NmapResult& r) {
			for (const HostResult& h : r.hosts) {
				uint32_t ip;
				if (h.state == "up" && pc_ip_parse(h.address.c_str(), &ip) == 0) {
					live.push_back(ip);
					s.note_host(h.address);
				}
			}
			s.prog.hosts_found = live.size();
		});
		scanned_addresses = st.addresses;
		add(st);
	}
	std::sort(live.begin(), live.end());
	live.erase(std::unique(live.begin(), live.end()), live.end());
	report.live_hosts = live.size();
	s.say("discovery: " + std::to_string(live.size()) + " hosts answered (" + std::to_string(static_cast<long long>(s.discovery_rate.rate())) +
		" addresses/s per worker measured)");

	// ---- stage 2: what runs there?
	std::map<uint32_t, HostRecord> records;
	for (uint32_t ip : live) {
		records[ip].ip = ip_text(ip);
		if (auto it = hostnames.find(records[ip].ip); it != hostnames.end()) records[ip].hostname = it->second;
	}
	if (!live.empty()) {
		std::string live_lines;
		for (uint32_t ip : live) live_lines += ip_text(ip) + "\n";
		std::istringstream live_in(live_lines);
		Plan services_plan = make_plan(live_in, s.planner_config(s.cfg.assumed_services_rate, s.services_rate));
		s.say("services: " + std::to_string(live.size()) + " hosts in " + std::to_string(services_plan.chunks.size()) + " chunks");
		add(s.run_stage(Stage::Services, services_plan.chunks, s.services_rate, [&](const NmapResult& r) {
			for (const HostResult& h : r.hosts) {
				uint32_t ip;
				if (pc_ip_parse(h.address.c_str(), &ip) != 0) continue;
				auto it = records.find(ip);
				if (it == records.end()) continue; // not a host discovery found: nothing to attach it to
				std::vector<int> open_ports;
				for (const PortResult& p : h.ports)
					if (p.state == "open") open_ports.push_back(p.port);
				s.note_host(h.address, open_ports);
				if (LiveHost* lh = s.live_host(h.address)) { // open ports that need no web probing are examined once nmap has identified them
					int web = 0;
					for (const PortResult& p : h.ports)
						if (p.state == "open" && web_service_scheme(p.service.name, static_cast<uint16_t>(p.port))) web++;
					lh->explored = s.cfg.web.enabled ? static_cast<int>(open_ports.size()) - web : static_cast<int>(open_ports.size());
				}
				for (const PortResult& p : h.ports) {
					if (p.state != "open") continue;
					ServiceRecord sv;
					sv.port = p.port;
					sv.protocol = p.protocol;
					sv.state = p.state;
					sv.name = p.service.name;
					sv.product = p.service.product;
					sv.version = p.service.version;
					sv.extrainfo = p.service.extrainfo;
					sv.confidence = std::clamp(p.service.confidence, 0, 10);
					it->second.services.push_back(std::move(sv));
				}
			}
		}, [&](const Chunk& c) { // the hosts of a chunk: the live addresses inside its CIDRs
			IpSet inside;
			inside.add_list(c.cidrs);
			std::vector<std::string> names;
			for (uint32_t ip : live)
				if (inside.contains(ip)) names.push_back(ip_text(ip));
			return names;
		}));
	}

	RunRecord run;
	run.source = "nmap";
	run.addresses_scanned = scanned_addresses;
	run.chunks = total.chunks;
	run.pauses = s.pauses;
	run.cancelled_chunks = total.cancelled;
	for (auto& [ip, rec] : records) {
		std::sort(rec.services.begin(), rec.services.end(), [](const ServiceRecord& a, const ServiceRecord& b) { return a.port < b.port; });
		report.services += rec.services.size();
		run.hosts.push_back(std::move(rec));
	}

	// ---- stage 3: web probing, with signatures
	if (s.cfg.web.enabled) {
		s.set_stage("web");
		const WebStageResult w = run_web_stage(run, s.cfg, *s.deps.transport, s.signatures, hostnames, s.stop, s.deps.log, [&s](const std::string& ip, uint16_t) {
			std::lock_guard<std::mutex> lock(s.web_progress_m);
			if (LiveHost* h = s.live_host(ip))
				if (h->explored < static_cast<int>(h->ports.size())) h->explored++;
			s.emit();
		});
		report.web_probed = w.probed;
		report.web_responding = w.responding;
		report.detections = w.detections + run_service_detections(run, s.custom_signatures);
		for (const std::string& warning : w.warnings) report.warnings.push_back(warning);
		if (s.stop.load()) throw RunAborted();
		if (!run.hosts.empty()) run.source = "nmap+web";
	}

	report.finished = s.deps.clock->now();
	run.started = format_time(report.started);
	run.finished = format_time(report.finished);
	report.addresses = scanned_addresses;
	report.chunks = total.chunks;
	report.pauses = s.pauses;
	report.cancelled_chunks = total.cancelled;
	report.splits = total.splits;
	report.retries = total.retries;
	report.discovery_rate = s.discovery_rate.rate();
	report.services_rate = s.services_rate.rate();

	s.set_stage("saving");
	if (s.deps.store) {
		report.run_id = s.deps.store->save(std::move(run));
		s.say("saved as run " + std::to_string(report.run_id));
	}
	s.set_stage("done");
	return report;
}

} // namespace proculus
