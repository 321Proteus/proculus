#include "report.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <map>
#include <sstream>

namespace proculus {

namespace {

constexpr size_t kPreview = 15; // entries shown per list unless --all

std::string fixed(double v, int digits) {
	char buf[32];
	std::snprintf(buf, sizeof buf, "%.*f", digits, v);
	return buf;
}

// Scanned text is untrusted: keep control characters off the terminal.
std::string printable(std::string s) {
	for (char& c : s)
		if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = '?';
	return s;
}

std::string key(const ServiceChange& s) { return s.ip + ":" + std::to_string(s.port) + "/" + printable(s.protocol); }

template <class T, class F>
void list(std::ostringstream& o, const std::vector<T>& items, bool all, F line) {
	const size_t shown = all ? items.size() : std::min(items.size(), kPreview);
	for (size_t i = 0; i < shown; i++) o << "  " << line(items[i]) << "\n";
	if (shown < items.size()) o << "  ... and " << items.size() - shown << " more (use --all)\n";
}

Json service_change_json(const ServiceChange& s) {
	return { { "ip", s.ip }, { "port", s.port }, { "protocol", s.protocol }, { "before", s.before }, { "after", s.after } };
}

Json event_json(const Event& e) {
	Json j = { { "kind", to_string(e.kind) }, { "ip", e.ip } };
	if (e.port) j["port"] = e.port;
	if (!e.detail.empty()) j["detail"] = e.detail;
	return j;
}

size_t count(const RunUpdate& u, EventKind k) {
	return static_cast<size_t>(std::count_if(u.events.begin(), u.events.end(), [&](const Event& e) { return e.kind == k; }));
}

std::string describe_event(const Event& e) {
	std::string s = std::string(to_string(e.kind)) + " " + e.ip;
	if (e.port) s += ":" + std::to_string(e.port);
	if (!e.detail.empty()) s += "  " + printable(e.detail);
	return s;
}

} // namespace

std::string render_comparison(const RunRecord& before, const RunRecord& after, const Comparison& c, const ReportOptions& o) {
	if (o.json) {
		Json j = { { "before", before.id }, { "after", after.id } };
		j["new_hosts"] = c.new_hosts;
		j["gone_hosts"] = c.gone_hosts;
		for (const char* name : { "new_services", "gone_services", "changed_services" }) j[name] = Json::array();
		for (const auto& s : c.new_services) j["new_services"].push_back(service_change_json(s));
		for (const auto& s : c.gone_services) j["gone_services"].push_back(service_change_json(s));
		for (const auto& s : c.changed_services) j["changed_services"].push_back(service_change_json(s));
		j["web_changes"] = Json::array();
		for (const auto& w : c.web_changes)
			j["web_changes"].push_back({ { "ip", w.ip }, { "port", w.port }, { "protocol", w.protocol }, { "what", w.what }, { "before", w.before }, { "after", w.after } });
		return dump_json(j, 2) + "\n";
	}

	std::ostringstream out;
	out << "Run " << before.id << " (" << printable(before.started) << ")  ->  run " << after.id << " ("
	    << printable(after.started) << ")\n\n";
	out << "hosts: +" << c.new_hosts.size() << " new, -" << c.gone_hosts.size() << " gone\n";
	std::vector<std::pair<char, std::string>> hosts;
	for (const auto& h : c.new_hosts) hosts.push_back({ '+', h });
	for (const auto& h : c.gone_hosts) hosts.push_back({ '-', h });
	list(out, hosts, o.all, [](const auto& h) { return std::string(1, h.first) + " " + h.second; });

	out << "\nservices: +" << c.new_services.size() << " new, -" << c.gone_services.size() << " gone, "
	    << c.changed_services.size() << " changed (on hosts present in both runs)\n";
	list(out, c.changed_services, o.all,
		[](const ServiceChange& s) { return "~ " + key(s) + "  " + printable(s.before) + " -> " + printable(s.after); });
	list(out, c.new_services, o.all, [](const ServiceChange& s) { return "+ " + key(s) + "  " + printable(s.after); });
	list(out, c.gone_services, o.all, [](const ServiceChange& s) { return "- " + key(s) + "  " + printable(s.before); });

	out << "\nweb: " << c.web_changes.size() << " change(s) on services probed in both runs\n";
	list(out, c.web_changes, o.all, [](const WebChange& w) {
		return "~ " + w.ip + ":" + std::to_string(w.port) + "/" + w.protocol + "  " + w.what + ": " + (w.before.empty() ? "(none)" : "'" + printable(w.before) + "'") +
		       " -> " + (w.after.empty() ? "(none)" : "'" + printable(w.after) + "'");
	});
	return out.str();
}

std::string render_tracking(const std::vector<RunUpdate>& updates, const Tracker& t, const ReportOptions& o) {
	if (o.json) {
		Json runs = Json::array();
		for (const RunUpdate& u : updates) {
			Json events = Json::array();
			for (const Event& e : u.events) events.push_back(event_json(e));
			runs.push_back({ { "run", u.run_id }, { "when", format_time(u.when) }, { "hosts_seen", u.hosts_seen },
				{ "hosts_missed", u.hosts_missed }, { "events", std::move(events) } });
		}
		Json hosts = Json::array();
		for (const auto& kv : t.hosts()) {
			const HostTrack& h = kv.second;
			Json services = Json::array();
			for (const auto& sv : h.services)
				services.push_back({ { "port", sv.second.port }, { "protocol", sv.second.protocol },
					{ "state", to_string(sv.second.state) }, { "description", sv.second.description },
					{ "confidence", sv.second.confidence() } });
			hosts.push_back({ { "ip", h.ip }, { "hostname", h.hostname }, { "state", to_string(h.state) },
				{ "existence", h.existence }, { "sightings", h.sightings }, { "observations", h.observations },
				{ "first_run", h.first_run }, { "last_run", h.last_run }, { "time_dependent", h.time_dependent },
				{ "services", std::move(services) } });
		}
		Json j = { { "runs", std::move(runs) }, { "hosts", std::move(hosts) } };
		return dump_json(j, 2) + "\n";
	}

	std::ostringstream out;
	out << "Replayed " << updates.size() << " runs";
	if (!updates.empty()) out << " (" << updates.front().run_id << " .. " << updates.back().run_id << ")";
	out << "\n\n";

	out << std::left << std::setw(5) << "RUN" << std::setw(22) << "WHEN" << std::right << std::setw(6) << "SEEN"
	    << std::setw(8) << "MISSED" << std::setw(6) << "NEW" << std::setw(6) << "BACK" << std::setw(7) << "STALE"
	    << std::setw(6) << "GONE" << std::setw(6) << "FLAP" << std::setw(7) << "STABLE" << "   SERVICES +/~/-\n";
	for (const RunUpdate& u : updates) {
		out << std::left << std::setw(5) << u.run_id << std::setw(22) << format_time(u.when) << std::right << std::setw(6)
		    << u.hosts_seen << std::setw(8) << u.hosts_missed << std::setw(6) << count(u, EventKind::HostNew) << std::setw(6)
		    << count(u, EventKind::HostReturned) << std::setw(7) << count(u, EventKind::HostStale) << std::setw(6)
		    << count(u, EventKind::HostGone) << std::setw(6) << count(u, EventKind::HostFlapping) << std::setw(7)
		    << count(u, EventKind::HostStable) << "   " << count(u, EventKind::ServiceNew) << "/"
		    << count(u, EventKind::ServiceChanged) << "/" << count(u, EventKind::ServiceGone) << "\n";
		if (o.events) {
			const size_t shown = o.all ? u.events.size() : std::min(u.events.size(), kPreview);
			for (size_t i = 0; i < shown; i++) out << "      " << describe_event(u.events[i]) << "\n";
			if (shown < u.events.size()) out << "      ... and " << u.events.size() - shown << " more (use --all)\n";
		}
	}

	out << "\n" << t.hosts().size() << " hosts tracked: " << t.count(HostState::Active) << " active, "
	    << t.count(HostState::New) << " new, " << t.count(HostState::Flapping) << " flapping, " << t.count(HostState::Stale)
	    << " stale, " << t.count(HostState::Gone) << " gone\n";

	// Hosts whose state is uncertain deserve another look before the next scheduled run.
	std::vector<const HostTrack*> uncertain;
	for (const std::string& ip : t.reprobe_candidates()) uncertain.push_back(t.find(ip));
	if (!uncertain.empty()) {
		out << "\nworth probing again (flapping or stale):\n";
		const size_t shown = o.all ? uncertain.size() : std::min(uncertain.size(), kPreview);
		for (size_t i = 0; i < shown; i++) {
			const HostTrack& h = *uncertain[i];
			out << "  " << std::left << std::setw(16) << h.ip << std::setw(14) << printable(h.hostname) << std::setw(10)
			    << to_string(h.state) << "answered " << h.sightings << " of " << h.observations << " scans, existence "
			    << fixed(h.existence, 2) << "\n";
		}
		if (shown < uncertain.size()) out << "  ... and " << uncertain.size() - shown << " more (use --all)\n";
	}

	size_t time_dependent = 0;
	for (const auto& kv : t.hosts()) time_dependent += kv.second.time_dependent;
	if (time_dependent) out << "\n" << time_dependent << " hosts answer only at certain hours of the day\n";
	return out.str();
}

} // namespace proculus
