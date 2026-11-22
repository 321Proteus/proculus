#include "api.hpp"

#include <algorithm>

#include "compare.hpp"
#include "proculus/insight/dashboard.hpp"
#include "report.hpp"
#include "track.hpp"

namespace proculus {

namespace {

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

Json summary_json(const RunSummary& s) {
	return { { "id", s.id }, { "source", s.source }, { "started", s.started }, { "finished", s.finished }, { "hosts", s.hosts }, { "services", s.services } };
}

Json finding_json(const Finding& f) {
	return { { "ip", f.ip }, { "hostname", f.hostname }, { "port", f.port }, { "protocol", f.protocol }, { "service", f.service }, { "title", f.title },
		{ "score", f.score }, { "level", f.level }, { "reasons", f.reasons }, { "detections", f.detections } };
}

Json counts_json(const std::vector<std::pair<std::string, size_t>>& v, const char* key) {
	Json a = Json::array();
	for (const auto& [name, n] : v) a.push_back({ { key, name }, { "count", n } });
	return a;
}

int64_t parse_id(const std::string& s) {
	if (s.empty() || s.size() > 15 || s.find_first_not_of("0123456789") != std::string::npos) throw ApiError(400, "not a run number: " + s);
	return std::stoll(s);
}

} // namespace

RunRecord Api::load(const std::string& which) const {
	int64_t id;
	if (which == "latest") {
		const auto runs = store_.list();
		if (runs.empty()) throw ApiError(404, "no runs stored yet");
		id = runs.back().id;
	} else {
		id = parse_id(which);
	}
	auto run = store_.load(id);
	if (!run) throw ApiError(404, "no run " + std::to_string(id));
	return std::move(*run);
}

Json Api::runs() const {
	Json a = Json::array();
	const auto list = store_.list();
	for (auto it = list.rbegin(); it != list.rend(); ++it) a.push_back(summary_json(*it)); // newest first
	return a;
}

Json Api::dashboard(const std::string& which) const {
	const auto list = store_.list();
	if (list.empty()) return { { "empty", true } };

	const RunRecord latest = load(which);
	// the run before this one, whichever run that is
	std::optional<RunRecord> previous;
	for (size_t i = 0; i < list.size(); i++)
		if (list[i].id == latest.id && i > 0) previous = store_.load(list[i - 1].id);

	const Dashboard d = build_dashboard(latest, previous ? &*previous : nullptr, 10);
	Json j = { { "empty", false }, { "run", summary_json(d.run) }, { "previous", d.previous ? summary_json(*d.previous) : Json(nullptr) },
		{ "web_services", d.web_services }, { "detections", d.detections }, { "levels", counts_json(d.levels, "level") },
		{ "categories", counts_json(d.categories, "category") }, { "technologies", counts_json(d.technologies, "name") } };
	if (d.changes) {
		const ChangeCounts& c = *d.changes;
		j["changes"] = { { "new_hosts", c.new_hosts }, { "gone_hosts", c.gone_hosts }, { "new_services", c.new_services }, { "gone_services", c.gone_services },
			{ "changed_services", c.changed_services }, { "web_changes", c.web_changes } };
	} else {
		j["changes"] = nullptr;
	}
	j["top"] = Json::array();
	for (const Finding& f : d.top) j["top"].push_back(finding_json(f));
	return j;
}

Json Api::services(const std::string& which, const ServicesQuery& q) const {
	if (q.limit < 1 || q.limit > 500) throw ApiError(400, "limit must be 1..500");
	const RunRecord run = load(which);
	const std::string needle = lower(q.text);

	Json rows = Json::array();
	size_t matched = 0;
	for (const Finding& f : list_findings(run)) {
		if (f.score < q.min_score) continue;
		if (!needle.empty()) {
			std::string hay = lower(f.ip + " " + f.hostname + " " + f.service + " " + f.title + " " + std::to_string(f.port));
			for (const std::string& d : f.detections) hay += " " + lower(d);
			if (hay.find(needle) == std::string::npos) continue;
		}
		if (matched >= q.offset && rows.size() < q.limit) rows.push_back(finding_json(f));
		matched++;
	}
	return { { "run", run.id }, { "total", matched }, { "offset", q.offset }, { "limit", q.limit }, { "services", std::move(rows) } };
}

Json Api::diff(const std::string& before, const std::string& after) const {
	const RunRecord a = load(before), b = load(after);
	if (a.id == b.id) throw ApiError(400, "choose two different runs");
	ReportOptions o;
	o.json = true;
	o.all = true;
	return Json::parse(render_comparison(a, b, compare_runs(a, b), o));
}

Json Api::hosts() const {
	Tracker tracker;
	for (const RunSummary& s : store_.list()) {
		auto run = store_.load(s.id);
		if (!run) continue;
		try {
			tracker.apply(*run);
		} catch (const std::invalid_argument&) {
			// a run that cannot be placed in time (bad timestamp, duplicate host) is skipped, not fatal
		}
	}
	Json j = { { "runs_applied", tracker.runs_applied() } };
	Json counts = Json::object();
	for (HostState s : {HostState::New, HostState::Active, HostState::Flapping, HostState::Stale, HostState::Gone}) counts[to_string(s)] = tracker.count(s);
	j["counts"] = std::move(counts);

	Json attention = Json::array();
	for (const auto& [ip, h] : tracker.hosts()) {
		if (h.state != HostState::Flapping && h.state != HostState::Stale && h.state != HostState::Gone) continue;
		attention.push_back({ { "ip", h.ip }, { "hostname", h.hostname }, { "state", to_string(h.state) }, { "existence", h.existence },
			{ "sightings", h.sightings }, { "observations", h.observations }, { "last_run", h.last_run }, { "time_dependent", h.time_dependent } });
		if (attention.size() >= 100) break;
	}
	j["attention"] = std::move(attention);
	return j;
}

} // namespace proculus
