#include "api.hpp"

#include <algorithm>
#include <map>

#include "compare.hpp"
#include "proculus/insight/dashboard.hpp"
#include "proculus/netutil/cidr.h"
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

// A scanned service as the user sees it: with their edits applied.
struct View {
	Finding f;
	std::string scan_hostname; // what the scan found, when an edit replaced it
	std::string status;        // ignored, false_positive, confirmed or ""
	bool edited = false;
	Json edit = nullptr;       // {"host": {...}, "service": {...}}
	std::string search;        // extra text the search looks in (notes, tags)
};

using EditMap = std::map<std::string, EditRecord>;

EditMap load_edits(EditStore* s) {
	EditMap m;
	if (s)
		for (auto& [k, r] : s->all()) m[k.text()] = std::move(r);
	return m;
}

View overlay(Finding f, const EditMap& edits) {
	View v;
	const auto host = edits.find(f.ip);
	const auto svc = edits.find(f.ip + ":" + std::to_string(f.port) + "/" + f.protocol);
	const EditRecord* h = host == edits.end() ? nullptr : &host->second;
	const EditRecord* s = svc == edits.end() ? nullptr : &svc->second;
	if (h && h->hostname) {
		v.scan_hostname = f.hostname;
		f.hostname = *h->hostname;
	}
	const EditRecord* priority_from = s && s->priority ? s : h && h->priority ? h : nullptr;
	if (priority_from) {
		f.score = *priority_from->priority;
		f.level = interest_level(f.score);
		f.reasons.insert(f.reasons.begin(), "priority set to " + std::to_string(f.score) + " by " + (priority_from->edited_by.empty() ? "a user" : priority_from->edited_by));
	}
	if (s && s->status) v.status = *s->status;
	else if (h && h->status) v.status = *h->status;
	if (h || s) {
		v.edited = true;
		v.edit = Json::object();
		for (const EditRecord* r : {h, s}) {
			if (!r) continue;
			v.search += " " + (r->note ? *r->note : "") + " ";
			for (const std::string& t : r->tags) v.search += t + " ";
			if (r->environment) v.search += *r->environment + " ";
		}
		if (h) v.edit["host"] = to_json(*h);
		if (s) v.edit["service"] = to_json(*s);
	}
	v.f = std::move(f);
	return v;
}

bool hidden(const View& v) { return v.status == "ignored" || v.status == "false_positive"; }

uint32_t numeric_ip(const std::string& ip) {
	uint32_t v = 0;
	return pc_ip_parse(ip.c_str(), &v) == 0 ? v : 0xffffffffu;
}

void sort_views(std::vector<View>& views) {
	std::stable_sort(views.begin(), views.end(), [](const View& a, const View& b) {
		if (a.f.score != b.f.score) return a.f.score > b.f.score;
		const uint32_t x = numeric_ip(a.f.ip), y = numeric_ip(b.f.ip);
		if (x != y) return x < y;
		return a.f.port < b.f.port;
	});
}

Json finding_json(const Finding& f) {
	return { { "ip", f.ip }, { "hostname", f.hostname }, { "port", f.port }, { "protocol", f.protocol }, { "service", f.service }, { "title", f.title },
		{ "score", f.score }, { "level", f.level }, { "reasons", f.reasons }, { "detections", f.detections } };
}

Json view_json(const View& v) {
	Json j = finding_json(v.f);
	j["status"] = v.status;
	if (!v.scan_hostname.empty()) j["scan_hostname"] = v.scan_hostname;
	if (v.edited) j["edit"] = v.edit;
	return j;
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
	const EditMap edits = load_edits(edits_);
	if (edits.empty()) {
		for (const Finding& f : d.top) j["top"].push_back(finding_json(f));
		return j;
	}
	// with edits: priorities and statuses as the user set them; ignored and false positives are left out
	std::vector<View> views;
	for (Finding& f : list_findings(latest)) views.push_back(overlay(std::move(f), edits));
	sort_views(views);
	std::map<std::string, size_t> levels = {{"high", 0}, {"medium", 0}, {"low", 0}, {"info", 0}};
	size_t shown = 0;
	for (const View& v : views) {
		if (hidden(v)) continue;
		levels[v.f.level]++;
		if (v.f.score > 0 && shown < 10) {
			j["top"].push_back(view_json(v));
			shown++;
		}
	}
	j["levels"] = Json::array();
	for (const char* l : {"high", "medium", "low", "info"}) j["levels"].push_back({{"level", l}, {"count", levels[l]}});
	return j;
}

Json Api::services(const std::string& which, const ServicesQuery& q) const {
	if (q.limit < 1 || q.limit > 500) throw ApiError(400, "limit must be 1..500");
	const RunRecord run = load(which);
	const std::string needle = lower(q.text);

	Json rows = Json::array();
	size_t matched = 0;
	const EditMap edits = load_edits(edits_);
	std::vector<View> views;
	for (Finding& f : list_findings(run)) views.push_back(overlay(std::move(f), edits));
	if (!edits.empty()) sort_views(views); // priorities may have changed the order
	for (const View& v : views) {
		const Finding& f = v.f;
		if (f.score < q.min_score) continue;
		if (q.hide_ignored && hidden(v)) continue;
		if (q.only_edited && !v.edited) continue;
		if (!needle.empty()) {
			std::string hay = lower(f.ip + " " + f.hostname + " " + v.scan_hostname + " " + f.service + " " + f.title + " " + std::to_string(f.port) + " " + v.status + " " + v.search);
			for (const std::string& d : f.detections) hay += " " + lower(d);
			if (hay.find(needle) == std::string::npos) continue;
		}
		if (matched >= q.offset && rows.size() < q.limit) rows.push_back(view_json(v));
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

Json Api::edits() const {
	if (!edits_) throw ApiError(404, "editing is not available on this server");
	Json a = Json::array();
	for (const auto& [k, r] : edits_->all()) {
		Json e = to_json(r);
		e["ip"] = k.ip;
		e["port"] = k.port;
		e["protocol"] = k.protocol;
		a.push_back(std::move(e));
	}
	return a;
}

Json Api::apply_edit(const EditKey& key, const Json& changes, const std::string& user) const {
	if (!edits_) throw ApiError(404, "editing is not available on this server");
	const EditResult r = edits_->apply(key, changes, user);
	return {{"removed", r.after.empty()}, {"edit", r.after.empty() ? Json(nullptr) : to_json(r.after)}};
}

Json Api::clear_edit(const EditKey& key) const {
	if (!edits_) throw ApiError(404, "editing is not available on this server");
	if (!valid_ip(key.ip)) throw ApiError(400, "not an IPv4 address");
	return {{"cleared", edits_->clear(key)}};
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
