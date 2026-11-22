#include "dojo.hpp"

#include <algorithm>
#include <map>
#include <sstream>
#include <stdexcept>

#include "proculus/insight/dashboard.hpp"

namespace proculus {

namespace {

int level_rank(const std::string& level) {
	if (level == "high") return 3;
	if (level == "medium") return 2;
	if (level == "low") return 1;
	return 0;
}

const char* severity(const std::string& level) {
	if (level == "high") return "High";
	if (level == "medium") return "Medium";
	if (level == "low") return "Low";
	return "Info";
}

// The tags DefectDojo gets: lower case, no separators it would split on.
std::string tag(const std::string& s) {
	std::string t;
	for (unsigned char c : s) {
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') t += static_cast<char>(c);
		else if (c >= 'A' && c <= 'Z') t += static_cast<char>(c + 32);
	}
	return t.substr(0, 40);
}

} // namespace

int parse_dojo_min_level(const std::string& name) {
	if (name == "info") return 0;
	if (name == "low") return 1;
	if (name == "medium") return 2;
	if (name == "high") return 3;
	throw std::invalid_argument("unknown level '" + name + "' (use info, low, medium or high)");
}

std::string dojo_text(const std::string& value, size_t max) {
	std::string cut = value;
	if (cut.size() > max) {
		cut.resize(max);
		while (!cut.empty() && (static_cast<unsigned char>(cut.back()) & 0xC0) == 0x80) cut.pop_back(); // not in the middle of a character
		if (!cut.empty() && static_cast<unsigned char>(cut.back()) >= 0xC0) cut.pop_back();
		cut += "...";
	}
	std::string out;
	for (char ch : cut) {
		const unsigned char c = static_cast<unsigned char>(ch);
		if (c < 0x20 || c == 0x7f) out += ' ';
		else if (std::string("\\`*_{}[]()<>#+!|~&\"").find(ch) != std::string::npos) {
			out += '\\';
			out += ch;
		} else out += ch;
	}
	return out;
}

std::string render_dojo(const RunRecord& run, int min_level) {
	std::map<std::string, const ServiceRecord*> services;
	for (const HostRecord& h : run.hosts)
		for (const ServiceRecord& s : h.services)
			services[h.ip + ":" + std::to_string(s.port) + "/" + s.protocol] = &s;

	std::string date;
	if (run.finished.size() >= 10 && run.finished[4] == '-' && run.finished[7] == '-') date = run.finished.substr(0, 10);

	Json list = Json::array();
	for (const Finding& f : list_findings(run)) {
		if (level_rank(f.level) < min_level) continue;
		const std::string key = f.ip + ":" + std::to_string(f.port) + "/" + f.protocol;
		const ServiceRecord* sv = services.count(key) ? services[key] : nullptr;

		const std::string what = f.service.empty() ? "service" : f.service;
		std::ostringstream d;
		d << "**Host:** " << dojo_text(f.ip) << (f.hostname.empty() ? "" : " (" + dojo_text(f.hostname) + ")") << "  \n"
		  << "**Service:** " << f.port << "/" << dojo_text(f.protocol) << " " << dojo_text(what) << "  \n";
		if (!f.title.empty()) d << "**Page title:** " << dojo_text(f.title) << "  \n";
		d << "**Priority:** " << f.score << "/100 (" << f.level << ")  \n";
		if (!f.reasons.empty()) {
			d << "\n**Why it is ranked this way:**\n";
			for (const std::string& r : f.reasons) d << "* " << dojo_text(r) << "\n";
		}
		if (sv && sv->web) {
			for (const DetectionRecord& det : sv->web->detections) {
				d << "\n**Detected:** " << dojo_text(det.name) << (det.version.empty() ? "" : " " + dojo_text(det.version)) << " ("
				  << dojo_text(det.category) << ", confidence " << static_cast<int>(det.confidence * 100 + 0.5) << "%)\n";
				for (const std::string& e : det.evidence) d << "* " << dojo_text(e) << "\n";
			}
		}

		Json tags = Json::array({ "proculus" });
		for (const Technology& t : f.technologies) {
			const std::string c = tag(t.category);
			if (!c.empty() && std::find(tags.begin(), tags.end(), c) == tags.end()) tags.push_back(c);
		}

		Json endpoint = { { "host", f.ip }, { "port", f.port }, { "protocol", sv && sv->web && sv->web->tls ? "https" : (sv && sv->web ? "http" : f.protocol) } };
		Json item = { { "title", dojo_text(what, 100) + " on " + f.ip + ":" + std::to_string(f.port) },
			{ "severity", severity(f.level) }, { "description", d.str() }, { "unique_id_from_tool", key },
			{ "active", true }, { "verified", false }, { "tags", tags }, { "endpoints", Json::array({ endpoint }) } };
		if (!date.empty()) item["date"] = date;
		list.push_back(std::move(item));
	}
	return dump_json(Json{ { "findings", list } }, 2) + "\n";
}

} // namespace proculus
