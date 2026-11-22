#include "proculus/insight/dashboard.hpp"

#include <algorithm>
#include <map>

#include "compare.hpp"
#include "proculus/netutil/cidr.h"

namespace proculus {

namespace {

std::string describe(const ServiceRecord& s) {
	std::string d = s.product;
	if (!s.version.empty()) d += (d.empty() ? "" : " ") + s.version;
	return d.empty() ? s.name : d;
}

std::vector<std::pair<std::string, size_t>> sorted_counts(const std::map<std::string, size_t>& m, size_t limit = 0) {
	std::vector<std::pair<std::string, size_t>> v(m.begin(), m.end());
	std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
	if (limit && v.size() > limit) v.resize(limit);
	return v;
}

} // namespace

std::vector<Finding> list_findings(const RunRecord& run) {
	std::vector<Finding> out;
	for (const HostRecord& h : run.hosts)
		for (const ServiceRecord& s : h.services) {
			Finding f;
			f.ip = h.ip;
			f.hostname = h.hostname;
			f.port = s.port;
			f.protocol = s.protocol;
			f.service = describe(s);
			if (s.web) {
				f.title = s.web->title;
				for (const DetectionRecord& d : s.web->detections) {
					f.detections.push_back(d.name + (d.version.empty() ? "" : " " + d.version));
					f.technologies.push_back({d.name, d.version, d.category});
				}
			}
			const Interest in = score_service(s);
			f.score = in.score;
			f.level = interest_level(in.score);
			f.reasons = in.reasons;
			out.push_back(std::move(f));
		}
	auto numeric = [](const std::string& ip) {
		uint32_t v = 0;
		return pc_ip_parse(ip.c_str(), &v) == 0 ? v : 0xffffffffu;
	};
	std::stable_sort(out.begin(), out.end(), [&](const Finding& a, const Finding& b) {
		if (a.score != b.score) return a.score > b.score;
		const uint32_t x = numeric(a.ip), y = numeric(b.ip);
		if (x != y) return x < y;
		return a.port < b.port;
	});
	return out;
}

Dashboard build_dashboard(const RunRecord& latest, const RunRecord* previous, size_t top_n) {
	Dashboard d;
	d.run = summarize(latest);
	if (previous) {
		d.previous = summarize(*previous);
		const Comparison c = compare_runs(*previous, latest);
		d.changes = ChangeCounts{c.new_hosts.size(), c.gone_hosts.size(), c.new_services.size(), c.gone_services.size(), c.changed_services.size(),
			c.web_changes.size()};
	}

	std::map<std::string, size_t> categories, technologies, levels = {{"high", 0}, {"medium", 0}, {"low", 0}, {"info", 0}};
	for (const HostRecord& h : latest.hosts)
		for (const ServiceRecord& s : h.services) {
			if (!s.web) continue;
			d.web_services++;
			for (const DetectionRecord& det : s.web->detections) {
				d.detections++;
				categories[det.category]++;
				technologies[det.name]++;
			}
		}

	std::vector<Finding> all = list_findings(latest);
	for (const Finding& f : all) levels[f.level]++;
	for (const char* l : {"high", "medium", "low", "info"}) d.levels.emplace_back(l, levels[l]);
	d.categories = sorted_counts(categories);
	d.technologies = sorted_counts(technologies, 10);
	for (const Finding& f : all) {
		if (f.score <= 0 || d.top.size() >= top_n) break;
		d.top.push_back(f);
	}
	return d;
}

} // namespace proculus
