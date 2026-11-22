#include "compare.hpp"

#include <algorithm>
#include <map>
#include <set>

#include "proculus/netutil/cidr.h"

namespace proculus {

namespace {

using Key = std::pair<uint16_t, std::string>;

struct HostView {
	std::string ip;
	std::map<Key, std::string> services; // (port, protocol) -> description
	std::map<Key, const WebRecord*> web; // only for services that were probed (points into the run)
};

std::string describe(const ServiceRecord& s) {
	std::string d = s.product;
	if (!s.version.empty()) d += (d.empty() ? "" : " ") + s.version;
	return d.empty() ? s.name : d;
}

// Keyed by numeric address so output is in address order, not text order.
std::map<uint32_t, HostView> index(const RunRecord& run) {
	std::map<uint32_t, HostView> out;
	for (const HostRecord& h : run.hosts) {
		uint32_t ip;
		if (pc_ip_parse(h.ip.c_str(), &ip) != 0) continue; // not an address: cannot be compared
		HostView& v = out[ip];
		v.ip = h.ip;
		for (const ServiceRecord& s : h.services) {
			v.services[{s.port, s.protocol}] = describe(s);
			if (s.web) v.web[{s.port, s.protocol}] = &*s.web;
		}
	}
	return out;
}

std::string join(const std::vector<std::string>& v) {
	std::string out;
	for (const std::string& s : v) out += (out.empty() ? "" : ", ") + s;
	return out;
}

std::string cookie_names(const WebRecord& w) {
	std::set<std::string> names;
	for (const CookieRecord& c : w.cookies) names.insert(c.name);
	return join({names.begin(), names.end()});
}

std::string tls_problems(const WebRecord& w) {
	std::vector<std::string> p;
	if (!w.tls) return "";
	if (w.tls->self_signed) p.push_back("self-signed");
	if (w.tls->expired) p.push_back("expired");
	if (w.tls->not_yet_valid) p.push_back("not yet valid");
	if (w.tls->hostname_match && !*w.tls->hostname_match) p.push_back("name mismatch");
	return join(p);
}

std::string redirects_text(const WebRecord& w) { return join(w.redirects); }

std::string tech_text(const DetectionRecord& d) { return d.name + (d.version.empty() ? "" : " " + d.version); }

void compare_web(const std::string& ip, const Key& key, const WebRecord& a, const WebRecord& b, std::vector<WebChange>& out) {
	auto add = [&](const char* what, const std::string& before, const std::string& after) {
		if (before != after) out.push_back({ip, key.first, key.second, what, before, after});
	};
	add("status", a.status ? std::to_string(a.status) : "", b.status ? std::to_string(b.status) : "");
	add("title", a.title, b.title);
	add("server", a.server, b.server);
	add("redirect", redirects_text(a), redirects_text(b));
	add("cookies", cookie_names(a), cookie_names(b));
	add("tls certificate", a.tls ? a.tls->sha256 : "", b.tls ? b.tls->sha256 : "");
	add("tls problems", tls_problems(a), tls_problems(b));

	std::map<std::string, const DetectionRecord*> before, after;
	for (const DetectionRecord& d : a.detections) before[d.id] = &d;
	for (const DetectionRecord& d : b.detections) after[d.id] = &d;
	for (const auto& [id, d] : after) {
		auto it = before.find(id);
		if (it == before.end()) add("technology added", "", tech_text(*d));
		else if (it->second->version != d->version) add("technology version", tech_text(*it->second), tech_text(*d));
	}
	for (const auto& [id, d] : before)
		if (!after.count(id)) add("technology removed", tech_text(*d), "");
}

} // namespace

Comparison compare_runs(const RunRecord& before, const RunRecord& after) {
	Comparison c;
	c.before_id = before.id;
	c.after_id = after.id;
	const auto a = index(before), b = index(after);

	for (const auto& [ip, host] : b) {
		auto it = a.find(ip);
		if (it == a.end()) {
			c.new_hosts.push_back(host.ip);
			continue;
		}
		for (const auto& [key, desc] : host.services) {
			auto old = it->second.services.find(key);
			if (old == it->second.services.end())
				c.new_services.push_back({host.ip, key.first, key.second, "", desc});
			else if (old->second != desc)
				c.changed_services.push_back({host.ip, key.first, key.second, old->second, desc});
			if (auto now = host.web.find(key); now != host.web.end())
				if (auto was = it->second.web.find(key); was != it->second.web.end())
					compare_web(host.ip, key, *was->second, *now->second, c.web_changes);
		}
		for (const auto& [key, desc] : it->second.services)
			if (!host.services.count(key)) c.gone_services.push_back({host.ip, key.first, key.second, desc, ""});
	}
	for (const auto& [ip, host] : a)
		if (!b.count(ip)) c.gone_hosts.push_back(host.ip);
	return c;
}

} // namespace proculus
