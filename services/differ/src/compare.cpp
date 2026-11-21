#include "compare.hpp"

#include <algorithm>
#include <map>

#include "proculus/netutil/cidr.h"

namespace proculus {

namespace {

using Key = std::pair<uint16_t, std::string>;

struct HostView {
	std::string ip;
	std::map<Key, std::string> services; // (port, protocol) -> description
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
		for (const ServiceRecord& s : h.services) v.services[{s.port, s.protocol}] = describe(s);
	}
	return out;
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
		}
		for (const auto& [key, desc] : it->second.services)
			if (!host.services.count(key)) c.gone_services.push_back({host.ip, key.first, key.second, desc, ""});
	}
	for (const auto& [ip, host] : a)
		if (!b.count(ip)) c.gone_hosts.push_back(host.ip);
	return c;
}

} // namespace proculus
