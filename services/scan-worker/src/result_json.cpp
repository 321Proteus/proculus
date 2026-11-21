#include "result_json.hpp"

#include <nlohmann/json.hpp>

namespace proculus {

std::string to_json(const NmapResult& r) {
	using Json = nlohmann::ordered_json;

	Json hosts = Json::array();
	for (const HostResult& h : r.hosts) {
		Json ports = Json::array();
		for (const PortResult& p : h.ports) {
			Json port = { { "port", p.port }, { "protocol", p.protocol }, { "state", p.state }, { "reason", p.reason } };
			if (p.has_service) {
				const ServiceInfo& s = p.service;
				port["service"] = { { "name", s.name }, { "product", s.product }, { "version", s.version },
					{ "extrainfo", s.extrainfo }, { "tunnel", s.tunnel }, { "method", s.method },
					{ "confidence", s.confidence }, { "cpes", s.cpes } };
			}
			ports.push_back(std::move(port));
		}
		hosts.push_back({ { "address", h.address }, { "state", h.state }, { "reason", h.reason },
			{ "hostnames", h.hostnames }, { "ports", std::move(ports) } });
	}

	Json doc = { { "nmap_version", r.nmap_version }, { "elapsed_seconds", r.elapsed_seconds },
		{ "hosts_up", r.hosts_up }, { "hosts_down", r.hosts_down }, { "hosts", std::move(hosts) } };
	// Banners come from the network and may hold invalid UTF-8: substitute it
	// rather than failing to report the scan.
	return doc.dump(2, ' ', false, Json::error_handler_t::replace) + "\n";
}

} // namespace proculus
