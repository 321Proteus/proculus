#ifndef PROCULUS_NMAP_XML_HPP
#define PROCULUS_NMAP_XML_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace proculus {

struct ServiceInfo {
	std::string name, product, version, extrainfo, ostype, devicetype, method,
		tunnel;
	int confidence = 0; // nmap's 0-10 "conf" for the service match
	std::vector<std::string> cpes;
};

struct PortResult {
	uint16_t port = 0;
	std::string protocol; // "tcp" / "udp"
	std::string state; // "open", "closed", "filtered", ...
	std::string reason;
	bool has_service = false;
	ServiceInfo service;
};

struct HostResult {
	std::string address; // IPv4 text
	std::string state; // "up" / "down"
	std::string reason;
	std::vector<std::string> hostnames;
	std::vector<PortResult> ports;
};

struct NmapResult {
	std::string nmap_version;
	double elapsed_seconds = 0;
	int hosts_up = 0;
	int hosts_down = 0;
	std::vector<HostResult> hosts;
};

// Parses nmap's `-oX` output. Throws std::runtime_error on malformed XML or
// on XML containing entity declarations (never produced by nmap).
NmapResult parse_nmap_xml(const std::string& xml);

} // namespace proculus

#endif // PROCULUS_NMAP_XML_HPP
