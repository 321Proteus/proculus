#include "result_json.hpp"

#include <cstdio>
#include <sstream>

namespace proculus {

std::string json_escape(const std::string& s) {
	std::string out;
	for (unsigned char c : s) {
		switch (c) {
		case '"':  out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default:
			if (c < 0x20) {
				char buf[8];
				std::snprintf(buf, sizeof buf, "\\u%04x", c);
				out += buf;
			} else {
				out += static_cast<char>(c);
			}
		}
	}
	return out;
}

static std::string q(const std::string& s) {
	return "\"" + json_escape(s) + "\"";
}

std::string to_json(const NmapResult& r) {
	std::ostringstream o;
	o << "{\n  \"nmap_version\": " << q(r.nmap_version) << ",\n"
	  << "  \"elapsed_seconds\": " << r.elapsed_seconds << ",\n"
	  << "  \"hosts_up\": " << r.hosts_up << ",\n"
	  << "  \"hosts_down\": " << r.hosts_down << ",\n"
	  << "  \"hosts\": [";
	for (size_t i = 0; i < r.hosts.size(); i++) {
		const HostResult& h = r.hosts[i];
		o << (i ? "," : "") << "\n    {\"address\": " << q(h.address)
		  << ", \"state\": " << q(h.state) << ", \"reason\": " << q(h.reason)
		  << ", \"hostnames\": [";
		for (size_t k = 0; k < h.hostnames.size(); k++)
			o << (k ? ", " : "") << q(h.hostnames[k]);
		o << "], \"ports\": [";
		for (size_t k = 0; k < h.ports.size(); k++) {
			const PortResult& p = h.ports[k];
			o << (k ? "," : "") << "\n      {\"port\": " << p.port
			  << ", \"protocol\": " << q(p.protocol)
			  << ", \"state\": " << q(p.state)
			  << ", \"reason\": " << q(p.reason);
			if (p.has_service) {
				const ServiceInfo& s = p.service;
				o << ", \"service\": {\"name\": " << q(s.name)
				  << ", \"product\": " << q(s.product)
				  << ", \"version\": " << q(s.version)
				  << ", \"extrainfo\": " << q(s.extrainfo)
				  << ", \"tunnel\": " << q(s.tunnel)
				  << ", \"method\": " << q(s.method)
				  << ", \"confidence\": " << s.confidence << ", \"cpes\": [";
				for (size_t c = 0; c < s.cpes.size(); c++)
					o << (c ? ", " : "") << q(s.cpes[c]);
				o << "]}";
			}
			o << "}";
		}
		o << (h.ports.empty() ? "" : "\n    ") << "]}";
	}
	o << (r.hosts.empty() ? "" : "\n  ") << "]\n}\n";
	return o.str();
}

} // namespace proculus
