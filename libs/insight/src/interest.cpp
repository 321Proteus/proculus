#include "proculus/insight/interest.hpp"

#include <algorithm>
#include <cmath>

namespace proculus {

namespace {

struct Exposure {
	const char* needle; // matched in the nmap service name
	int points;
	const char* why;
};

// Remote administration, databases and legacy protocols reachable on the network.
const Exposure kExposures[] = {
	{"telnet", 40, "telnet is exposed (cleartext remote login)"},
	{"redis", 40, "redis is exposed"},
	{"mongo", 40, "mongodb is exposed"},
	{"memcache", 35, "memcached is exposed"},
	{"elastic", 35, "elasticsearch is exposed"},
	{"vnc", 35, "vnc is exposed (remote desktop)"},
	{"ms-wbt-server", 35, "rdp is exposed (remote desktop)"},
	{"rdp", 35, "rdp is exposed (remote desktop)"},
	{"microsoft-ds", 30, "smb is exposed"},
	{"netbios", 20, "netbios is exposed"},
	{"x11", 30, "x11 is exposed"},
	{"mysql", 25, "mysql is exposed"},
	{"postgres", 25, "postgresql is exposed"},
	{"ms-sql", 25, "sql server is exposed"},
	{"mssql", 25, "sql server is exposed"},
	{"oracle", 25, "oracle database is exposed"},
	{"nfs", 25, "nfs is exposed"},
	{"snmp", 20, "snmp is exposed"},
	{"ftp", 20, "ftp is exposed (usually cleartext)"},
	{"rpcbind", 15, "rpcbind is exposed"},
};

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

bool usual_web_port(uint16_t p) { return p == 80 || p == 443 || p == 8080 || p == 8443; }

} // namespace

Interest score_service(const ServiceRecord& s) {
	Interest out;
	int score = 0;

	if (s.web) {
		// the strongest detection sets the base; each other serious one adds a little
		struct Hit {
			int points;
			int interest;
			std::string reason;
		};
		std::vector<Hit> hits;
		for (const DetectionRecord& d : s.web->detections) {
			const int points = static_cast<int>(std::lround(d.interest * 20.0 * d.confidence));
			if (points <= 0) continue;
			hits.push_back({points, d.interest,
				d.name + (d.version.empty() ? "" : " " + d.version) + " (" + d.category + ", interest " + std::to_string(d.interest) + ")"});
		}
		std::stable_sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.points > b.points; });
		int extra = 0;
		for (size_t i = 0; i < hits.size(); i++) {
			if (i == 0) {
				score += hits[0].points;
				out.reasons.push_back(hits[0].reason);
			} else if (hits[i].interest >= 3 && extra < 15) {
				extra += 5;
				out.reasons.push_back(hits[i].reason);
			}
		}
		score += extra;
		if (s.web->status > 0 && !usual_web_port(s.port)) { // (status 0: a detection on a service that is not a web service)
			score += 5;
			out.reasons.push_back("web service on an unusual port (" + std::to_string(s.port) + ")");
		}
	}

	const std::string name = lower(s.name + " " + s.product);
	for (const Exposure& e : kExposures)
		if (name.find(e.needle) != std::string::npos) {
			score += e.points;
			out.reasons.push_back(e.why);
			break;
		}

	out.score = std::clamp(score, 0, 100);
	return out;
}

const char* interest_level(int score) {
	if (score >= 70) return "high";
	if (score >= 40) return "medium";
	if (score >= 15) return "low";
	return "info";
}

} // namespace proculus
