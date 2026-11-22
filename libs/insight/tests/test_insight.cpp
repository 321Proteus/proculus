#undef NDEBUG
#include <cassert>

#include "proculus/insight/dashboard.hpp"

using namespace proculus;

static DetectionRecord det(const char* name, const char* category, int interest, double confidence, const char* version = "") {
	DetectionRecord d;
	d.id = name;
	d.name = name;
	d.category = category;
	d.interest = interest;
	d.confidence = confidence;
	d.version = version;
	return d;
}

static ServiceRecord svc(uint16_t port, const char* name, const char* product = "", const char* version = "") {
	ServiceRecord s;
	s.port = port;
	s.name = name;
	s.product = product;
	s.version = version;
	return s;
}

static ServiceRecord web(uint16_t port, std::vector<DetectionRecord> dets, const char* title = "") {
	ServiceRecord s = svc(port, "http", "nginx", "1.24.0");
	s.web = WebRecord{};
	s.web->title = title;
	s.web->detections = std::move(dets);
	return s;
}

static void test_scoring() {
	// nothing interesting
	Interest plain = score_service(svc(80, "http", "nginx", "1.24.0"));
	assert(plain.score == 0 && plain.reasons.empty() && std::string(interest_level(plain.score)) == "info");
	assert(score_service(web(80, {})).score == 0);
	assert(score_service(web(443, {det("nginx", "server", 0, 0.95)})).score == 0);

	// a strong admin-panel detection scales with interest and confidence
	Interest admin = score_service(web(443, {det("phpMyAdmin", "admin", 4, 0.9, "5.2.1")}));
	assert(admin.score == 72 && std::string(interest_level(admin.score)) == "high");
	assert(admin.reasons.size() == 1 && admin.reasons[0].find("phpMyAdmin 5.2.1") != std::string::npos);
	assert(score_service(web(443, {det("phpMyAdmin", "admin", 4, 0.5)})).score == 40);

	// more serious detections add a little (capped); the base is the strongest one
	Interest many = score_service(web(443, {det("a", "admin", 4, 0.9), det("b", "staging", 3, 0.9), det("c", "admin", 3, 0.9), det("d", "admin", 3, 0.9),
		det("e", "admin", 3, 0.9), det("low", "other", 1, 0.9)}));
	assert(many.score == 72 + 15);
	assert(many.reasons.size() == 4); // base + three that counted; the capped fourth and the minor one are not listed

	// an unusual port for a web service
	assert(score_service(web(9999, {})).score == 5);
	assert(score_service(web(8080, {})).score == 0);

	// exposed administration / databases, with or without a web probe
	Interest telnet = score_service(svc(23, "telnet"));
	assert(telnet.score == 40 && std::string(interest_level(telnet.score)) == "medium" && telnet.reasons[0].find("telnet") != std::string::npos);
	assert(score_service(svc(6379, "redis", "Redis key-value store")).score == 40);
	assert(score_service(svc(3389, "ms-wbt-server")).score == 35);
	assert(score_service(svc(22, "ssh", "OpenSSH", "8.2")).score == 0);

	// the score never exceeds 100
	assert(score_service(web(9999, {det("x", "admin", 5, 0.99), det("y", "admin", 5, 0.99), det("z", "admin", 5, 0.99), det("w", "admin", 5, 0.99),
		det("v", "admin", 5, 0.99)})).score == 100);

	assert(std::string(interest_level(70)) == "high" && std::string(interest_level(69)) == "medium" && std::string(interest_level(40)) == "medium");
	assert(std::string(interest_level(39)) == "low" && std::string(interest_level(15)) == "low" && std::string(interest_level(14)) == "info");
}

static RunRecord run(int64_t id, std::vector<HostRecord> hosts) {
	RunRecord r;
	r.id = id;
	r.source = "test";
	r.started = "2026-11-22T10:00:00Z";
	r.finished = "2026-11-22T10:10:00Z";
	r.hosts = std::move(hosts);
	return r;
}

static HostRecord host(const char* ip, std::vector<ServiceRecord> services, const char* name = "") {
	HostRecord h;
	h.ip = ip;
	h.hostname = name;
	h.services = std::move(services);
	return h;
}

static void test_findings_order() {
	RunRecord r = run(1, {host("10.0.0.20", {svc(80, "http")}), host("10.0.0.3", {svc(23, "telnet"), svc(22, "ssh", "OpenSSH", "8.2")}),
		host("10.0.0.9", {web(443, {det("phpMyAdmin", "admin", 4, 0.9)}, "phpMyAdmin")}, "db-admin"), host("10.0.0.100", {svc(21, "ftp")})});
	const auto f = list_findings(r);
	assert(f.size() == 5);
	assert(f[0].ip == "10.0.0.9" && f[0].score == 72 && f[0].title == "phpMyAdmin" && f[0].hostname == "db-admin" && f[0].detections == std::vector<std::string>{"phpMyAdmin"});
	assert(f[1].ip == "10.0.0.3" && f[1].port == 23 && f[1].score == 40 && f[1].level == "medium");
	assert(f[2].ip == "10.0.0.100" && f[2].score == 20 && f[2].level == "low");
	// equal scores: by numeric address (10.0.0.3 before 10.0.0.20), then port
	assert(f[3].ip == "10.0.0.3" && f[3].port == 22 && f[4].ip == "10.0.0.20");
	assert(f[3].service == "OpenSSH 8.2" && f[4].service == "http");
}

static void test_dashboard() {
	RunRecord before = run(1, {host("10.0.0.1", {web(80, {det("WordPress", "cms", 1, 0.95, "6.4")}, "Blog")}), host("10.0.0.2", {svc(23, "telnet")})});
	RunRecord after = run(2, {host("10.0.0.1", {web(80, {det("WordPress", "cms", 1, 0.95, "6.5"), det("PHP", "framework", 0, 0.9)}, "Blog")}),
		host("10.0.0.5", {web(8443, {det("Tomcat Manager", "admin", 5, 0.95)}, "Manager")})});
	const Dashboard d = build_dashboard(after, &before, 10);

	assert(d.run.id == 2 && d.run.hosts == 2 && d.run.services == 2 && d.previous && d.previous->id == 1);
	assert(d.web_services == 2 && d.detections == 3);
	assert(d.changes && d.changes->new_hosts == 1 && d.changes->gone_hosts == 1 && d.changes->web_changes >= 1);
	assert(d.levels.size() == 4 && d.levels[0].first == "high" && d.levels[0].second == 1);
	size_t total = 0;
	for (const auto& l : d.levels) total += l.second;
	assert(total == 2);
	assert(d.categories.size() == 3 && d.categories[0].second == 1);
	assert(!d.technologies.empty() && d.technologies.size() <= 10);
	assert(d.top.size() == 2 && d.top[0].ip == "10.0.0.5" && d.top[0].score == 95);
	// services with score 0 are not "top findings"
	assert(build_dashboard(run(3, {host("10.0.0.1", {svc(22, "ssh")})}), nullptr).top.empty());

	// first run: no previous, no changes
	const Dashboard first = build_dashboard(before, nullptr, 1);
	assert(!first.previous && !first.changes && first.top.size() == 1);

	// an empty run is fine
	const Dashboard empty = build_dashboard(run(4, {}), nullptr);
	assert(empty.run.hosts == 0 && empty.top.empty() && empty.levels.size() == 4);
}

int main() {
	test_scoring();
	test_findings_order();
	test_dashboard();
	return 0;
}
