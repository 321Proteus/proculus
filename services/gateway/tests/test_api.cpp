#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>

#include "api.hpp"

using namespace proculus;
namespace fs = std::filesystem;

static ServiceRecord svc(uint16_t port, const char* name, const char* product = "", const char* version = "") {
	ServiceRecord s;
	s.port = port;
	s.name = name;
	s.product = product;
	s.version = version;
	return s;
}

static ServiceRecord admin_web(uint16_t port, const char* title) {
	ServiceRecord s = svc(port, "http", "nginx", "1.24.0");
	s.web = WebRecord{};
	s.web->title = title;
	DetectionRecord d;
	d.id = "phpmyadmin";
	d.name = "phpMyAdmin";
	d.category = "admin";
	d.interest = 4;
	d.confidence = 0.9;
	s.web->detections = {d};
	return s;
}

static HostRecord host(const char* ip, std::vector<ServiceRecord> services, const char* name = "") {
	HostRecord h;
	h.ip = ip;
	h.hostname = name;
	h.services = std::move(services);
	return h;
}

static RunRecord run(const char* started, std::vector<HostRecord> hosts) {
	RunRecord r;
	r.source = "test";
	r.started = started;
	r.finished = started;
	r.hosts = std::move(hosts);
	return r;
}

static bool fails(int status, const std::function<void()>& fn) {
	try {
		fn();
	} catch (const ApiError& e) {
		return e.status == status;
	}
	return false;
}

int main() {
	const fs::path dir = fs::temp_directory_path() / ("proculus_api_" + std::to_string(getpid()));
	fs::remove_all(dir);
	FileResultStore store(dir);
	Api api(store);

	// ---- nothing stored yet
	assert(api.runs().empty());
	assert(api.dashboard("latest")["empty"] == true);
	assert(fails(404, [&] { api.services("latest", {}); }));
	assert(fails(404, [&] { api.services("7", {}); }));
	assert(fails(400, [&] { api.services("seven", {}); }));
	assert(fails(400, [&] { api.services("../etc/passwd", {}); }));

	store.save(run("2026-11-22T10:00:00Z", {host("10.0.0.1", {svc(22, "ssh", "OpenSSH", "8.2")}), host("10.0.0.2", {svc(23, "telnet")}, "old-switch")}));
	store.save(run("2026-11-22T12:00:00Z", {host("10.0.0.1", {svc(22, "ssh", "OpenSSH", "8.2"), admin_web(443, "phpMyAdmin <script>alert(1)</script>")}, "db-admin"),
		host("10.0.0.9", {svc(6379, "redis")})}));

	// ---- runs, newest first
	const Json runs = api.runs();
	assert(runs.size() == 2 && runs[0]["id"] == 2 && runs[1]["id"] == 1 && runs[0]["hosts"] == 2 && runs[0]["services"] == 3);

	// ---- dashboard
	const Json d = api.dashboard("latest");
	assert(d["empty"] == false && d["run"]["id"] == 2 && d["previous"]["id"] == 1);
	assert(d["changes"]["new_hosts"] == 1 && d["changes"]["gone_hosts"] == 1 && d["changes"]["new_services"] == 1);
	assert(d["web_services"] == 1 && d["detections"] == 1);
	assert(d["levels"].size() == 4 && d["levels"][0]["level"] == "high" && d["levels"][0]["count"] == 1);
	assert(d["top"][0]["ip"] == "10.0.0.1" && d["top"][0]["score"] == 72 && d["top"][0]["detections"][0] == "phpMyAdmin");
	assert(d["top"][1]["ip"] == "10.0.0.9" && d["top"][1]["score"] == 40);
	// the first run has nothing to compare with
	const Json first = api.dashboard("1");
	assert(first["previous"].is_null() && first["changes"].is_null() && first["run"]["id"] == 1);
	// hostile page text is data: it comes back as an ordinary string, escaped by JSON
	assert(d["top"][0]["title"] == "phpMyAdmin <script>alert(1)</script>");

	// ---- services: filter, score, paging
	Json all = api.services("latest", {});
	assert(all["total"] == 3 && all["services"].size() == 3 && all["services"][0]["score"] == 72);
	ServicesQuery q;
	q.text = "REDIS";
	assert(api.services("2", q)["total"] == 1);
	q.text = "db-admin";
	assert(api.services("2", q)["total"] == 2); // both services of that host
	q.text = "phpmyadmin"; // detection, title and service text
	assert(api.services("2", q)["total"] == 1);
	q.text = "";
	q.min_score = 40;
	assert(api.services("2", q)["total"] == 2);
	q.min_score = 0;
	q.limit = 1;
	q.offset = 1;
	const Json page = api.services("2", q);
	assert(page["total"] == 3 && page["services"].size() == 1 && page["services"][0]["ip"] == "10.0.0.9");
	q.offset = 99;
	assert(api.services("2", q)["services"].empty());
	q.limit = 0;
	assert(fails(400, [&] { api.services("2", q); }));
	q.limit = 501;
	assert(fails(400, [&] { api.services("2", q); }));

	// ---- diff
	const Json diff = api.diff("1", "2");
	assert(diff["new_hosts"][0] == "10.0.0.9" && diff["gone_hosts"][0] == "10.0.0.2");
	assert(diff["new_services"][0]["port"] == 443 && diff["web_changes"].is_array());
	assert(fails(400, [&] { api.diff("1", "1"); }));
	assert(fails(404, [&] { api.diff("1", "9"); }));
	assert(api.diff("1", "latest")["after"] == 2);

	// ---- hosts over time
	const Json hosts = api.hosts();
	assert(hosts["runs_applied"] == 2 && hosts["counts"].contains("active") && hosts["counts"].contains("gone"));
	assert(hosts["attention"].is_array());

	fs::remove_all(dir);
	return 0;
}
