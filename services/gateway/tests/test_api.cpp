#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>

#include "api.hpp"
#include "proculus/edits/edits.hpp"

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

	// ---- user edits: applied on top of the runs, never stored in them, and kept across scans
	{
		const fs::path edir = dir / "edits";
		auto edit_store = make_file_edit_store(edir);
		Api edited(store, edit_store.get());
		assert(edited.edits().empty() && !api.has_edits() && edited.has_edits());
		assert(fails(404, [&] { api.edits(); }) && fails(404, [&] { api.apply_edit({"10.0.0.1", 0, ""}, Json::object(), "x"); }));

		// before any edit the answers are the same as without an edit store
		assert(edited.services("latest", {}).dump() == api.services("latest", {}).dump());
		assert(edited.dashboard("latest")["top"].dump() == api.dashboard("latest")["top"].dump());

		// a host edit: a name, an environment, a note and a lower priority for its web service
		const Json made = edited.apply_edit({"10.0.0.1", 0, ""}, Json::parse(R"({"hostname":"db-admin.corp","environment":"staging","note":"owned by Team A","tags":["finance"],"priority":10})"), "ann");
		assert(made["removed"] == false && made["edit"]["edited_by"] == "ann");
		Json rows = edited.services("latest", {});
		Json web_row;
		for (const Json& r : rows["services"])
			if (r["ip"] == "10.0.0.1" && r["port"] == 443) web_row = r;
		assert(web_row["hostname"] == "db-admin.corp" && web_row["scan_hostname"] == "db-admin" && web_row["score"] == 10 && web_row["level"] == "info");
		assert(web_row["edit"]["host"]["note"] == "owned by Team A" && web_row["edit"]["host"]["tags"][0] == "finance" && !web_row["edit"].contains("service"));
		assert(web_row["reasons"][0].get<std::string>().find("priority set to 10 by ann") == 0);
		assert(web_row["status"] == "");
		// the scan data itself is untouched
		assert(store.load(2)->hosts[0].hostname == "db-admin");

		// the priority order changed: the edited service is no longer first
		assert(rows["services"][0]["ip"] != "10.0.0.1" || rows["services"][0]["port"] != 443);
		assert(edited.dashboard("latest")["top"][0]["ip"] == "10.0.0.9");

		// a service edit: false positive is hidden from the dashboard and can be hidden in the list
		edited.apply_edit({"10.0.0.9", 6379, "tcp"}, Json::parse(R"({"status":"false_positive"})"), "ann");
		const Json dash = edited.dashboard("latest");
		for (const Json& t : dash["top"]) assert(!(t["ip"] == "10.0.0.9" && t["port"] == 6379));
		size_t counted = 0;
		for (const Json& l : dash["levels"]) counted += l["count"].get<size_t>();
		assert(counted == 2); // three services, one of them left out
		ServicesQuery hide;
		hide.hide_ignored = true;
		assert(edited.services("latest", hide)["total"] == 2 && edited.services("latest", {})["total"] == 3);
		ServicesQuery only;
		only.only_edited = true;
		assert(edited.services("latest", only)["total"] == 3); // the host edit covers its two services, and the redis service has its own
		ServicesQuery text;
		text.text = "team a"; // notes and tags are searchable
		assert(edited.services("latest", text)["total"] == 2);
		text.text = "finance";
		assert(edited.services("latest", text)["total"] == 2);
		text.text = "db-admin.corp";
		assert(edited.services("latest", text)["total"] == 2);

		// edits survive later scans: a new run still shows them, and so does a host that is gone for a while
		store.save(run("2026-11-22T14:00:00Z", {host("10.0.0.1", {svc(22, "ssh", "OpenSSH", "8.2")}, "db-admin")}));
		const Json later = edited.services("latest", {});
		assert(later["total"] == 1 && later["services"][0]["hostname"] == "db-admin.corp" && later["services"][0]["edit"]["host"]["note"] == "owned by Team A");
		const Json all_edits = edited.edits();
		bool redis_edit = false;
		for (const Json& e : all_edits) redis_edit |= e["ip"] == "10.0.0.9" && e["port"] == 6379 && e["status"] == "false_positive"; // its host is not in the latest run any more
		assert(all_edits.size() == 2 && redis_edit);

		// removing every field removes the edit; clearing works; bad edits are refused
		assert(edited.apply_edit({"10.0.0.9", 6379, "tcp"}, Json::parse(R"({"status":null})"), "ann")["removed"] == true);
		assert(edited.clear_edit({"10.0.0.1", 0, ""})["cleared"] == true && edited.clear_edit({"10.0.0.1", 0, ""})["cleared"] == false && edited.edits().empty());
		bool refused = false;
		try {
			edited.apply_edit({"10.0.0.1", 0, ""}, Json::parse(R"({"status":"whatever"})"), "ann");
		} catch (const EditError&) {
			refused = true;
		}
		assert(refused);
		assert(fails(400, [&] { edited.clear_edit({"nope", 0, ""}); }));
	}

	fs::remove_all(dir);
	return 0;
}
