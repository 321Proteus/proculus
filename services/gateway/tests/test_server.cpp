#undef NDEBUG
#include <httplib.h>
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <thread>

#include "server.hpp"
#include "sim_network.hpp"

using namespace proculus;
namespace fs = std::filesystem;

static ServiceRecord svc(uint16_t port, const char* name) {
	ServiceRecord s;
	s.port = port;
	s.name = name;
	return s;
}

int main() {
	const fs::path dir = fs::temp_directory_path() / ("proculus_server_" + std::to_string(getpid()));
	fs::remove_all(dir);
	FileResultStore store(dir);
	RunRecord r;
	r.source = "test";
	r.started = r.finished = "2026-11-22T10:00:00Z";
	HostRecord h;
	h.ip = "10.0.0.2";
	h.services = {svc(23, "telnet")};
	r.hosts = {h};
	store.save(r);

	ServerConfig cfg;
	cfg.port = 0;
	cfg.allowed_hosts = {"proculus.lan"};
	WebServer server(store, cfg);
	const int port = server.bind();
	std::thread t([&] { server.run(); });

	httplib::Client c("127.0.0.1", port);
	c.set_connection_timeout(3);
	c.set_read_timeout(3);

	// ---- it is an API, not a site: no pages, and the security headers are on every response
	assert(c.Get("/")->status == 404 && c.Get("/app.js")->status == 404 && c.Get("/index.html")->status == 404);
	auto health = c.Get("/api/health");
	assert(health && health->status == 200);
	assert(health->get_header_value("Content-Security-Policy") == "default-src 'none'; frame-ancestors 'none'");
	assert(health->get_header_value("X-Content-Type-Options") == "nosniff" && health->get_header_value("X-Frame-Options") == "DENY");
	assert(health->get_header_value("Content-Type").find("application/json") == 0);

	// ---- the API
	assert(health->body.find("true") != std::string::npos && health->get_header_value("Cache-Control") == "no-store");
	auto dash = c.Get("/api/dashboard");
	assert(dash && dash->status == 200 && Json::parse(dash->body)["run"]["id"] == 1);
	auto services = c.Get("/api/services?q=telnet&min_score=40&limit=10");
	assert(services && services->status == 200 && Json::parse(services->body)["total"] == 1);
	auto runs = c.Get("/api/runs");
	assert(runs && Json::parse(runs->body).size() == 1);
	assert(c.Get("/api/hosts")->status == 200);

	// ---- bad requests get clean errors
	auto bad_run = c.Get("/api/services?run=zzz");
	assert(bad_run && bad_run->status == 400 && Json::parse(bad_run->body).contains("error"));
	auto missing = c.Get("/api/services?run=42");
	assert(missing && missing->status == 404);
	assert(c.Get("/api/services?limit=abc")->status == 400);
	assert(c.Get("/api/services?limit=9999999999999")->status == 400);
	assert(c.Get("/api/diff?before=1&after=1")->status == 400);
	assert(c.Get("/api/nothing")->status == 404);
	assert(c.Get("/nothing.html")->status == 404);
	assert(c.Get("/api/services?q=" + std::string(500, 'a'))->status == 400);

	// ---- read-only
	assert(c.Post("/api/runs", "{}", "application/json")->status == 405);
	assert(c.Delete("/api/runs")->status == 405);
	assert(c.Put("/api/runs", "x", "text/plain")->status == 405);

	// ---- Host header checks (DNS rebinding)
	httplib::Headers evil = {{"Host", "attacker.example"}};
	auto rebound = c.Get("/api/runs", evil);
	assert(rebound && rebound->status == 403 && rebound->body.find("runs") == std::string::npos);
	assert(c.Get("/api/health", evil)->status == 403);
	assert(c.Get("/api/runs", httplib::Headers{{"Host", "localhost:8080"}})->status == 200);
	assert(c.Get("/api/runs", httplib::Headers{{"Host", "proculus.lan:8080"}})->status == 200); // --allow-host
	assert(c.Get("/api/runs", httplib::Headers{{"Host", "127.0.0.1.attacker.example"}})->status == 403);

	// ---- without scan control, the scan routes say so
	auto scan_off = c.Get("/api/scan");
	assert(scan_off && scan_off->status == 200 && Json::parse(scan_off->body)["enabled"] == false);
	httplib::Headers json_h = {{"Content-Type", "application/json"}};
	assert(c.Post("/api/scan", json_h, "{}", "application/json")->status == 403);
	assert(c.Post("/api/other", "{}", "application/json")->status == 405); // POST is only for the scan routes

	server.stop();
	t.join();

	// ---- with scan control: token, content type, validation, and the Host check still apply
	{
		SimNetwork net = SimNetwork::generate(7, "10.20.0.0/22", 0.05);
		ScanPolicy policy;
		policy.enabled = true;
		policy.scope = "10.20.0.0/22";
		policy.allowed_ports = "22,80,443";
		RunnerDeps base;
		base.deadline_watchdog = false;
		base.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
		FileResultStore sstore(dir / "scans");
		ScanController scans(policy, &sstore, base);
		ServerConfig scfg;
		scfg.port = 0;
		scfg.control_token = "test-token-0123456789abcdef";
		WebServer sserver(sstore, scfg, &scans);
		const int sport = sserver.bind();
		std::thread st([&] { sserver.run(); });
		httplib::Client sc("127.0.0.1", sport);
		sc.set_read_timeout(5);
		const std::string body = R"({"targets":["10.20.0.0/24"]})";
		const httplib::Headers good = {{"X-Proculus-Token", "test-token-0123456789abcdef"}};

		auto status = sc.Get("/api/scan");
		assert(status && Json::parse(status->body)["enabled"] == true && Json::parse(status->body)["policy"]["scope"] == "10.20.0.0/22");
		assert(sc.Post("/api/scan", body, "application/json")->status == 401);            // no token
		assert(sc.Post("/api/scan/stop", body, "application/json")->status == 401);
		assert(sc.Post("/api/scan", httplib::Headers{{"X-Proculus-Token", "nope"}}, body, "application/json")->status == 401);
		assert(sc.Post("/api/scan", good, body, "text/plain")->status == 415);              // not JSON: a plain form post cannot trigger it
		assert(sc.Post("/api/scan", good, body, "application/x-www-form-urlencoded")->status == 415);
		assert(sc.Post("/api/scan", good, "{not json", "application/json")->status == 400);
		assert(sc.Post("/api/scan", good, R"({"targets":["8.8.8.8"]})", "application/json")->status == 400); // outside the scope
		auto refused = sc.Post("/api/scan", good, R"({"targets":["8.8.8.8"]})", "application/json");
		assert(Json::parse(refused->body)["error"].get<std::string>().find("outside the allowed scope") != std::string::npos);
		assert(sc.Post("/api/scan", good, R"({"targets":["10.20.0.1"],"scope":"0.0.0.0/0"})", "application/json")->status == 400);
		assert(sc.Post("/api/scan", httplib::Headers{{"X-Proculus-Token", "test-token-0123456789abcdef"}, {"Host", "attacker.example"}}, body, "application/json")->status == 403);
		assert(sstore.list().empty()); // every refused request started nothing

		auto plan = sc.Post("/api/scan/plan", good, body, "application/json");
		assert(plan && plan->status == 200 && Json::parse(plan->body)["addresses"] == 256);
		auto started = sc.Post("/api/scan", good, body, "application/json");
		assert(started && started->status == 200);
		scans.wait_idle();
		assert(sstore.list().size() == 1);
		assert(Json::parse(sc.Get("/api/scan")->body)["last"]["ok"] == true);
		assert(sc.Post("/api/scan/stop", good, "{}", "application/json")->status == 200); // stopping when idle is harmless

		// guessing the token is limited
		for (int i = 0; i < 5; i++) sc.Post("/api/scan/stop", httplib::Headers{{"X-Proculus-Token", "guess"}}, "{}", "application/json");
		assert(sc.Post("/api/scan/stop", good, "{}", "application/json")->status == 429);

		sserver.stop();
		st.join();
	}

	fs::remove_all(dir);
	return 0;
}
