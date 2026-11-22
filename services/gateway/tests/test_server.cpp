#undef NDEBUG
#include <httplib.h>
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <thread>

#include "server.hpp"

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

	server.stop();
	t.join();
	fs::remove_all(dir);
	return 0;
}
