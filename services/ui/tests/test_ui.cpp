#undef NDEBUG
#include <httplib.h>

#include <cassert>
#include <thread>

#include "ui_server.hpp"

using namespace proculus;

static void test_targets() {
	for (const char* ok : {"/api/health", "/api/runs", "/api/services?q=nginx&min_score=40&limit=10", "/api/diff?before=1&after=latest", "/api/a/b-c_d",
	                        "/api/services?q=a%20b%2Fc"})
		assert(is_proxyable_target(ok));
	for (const char* bad : {"", "/", "/api", "/api/", "/api//runs", "/api/runs/", "/api/../etc/passwd", "/api/%2e%2e/x", "/api/runs.json", "/API/runs", "/apix/runs",
	                         "http://evil.example/api/runs", "//evil.example/api/runs", "/api/runs?q=a b", "/api/runs?q=<script>", "/api/runs?q=\"x\"",
	                         "/api/runs\r\nX-Evil: 1", "/api/runs#frag", "/api/runs?q=a;b", "/api/runs?q=a\\b", "/static/app.js"})
		assert(!is_proxyable_target(bad));
	assert(!is_proxyable_target("/api/" + std::string(3000, 'a')));
	assert(is_postable_path("/api/scan") && is_postable_path("/api/scan/plan") && is_postable_path("/api/scan/stop") && is_postable_path("/api/scan/config"));
	for (const char* p : {"/api/edits", "/api/edits/clear", "/api/login", "/api/setup", "/api/logout", "/api/users", "/api/users/update", "/api/roles", "/api/roles/delete"}) assert(is_postable_path(p));
	for (const char* no : {"/api/runs", "/api/scan/", "/api/scan/x", "/api/scans", "/api", "/", "/api/scan/stop/", "/api/audit", "/api/me", "/api/users/", "/api/users/delete", "/api/edits/", "/api/edits/other"}) assert(!is_postable_path(no));
}

int main() {
	test_targets();

	// ---- a fake gateway
	httplib::Server fake;
	std::string last_cookie = "unset", last_host, last_accept;
	std::string last_session = "unset";
	fake.Get("/api/echo", [&](const httplib::Request& req, httplib::Response& res) {
		last_session = req.has_header("X-Proculus-Session") ? req.get_header_value("X-Proculus-Session") : "none";
		last_cookie = req.has_header("Cookie") ? req.get_header_value("Cookie") : "none";
		last_host = req.get_header_value("Host");
		last_accept = req.get_header_value("Accept");
		res.set_content("{\"q\":\"" + req.get_param_value("q") + "\",\"n\":" + req.get_param_value("n") + "}", "application/json; charset=utf-8");
		res.set_header("Set-Cookie", "secret=1"); // must not reach the browser
	});
	fake.Get("/api/missing", [](const httplib::Request&, httplib::Response& res) { res.status = 404; res.set_content("{\"error\":\"no run 7\"}", "application/json"); });
	fake.Get("/api/broken", [](const httplib::Request&, httplib::Response& res) { res.status = 500; res.set_content("{\"error\":\"internal error\"}", "application/json"); });
	fake.Get("/api/html", [](const httplib::Request&, httplib::Response& res) { res.set_content("<script>alert(1)</script>", "text/html"); });
	fake.Get("/api/redirect", [](const httplib::Request&, httplib::Response& res) { res.set_redirect("http://evil.example/"); });
	fake.Get("/api/big", [](const httplib::Request&, httplib::Response& res) { res.set_content(std::string(5000, 'x'), "application/json"); });
	std::string post_token = "unset", post_cookie = "unset", post_body, post_type;
	fake.Post("/api/scan", [&](const httplib::Request& req, httplib::Response& res) {
		post_token = req.has_header("X-Proculus-Token") ? req.get_header_value("X-Proculus-Token") : "none";
		post_cookie = req.has_header("Cookie") ? req.get_header_value("Cookie") : "none";
		post_body = req.body;
		post_type = req.get_header_value("Content-Type");
		if (post_token != "tok123") {
			res.status = 401;
			res.set_content("{\"error\":\"wrong or missing control token\"}", "application/json");
			return;
		}
		res.set_content("{\"started\":true}", "application/json");
	});
	fake.Post("/api/scan/stop", [&](const httplib::Request&, httplib::Response& res) { res.set_content("{\"stopped\":true}", "application/json"); });
	fake.Post("/api/echo", [&](const httplib::Request&, httplib::Response& res) { res.set_content("{\"must\":\"not be reachable\"}", "application/json"); });
	const int fake_port = fake.bind_to_any_port("127.0.0.1");
	std::thread fake_thread([&] { fake.listen_after_bind(); });

	UiConfig cfg;
	cfg.port = 0;
	cfg.api = {"127.0.0.1", fake_port};
	cfg.allowed_hosts = {"proculus.lan"};
	cfg.max_api_body = 1000;
	UiServer ui(cfg);
	const int port = ui.bind();
	std::thread ui_thread([&] { ui.run(); });

	httplib::Client c("127.0.0.1", port);
	c.set_connection_timeout(3);
	c.set_read_timeout(5);

	// ---- the pages, with the security headers
	auto page = c.Get("/");
	assert(page && page->status == 200 && page->body.find("<script src=\"/app.js\">") != std::string::npos);
	assert(page->get_header_value("Content-Type").find("text/html") == 0);
	assert(page->get_header_value("Content-Security-Policy").find("connect-src 'self'") != std::string::npos);
	assert(page->get_header_value("Content-Security-Policy").find("unsafe-inline") == std::string::npos);
	assert(page->get_header_value("X-Content-Type-Options") == "nosniff" && page->get_header_value("X-Frame-Options") == "DENY");
	auto js = c.Get("/app.js");
	assert(js && js->status == 200 && js->get_header_value("Content-Type").find("javascript") != std::string::npos);
	// the settings import has a fixed scheme, and the placeholder tab for it is gone
	assert(js->body.find("parseSettingsFile") != std::string::npos && js->body.find("nmap_processes") != std::string::npos);
	assert(js->body.find("soonTargets") == std::string::npos && js->body.find("tab_targets") == std::string::npos);
	assert(js->body.find("setAttribute('style'") == std::string::npos && js->body.find("style.cssText") != std::string::npos); // styles go through the CSSOM: the policy blocks style attributes
	assert(js->body.find("textContent") != std::string::npos && js->body.find("innerHTML") == std::string::npos); // untrusted text goes in as text only
	auto icon = c.Get("/favicon.svg");
	assert(icon && icon->status == 200 && icon->get_header_value("Content-Type").find("image/svg+xml") == 0 && icon->body.find("<svg") != std::string::npos);
	assert(page->body.find("proculus-emblem") != std::string::npos && js->body.find("proculus-emblem") != std::string::npos); // the logo is defined once and used by the page
	auto css = c.Get("/style.css");
	assert(css && css->status == 200 && css->get_header_value("Content-Type").find("text/css") == 0);
	assert(c.Get("/nothing.html")->status == 404 && c.Get("/index.html")->status == 200);

	// ---- the proxy passes JSON through, with the query intact
	auto echo = c.Get("/api/echo?q=a%20b&n=5", httplib::Headers{{"Cookie", "session=abc"}});
	assert(echo && echo->status == 200 && echo->body == "{\"q\":\"a b\",\"n\":5}");
	assert(echo->get_header_value("Content-Type").find("application/json") == 0 && echo->get_header_value("Cache-Control") == "no-store");
	assert(echo->get_header_value("Set-Cookie").empty()); // upstream headers are not passed back
	assert(last_cookie == "none" && last_accept == "application/json"); // the browser's cookies are not passed on
	assert(last_host == "127.0.0.1:" + std::to_string(fake_port)); // the upstream sees its own address, not the browser's Host

	// ---- the session token is passed on, and only if it is a plain token
	assert(c.Get("/api/echo?q=1&n=1", httplib::Headers{{"X-Proculus-Session", "abc123"}}) && last_session == "abc123");
	assert(c.Get("/api/echo?q=1&n=1") && last_session == "none");
	assert(c.Get("/api/echo?q=1&n=1", httplib::Headers{{"X-Proculus-Session", "has space"}})->status == 400);
	assert(c.Get("/api/echo?q=1&n=1", httplib::Headers{{"X-Proculus-Session", std::string(200, 'a')}})->status == 400);

	// ---- the gateway's own errors keep their status
	auto missing = c.Get("/api/missing");
	assert(missing && missing->status == 404 && missing->body.find("no run 7") != std::string::npos);
	auto broken = c.Get("/api/broken");
	assert(broken && broken->status == 500);

	// ---- anything unexpected becomes a clean 502
	for (const char* path : {"/api/html", "/api/redirect", "/api/big"}) {
		auto r = c.Get(path);
		assert(r && r->status == 502 && r->body.find("error") != std::string::npos);
		assert(r->body.find("script") == std::string::npos && r->body.find("evil.example") == std::string::npos);
	}

	// ---- paths that are not proxied
	assert(c.Get("/api/")->status == 400 && c.Get("/api/%2e%2e/x")->status == 400 && c.Get("/api/runs.json")->status == 400);

	// ---- POST: only the scan routes, JSON only, small, with the token passed on and nothing else of the browser's
	auto started = c.Post("/api/scan", httplib::Headers{{"X-Proculus-Token", "tok123"}, {"Cookie", "session=abc"}}, "{\"targets\":[\"10.0.0.1\"]}", "application/json");
	assert(started && started->status == 200 && started->body == "{\"started\":true}");
	assert(post_token == "tok123" && post_cookie == "none" && post_body == "{\"targets\":[\"10.0.0.1\"]}" && post_type == "application/json");
	auto unauth = c.Post("/api/scan", "{}", "application/json"); // the gateway's refusal reaches the page unchanged
	assert(unauth && unauth->status == 401 && unauth->body.find("control token") != std::string::npos && post_token == "none");
	assert(c.Post("/api/scan/stop", httplib::Headers{{"X-Proculus-Token", "tok123"}}, "{}", "application/json")->status == 200);
	assert(c.Post("/api/scan", httplib::Headers{{"X-Proculus-Token", "tok123"}}, "x=1", "application/x-www-form-urlencoded")->status == 415);
	assert(c.Post("/api/scan", httplib::Headers{{"X-Proculus-Token", "tok123"}}, std::string(20000, 'a'), "application/json")->status == 413);
	assert(c.Post("/api/scan?x=1", "{}", "application/json")->status == 405);
	assert(c.Post("/api/scan", httplib::Headers{{"X-Proculus-Token", "bad token"}}, "{}", "application/json")->status == 400);
	assert(c.Post("/api/echo", "{}", "application/json")->status == 405 && c.Post("/api/runs", "{}", "application/json")->status == 405); // not postable, though the gateway has them
	assert(c.Post("/", "{}", "application/json")->status == 405 && c.Post("/api/scan/x", "{}", "application/json")->status == 405);

	// ---- everything else is read-only, and Host is checked
	assert(c.Delete("/api/echo")->status == 405 && c.Put("/", "x", "text/plain")->status == 405 && c.Patch("/api/scan", "{}", "application/json")->status == 405);
	assert(c.Post("/api/scan", httplib::Headers{{"Host", "attacker.example"}, {"X-Proculus-Token", "tok123"}}, "{}", "application/json")->status == 403);
	httplib::Headers evil = {{"Host", "attacker.example"}};
	assert(c.Get("/", evil)->status == 403 && c.Get("/api/echo?q=1&n=1", evil)->status == 403 && c.Get("/app.js", evil)->status == 403);
	assert(c.Get("/", httplib::Headers{{"Host", "localhost:8080"}})->status == 200);
	assert(c.Get("/", httplib::Headers{{"Host", "proculus.lan"}})->status == 200); // --allow-host

	ui.stop();
	ui_thread.join();

	// ---- the gateway is down: a clean 502, not a hang or a crash
	fake.stop();
	fake_thread.join();
	UiConfig down = cfg;
	UiServer ui2(down);
	const int port2 = ui2.bind();
	std::thread t2([&] { ui2.run(); });
	httplib::Client c2("127.0.0.1", port2);
	c2.set_read_timeout(8);
	auto gone = c2.Get("/api/echo?q=1&n=1");
	assert(gone && gone->status == 502 && gone->body.find("not reachable") != std::string::npos);
	assert(c2.Get("/")->status == 200); // the pages still load
	ui2.stop();
	t2.join();
	return 0;
}
