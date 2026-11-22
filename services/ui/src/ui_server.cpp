#include "ui_server.hpp"

#include <httplib.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>

#include "ui_assets.hpp"

namespace proculus {

namespace {

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

void send_error(httplib::Response& res, int status, const char* message) {
	res.status = status;
	res.set_header("Cache-Control", "no-store");
	res.set_content(std::string("{\"error\":\"") + message + "\"}", "application/json; charset=utf-8");
}

std::string read_file(const std::string& path, bool& ok) {
	std::ifstream f(path, std::ios::binary);
	ok = static_cast<bool>(f);
	std::ostringstream s;
	s << f.rdbuf();
	return s.str();
}

} // namespace

bool is_proxyable_target(const std::string& target) {
	if (target.size() < 6 || target.size() > 2048 || target.compare(0, 5, "/api/") != 0) return false;
	const size_t q = target.find('?');
	const std::string path = target.substr(0, q);
	for (unsigned char c : path)
		if (!(std::islower(c) || std::isdigit(c) || c == '/' || c == '-' || c == '_')) return false; // no dots, no escapes: nothing to disguise a ".."
	if (path.find("//") != std::string::npos || path.back() == '/') return false;
	if (q != std::string::npos)
		for (unsigned char c : target.substr(q + 1))
			if (!(std::isalnum(c) || c == '%' || c == '=' || c == '&' || c == '_' || c == '.' || c == '~' || c == '+' || c == '-' || c == ':' || c == ',')) return false;
	return true;
}

bool is_postable_path(const std::string& path) {
	static const char* const paths[] = {"/api/scan", "/api/scan/plan", "/api/scan/stop", "/api/edits", "/api/edits/clear", "/api/login", "/api/setup", "/api/logout", "/api/users", "/api/users/update", "/api/roles", "/api/roles/delete"};
	return std::any_of(std::begin(paths), std::end(paths), [&](const char* p) { return path == p; });
}

// The session token (or control token) a request carries: printable, short, or it is not passed on.
static bool token_ok(const std::string& t) { return t.size() <= 128 && std::all_of(t.begin(), t.end(), [](unsigned char c) { return c > 0x20 && c < 0x7f; }); }

static httplib::Headers forwarded_headers(const httplib::Request& req, bool& ok) {
	httplib::Headers h = {{"Accept", "application/json"}};
	ok = true;
	for (const char* name : {"X-Proculus-Session", "X-Proculus-Token"}) {
		const std::string v = req.get_header_value(name);
		if (v.empty()) continue;
		if (!token_ok(v)) ok = false;
		else h.emplace(name, v);
	}
	return h;
}

UiServer::UiServer(UiConfig config) : config_(std::move(config)), server_(std::make_unique<httplib::Server>()) {
	httplib::Server& svr = *server_;

	std::vector<std::string> allowed = web::default_allowed_hosts();
	for (const std::string& h : config_.allowed_hosts) allowed.push_back(lower(h));

	svr.set_read_timeout(10, 0);
	svr.set_write_timeout(10, 0);
	svr.set_payload_max_length(64 * 1024);
	svr.set_default_headers({
		{"Content-Security-Policy", web::kPageContentSecurityPolicy},
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "no-referrer"},
	});

	svr.set_pre_routing_handler([allowed](const httplib::Request& req, httplib::Response& res) {
		if (req.method != "GET" && req.method != "HEAD" && !(req.method == "POST" && is_postable_path(req.path))) {
			send_error(res, 405, "not allowed");
			return httplib::Server::HandlerResponse::Handled;
		}
		if (!web::host_allowed(req.get_header_value("Host"), allowed)) {
			send_error(res, 403, "host not allowed (see --allow-host)");
			return httplib::Server::HandlerResponse::Handled;
		}
		return httplib::Server::HandlerResponse::Unhandled;
	});
	svr.set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr) { send_error(res, 500, "internal error"); });
	svr.set_error_handler([](const httplib::Request&, httplib::Response& res) {
		if (res.body.empty()) send_error(res, res.status, res.status == 404 ? "not found" : "error");
	});

	// ---- /api/...: on to the gateway
	auto pass_on = [this](httplib::Response& res, const httplib::Result& answer) {
		if (!answer) return send_error(res, 502, "the API is not reachable");
		if (answer->body.size() > config_.max_api_body) return send_error(res, 502, "the API answer is too large");
		const std::string type = lower(answer->get_header_value("Content-Type"));
		if (answer->status < 200 || answer->status > 599 || (answer->status >= 300 && answer->status < 400) || type.compare(0, 16, "application/json") != 0)
			return send_error(res, 502, "unexpected answer from the API");
		res.status = answer->status;
		res.set_header("Cache-Control", "no-store");
		res.set_content(answer->body, "application/json; charset=utf-8");
	};
	auto client = [this]() {
		auto upstream = std::make_unique<httplib::Client>(config_.api.host, config_.api.port);
		upstream->set_connection_timeout(3, 0);
		upstream->set_read_timeout(config_.api_timeout_seconds, 0);
		upstream->set_write_timeout(config_.api_timeout_seconds, 0);
		upstream->set_follow_location(false);
		return upstream;
	};

	svr.Get(R"(/api/.*)", [client, pass_on](const httplib::Request& req, httplib::Response& res) {
		if (!is_proxyable_target(req.target)) return send_error(res, 400, "bad request");
		bool ok;
		const httplib::Headers headers = forwarded_headers(req, ok);
		if (!ok) return send_error(res, 400, "bad token");
		pass_on(res, client()->Get(req.target, headers));
	});

	svr.Post(R"(/api/.*)", [this, client, pass_on](const httplib::Request& req, httplib::Response& res) {
		if (!is_proxyable_target(req.target) || req.target.find('?') != std::string::npos || !is_postable_path(req.path)) return send_error(res, 405, "not allowed");
		if (req.get_header_value("Content-Type").compare(0, 16, "application/json") != 0) return send_error(res, 415, "send JSON");
		if (req.body.size() > config_.max_post_body) return send_error(res, 413, "the request is too large");
		bool ok;
		const httplib::Headers headers = forwarded_headers(req, ok);
		if (!ok) return send_error(res, 400, "bad token");
		pass_on(res, client()->Post(req.target, headers, req.body, "application/json"));
	});

	// ---- the pages
	for (const UiAsset& a : ui_assets()) {
		auto serve = [this, a](const httplib::Request&, httplib::Response& res) {
			std::string body = a.content;
			if (!config_.web_dir.empty()) { // development: edit the files without rebuilding
				bool ok = false;
				std::string from_disk = read_file(config_.web_dir + a.path, ok);
				if (ok) body = std::move(from_disk);
			}
			res.set_header("Cache-Control", "no-cache");
			res.set_content(body, a.mime);
		};
		svr.Get(a.path, serve);
		if (std::string(a.path) == "/index.html") svr.Get("/", serve);
	}
}

UiServer::~UiServer() { stop(); }

int UiServer::bind() {
	int port;
	if (config_.port == 0) port = server_->bind_to_any_port(config_.bind);
	else port = server_->bind_to_port(config_.bind, config_.port) ? config_.port : -1;
	if (port <= 0) throw std::runtime_error("cannot listen on " + config_.bind + ":" + std::to_string(config_.port));
	return port;
}

void UiServer::run() { server_->listen_after_bind(); }

void UiServer::stop() {
	if (server_) server_->stop();
}

} // namespace proculus
