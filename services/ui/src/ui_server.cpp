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
		if (req.method != "GET" && req.method != "HEAD") {
			send_error(res, 405, "read-only");
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
	svr.Get(R"(/api/.*)", [this](const httplib::Request& req, httplib::Response& res) {
		if (!is_proxyable_target(req.target)) return send_error(res, 400, "bad request");
		httplib::Client upstream(config_.api.host, config_.api.port);
		upstream.set_connection_timeout(3, 0);
		upstream.set_read_timeout(config_.api_timeout_seconds, 0);
		upstream.set_write_timeout(config_.api_timeout_seconds, 0);
		upstream.set_follow_location(false);
		auto answer = upstream.Get(req.target, httplib::Headers{{"Accept", "application/json"}});

		if (!answer) return send_error(res, 502, "the API is not reachable");
		if (answer->body.size() > config_.max_api_body) return send_error(res, 502, "the API answer is too large");
		const std::string type = lower(answer->get_header_value("Content-Type"));
		if (answer->status < 200 || answer->status > 599 || (answer->status >= 300 && answer->status < 400) || type.compare(0, 16, "application/json") != 0)
			return send_error(res, 502, "unexpected answer from the API");

		res.status = answer->status;
		res.set_header("Cache-Control", "no-store");
		res.set_content(answer->body, "application/json; charset=utf-8");
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
