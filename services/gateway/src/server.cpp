#include "server.hpp"

#include <httplib.h>

#include <algorithm>
#include <functional>
#include <iostream>

#include "proculus/web/guard.hpp"

namespace proculus {

namespace {

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

size_t number_param(const httplib::Request& req, const char* name, size_t fallback, size_t max) {
	if (!req.has_param(name)) return fallback;
	const std::string v = req.get_param_value(name);
	if (v.empty() || v.size() > 9 || v.find_first_not_of("0123456789") != std::string::npos) throw ApiError(400, std::string("bad value for ") + name);
	return std::min<size_t>(std::stoull(v), max);
}

std::string text_param(const httplib::Request& req, const char* name, const char* fallback, size_t max_len = 200) {
	if (!req.has_param(name)) return fallback;
	std::string v = req.get_param_value(name);
	if (v.size() > max_len) throw ApiError(400, std::string("value of ") + name + " is too long");
	return v;
}

void send_json(httplib::Response& res, int status, const Json& j) {
	res.status = status;
	res.set_header("Cache-Control", "no-store");
	res.set_content(dump_json(j), "application/json; charset=utf-8");
}

// Runs `fn`, turns ApiError into its status and anything else into a plain 500
// (details of internal failures are not sent to the client).
template <class Fn>
void api_route(httplib::Response& res, Fn&& fn) {
	try {
		send_json(res, 200, fn());
	} catch (const ApiError& e) {
		send_json(res, e.status, { { "error", e.what() } });
	} catch (const std::exception& e) {
		std::cerr << "gateway: request failed: " << e.what() << "\n";
		send_json(res, 500, { { "error", "internal error" } });
	}
}

} // namespace

WebServer::WebServer(const ResultStore& store, ServerConfig config, ScanController* scans)
	: store_(store), config_(std::move(config)), api_(store_), scans_(scans), guard_(config_.control_token), server_(std::make_unique<httplib::Server>()) {
	httplib::Server& svr = *server_;

	std::vector<std::string> allowed = web::default_allowed_hosts();
	for (const std::string& h : config_.allowed_hosts) allowed.push_back(lower(h));

	svr.set_read_timeout(10, 0);
	svr.set_write_timeout(10, 0);
	svr.set_payload_max_length(64 * 1024);
	svr.set_default_headers({
		{"Content-Security-Policy", web::kApiContentSecurityPolicy},
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "no-referrer"},
	});

	// Reads, plus POST to the scan routes only; and only for names we answer to (see the header comment).
	svr.set_pre_routing_handler([allowed](const httplib::Request& req, httplib::Response& res) {
		const bool scan_post = req.method == "POST" && (req.path == "/api/scan" || req.path == "/api/scan/plan" || req.path == "/api/scan/stop");
		if (req.method != "GET" && req.method != "HEAD" && !scan_post) {
			send_json(res, 405, { { "error", "not allowed" } });
			return httplib::Server::HandlerResponse::Handled;
		}
		if (!web::host_allowed(req.get_header_value("Host"), allowed)) {
			send_json(res, 403, { { "error", "host not allowed (see --allow-host)" } });
			return httplib::Server::HandlerResponse::Handled;
		}
		return httplib::Server::HandlerResponse::Unhandled;
	});

	svr.set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr) {
		send_json(res, 500, { { "error", "internal error" } });
	});
	svr.set_error_handler([](const httplib::Request&, httplib::Response& res) {
		if (res.body.empty()) send_json(res, res.status, { { "error", res.status == 404 ? "not found" : "error" } });
	});

	// ---- API
	svr.Get("/api/health", [](const httplib::Request&, httplib::Response& res) { send_json(res, 200, { { "ok", true } }); });
	svr.Get("/api/runs", [this](const httplib::Request&, httplib::Response& res) { api_route(res, [&] { return api_.runs(); }); });
	svr.Get("/api/dashboard", [this](const httplib::Request& req, httplib::Response& res) {
		api_route(res, [&] { return api_.dashboard(text_param(req, "run", "latest", 20)); });
	});
	svr.Get("/api/services", [this](const httplib::Request& req, httplib::Response& res) {
		api_route(res, [&] {
			ServicesQuery q;
			q.text = text_param(req, "q", "");
			q.min_score = static_cast<int>(number_param(req, "min_score", 0, 100));
			q.limit = number_param(req, "limit", 50, 500);
			q.offset = number_param(req, "offset", 0, 100000000);
			return api_.services(text_param(req, "run", "latest", 20), q);
		});
	});
	svr.Get("/api/diff", [this](const httplib::Request& req, httplib::Response& res) {
		api_route(res, [&] { return api_.diff(text_param(req, "before", "", 20), text_param(req, "after", "latest", 20)); });
	});
	// ---- scans: status is public like the rest; starting and stopping need the control token
	svr.Get("/api/scan", [this](const httplib::Request&, httplib::Response& res) {
		api_route(res, [&] { return scans_ ? scans_->status() : Json{{"enabled", false}}; });
	});
	auto control = [this](const httplib::Request& req, httplib::Response& res, const std::function<Json(const Json&)>& action) {
		if (!scans_ || !scans_->enabled()) return send_json(res, 403, {{"error", "scans are not enabled on this server"}});
		switch (guard_.check(req.get_header_value("X-Proculus-Token"))) {
		case TokenGuard::Result::Ok: break;
		case TokenGuard::Result::Disabled: return send_json(res, 403, {{"error", "no control token is configured"}});
		case TokenGuard::Result::Locked: return send_json(res, 429, {{"error", "too many wrong tokens; try again in a minute"}});
		case TokenGuard::Result::Denied: return send_json(res, 401, {{"error", "wrong or missing control token"}});
		}
		if (req.get_header_value("Content-Type").compare(0, 16, "application/json") != 0) return send_json(res, 415, {{"error", "send JSON"}});
		const Json body = Json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
		if (body.is_discarded()) return send_json(res, 400, {{"error", "the request is not valid JSON"}});
		api_route(res, [&] { return action(body); });
	};
	svr.Post("/api/scan", [this, control](const httplib::Request& req, httplib::Response& res) {
		control(req, res, [&](const Json& body) -> Json {
			scans_->start(parse_scan_request(body));
			return scans_->status();
		});
	});
	svr.Post("/api/scan/plan", [this, control](const httplib::Request& req, httplib::Response& res) {
		control(req, res, [&](const Json& body) -> Json { return scans_->plan(parse_scan_request(body)); });
	});
	svr.Post("/api/scan/stop", [this, control](const httplib::Request& req, httplib::Response& res) {
		control(req, res, [&](const Json&) -> Json {
			scans_->stop();
			return scans_->status();
		});
	});
	svr.Get("/api/hosts", [this](const httplib::Request&, httplib::Response& res) { api_route(res, [&] { return api_.hosts(); }); });
}

WebServer::~WebServer() { stop(); }

int WebServer::bind() {
	if (config_.port == 0) port_ = server_->bind_to_any_port(config_.bind);
	else port_ = server_->bind_to_port(config_.bind, config_.port) ? config_.port : -1;
	if (port_ <= 0) throw std::runtime_error("cannot listen on " + config_.bind + ":" + std::to_string(config_.port));
	return port_;
}

void WebServer::run() { server_->listen_after_bind(); }

void WebServer::stop() {
	if (server_) server_->stop();
}

} // namespace proculus
