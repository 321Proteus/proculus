#include "server.hpp"

#include <httplib.h>

#include <algorithm>
#include <functional>
#include <iostream>

#include "proculus/web/auth.hpp"
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
	} catch (const web::AuthError& e) {
		send_json(res, e.status, { { "error", e.what() } });
	} catch (const std::exception& e) {
		std::cerr << "gateway: request failed: " << e.what() << "\n";
		send_json(res, 500, { { "error", "internal error" } });
	}
}

// Who may call what: the permission a route needs ("" = anyone, "*" = any signed-in
// user). Routes not listed here do not exist; with login on, nothing is reachable
// without a matching rule.
struct Rule {
	const char *method, *path, *permission;
};
const Rule kRules[] = {
	{"GET", "/api/health", ""}, {"GET", "/api/auth", ""}, {"POST", "/api/login", ""}, {"POST", "/api/setup", ""}, {"POST", "/api/logout", "*"}, {"GET", "/api/me", "*"},
	{"GET", "/api/runs", "data.read"}, {"GET", "/api/dashboard", "data.read"}, {"GET", "/api/services", "data.read"}, {"GET", "/api/diff", "data.read"},
	{"GET", "/api/hosts", "data.read"}, {"GET", "/api/scan", "data.read"},
	{"POST", "/api/scan", "scan.run"}, {"POST", "/api/scan/plan", "scan.run"}, {"POST", "/api/scan/stop", "scan.run"},
	{"GET", "/api/users", "users.manage"}, {"POST", "/api/users", "users.manage"}, {"POST", "/api/users/update", "users.manage"},
	{"GET", "/api/roles", "users.manage"}, {"POST", "/api/roles", "users.manage"}, {"POST", "/api/roles/delete", "users.manage"}, {"GET", "/api/audit", "users.manage"},
};

const Rule* find_rule(const std::string& method, const std::string& path) {
	const std::string m = method == "HEAD" ? "GET" : method;
	for (const Rule& r : kRules)
		if (m == r.method && path == r.path) return &r;
	return nullptr;
}

Json user_json(const web::AuthUser& u) { return {{"id", u.id}, {"username", u.username}, {"role", u.role}, {"permissions", u.permissions}}; }

std::string clip(const std::string& s, size_t n = 64) {
	std::string out;
	for (unsigned char c : s) {
		if (out.size() >= n) break;
		out.push_back(c >= 0x20 && c != 0x7f ? static_cast<char>(c) : '?');
	}
	return out;
}

// The JSON body of a POST, or nullopt after answering 415 / 400.
std::optional<Json> json_body(const httplib::Request& req, httplib::Response& res) {
	if (req.get_header_value("Content-Type").compare(0, 16, "application/json") != 0) {
		send_json(res, 415, {{"error", "send JSON"}});
		return std::nullopt;
	}
	Json body = Json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
	if (body.is_discarded() || !body.is_object()) {
		send_json(res, 400, {{"error", "the request is not valid JSON"}});
		return std::nullopt;
	}
	return body;
}

std::string str_field(const Json& b, const char* key, size_t max = 200) {
	auto it = b.find(key);
	if (it == b.end() || !it->is_string() || it->get<std::string>().size() > max) throw ApiError(400, std::string("\"") + key + "\" must be text");
	return it->get<std::string>();
}

} // namespace

WebServer::WebServer(const ResultStore& store, ServerConfig config, ScanController* scans, web::AuthBackend* auth)
	: store_(store), config_(std::move(config)), api_(store_), scans_(scans), guard_(config_.control_token), setup_guard_(config_.setup_token), auth_(auth), server_(std::make_unique<httplib::Server>()) {
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

	// Only the routes in the rule table (reads, and POST where a rule says so), only for names we
	// answer to (see the header comment); with login on, the session's role must have the permission.
	svr.set_pre_routing_handler([this, allowed](const httplib::Request& req, httplib::Response& res) {
		const Rule* rule = find_rule(req.method, req.path);
		if (!rule && req.method != "GET" && req.method != "HEAD") {
			send_json(res, 405, { { "error", "not allowed" } });
			return httplib::Server::HandlerResponse::Handled;
		}
		if (!web::host_allowed(req.get_header_value("Host"), allowed)) {
			send_json(res, 403, { { "error", "host not allowed (see --allow-host)" } });
			return httplib::Server::HandlerResponse::Handled;
		}
		if (auth_ && rule && *rule->permission) {
			const auto user = sessions_.find(req.get_header_value("X-Proculus-Session"));
			if (!user) {
				send_json(res, 401, { { "error", "login required" } });
				return httplib::Server::HandlerResponse::Handled;
			}
			if (std::string(rule->permission) != "*" && !user->has(rule->permission)) {
				send_json(res, 403, { { "error", "your role does not allow this" } });
				return httplib::Server::HandlerResponse::Handled;
			}
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
	auto current_user = [this](const httplib::Request& req) -> std::optional<web::AuthUser> { return sessions_.find(req.get_header_value("X-Proculus-Session")); };
	auto control = [this, current_user](const httplib::Request& req, httplib::Response& res, const std::function<Json(const Json&)>& action) {
		if (!scans_ || !scans_->enabled()) return send_json(res, 403, {{"error", "scans are not enabled on this server"}});
		if (!auth_) { // no login: the control token
			switch (guard_.check(req.get_header_value("X-Proculus-Token"))) {
			case TokenGuard::Result::Ok: break;
			case TokenGuard::Result::Disabled: return send_json(res, 403, {{"error", "no control token is configured"}});
			case TokenGuard::Result::Locked: return send_json(res, 429, {{"error", "too many wrong tokens; try again in a minute"}});
			case TokenGuard::Result::Denied: return send_json(res, 401, {{"error", "wrong or missing control token"}});
			}
		}
		const auto body = json_body(req, res);
		if (!body) return;
		api_route(res, [&] { return action(*body); });
		if (auth_ && res.status == 200) {
			const auto user = current_user(req);
			auth_->record(user ? &*user : nullptr, req.path == "/api/scan" ? "scan started" : req.path == "/api/scan/stop" ? "scan stopped" : "scan planned", "scan",
				req.path == "/api/scan/plan" ? "" : clip(body->dump(), 300), req.remote_addr);
		}
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

	// ---- login, users, roles, audit (only with an auth backend)
	svr.Get("/api/auth", [this](const httplib::Request&, httplib::Response& res) {
		api_route(res, [&] {
			if (!auth_) return Json{{"enabled", false}};
			const bool users = auth_->has_users();
			return Json{{"enabled", true}, {"has_users", users}, {"setup_required", !users && !config_.setup_token.empty()}};
		});
	});
	if (!auth_) return;

	svr.Post("/api/login", [this](const httplib::Request& req, httplib::Response& res) {
		const auto body = json_body(req, res);
		if (!body) return;
		try {
			const std::string username = str_field(*body, "username", 64), password = str_field(*body, "password", 200);
			std::string key = username;
			std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			if (!throttle_.allowed(key)) return send_json(res, 429, {{"error", "too many failed logins; try again in a few minutes"}});
			const auto user = auth_->verify(username, password);
			if (!user) {
				throttle_.failed(key);
				auth_->record(nullptr, "login failed", "user:" + clip(username), "", req.remote_addr);
				return send_json(res, 401, {{"error", "wrong user name or password"}}); // the same whether the name exists or not
			}
			throttle_.succeeded(key);
			const std::string token = sessions_.create(*user);
			auth_->record(&*user, "login", "user:" + user->username, "", req.remote_addr);
			send_json(res, 200, {{"token", token}, {"user", user_json(*user)}});
		} catch (const ApiError& e) {
			send_json(res, e.status, {{"error", e.what()}});
		} catch (const std::exception& e) {
			std::cerr << "gateway: login failed: " << e.what() << "\n";
			send_json(res, 500, {{"error", "internal error"}});
		}
	});
	// First-run setup: while there are no accounts, whoever knows the setup token (printed on the
	// gateway's console) can create the first administrator. Afterwards this route only says 409.
	svr.Post("/api/setup", [this](const httplib::Request& req, httplib::Response& res) {
		const auto body = json_body(req, res);
		if (!body) return;
		try {
			if (auth_->has_users()) return send_json(res, 409, {{"error", "the system is already set up"}});
			switch (setup_guard_.check(str_field(*body, "setup_token", 128))) {
			case TokenGuard::Result::Ok: break;
			case TokenGuard::Result::Disabled: return send_json(res, 403, {{"error", "setup is not available: create the first administrator with `gateway user add`"}});
			case TokenGuard::Result::Locked: return send_json(res, 429, {{"error", "too many wrong setup tokens; try again in a minute"}});
			case TokenGuard::Result::Denied: return send_json(res, 401, {{"error", "wrong setup token"}});
			}
			const std::string username = str_field(*body, "username", 64), password = str_field(*body, "password", 200);
			auth_->create_first_admin(username, password);
			const auto user = auth_->verify(username, password);
			if (!user) return send_json(res, 500, {{"error", "internal error"}});
			auth_->record(&*user, "setup", "user:" + user->username, "first administrator created", req.remote_addr);
			send_json(res, 200, {{"token", sessions_.create(*user)}, {"user", user_json(*user)}});
		} catch (const web::AuthError& e) {
			send_json(res, e.status, {{"error", e.what()}});
		} catch (const ApiError& e) {
			send_json(res, e.status, {{"error", e.what()}});
		} catch (const std::exception& e) {
			std::cerr << "gateway: setup failed: " << e.what() << "\n";
			send_json(res, 500, {{"error", "internal error"}});
		}
	});
	svr.Post("/api/logout", [this, current_user](const httplib::Request& req, httplib::Response& res) {
		if (const auto user = current_user(req)) auth_->record(&*user, "logout", "user:" + user->username, "", req.remote_addr);
		sessions_.revoke(req.get_header_value("X-Proculus-Session"));
		send_json(res, 200, {{"ok", true}});
	});
	svr.Get("/api/me", [current_user](const httplib::Request& req, httplib::Response& res) {
		const auto user = current_user(req);
		send_json(res, user ? 200 : 401, user ? Json{{"user", user_json(*user)}} : Json{{"error", "login required"}});
	});

	svr.Get("/api/users", [this](const httplib::Request&, httplib::Response& res) {
		api_route(res, [&] {
			Json a = Json::array();
			for (const auto& u : auth_->users()) a.push_back({{"id", u.id}, {"username", u.username}, {"role", u.role}, {"disabled", u.disabled}, {"last_login", u.last_login}});
			return a;
		});
	});
	svr.Post("/api/users", [this, current_user](const httplib::Request& req, httplib::Response& res) {
		const auto body = json_body(req, res);
		if (!body) return;
		api_route(res, [&] {
			const auto created = auth_->create_user(str_field(*body, "username", 64), str_field(*body, "password"), str_field(*body, "role", 32));
			const auto actor = current_user(req);
			auth_->record(actor ? &*actor : nullptr, "user created", "user:" + created.username, "role " + created.role, req.remote_addr);
			return Json{{"id", created.id}, {"username", created.username}, {"role", created.role}};
		});
	});
	svr.Post("/api/users/update", [this, current_user](const httplib::Request& req, httplib::Response& res) {
		const auto body = json_body(req, res);
		if (!body) return;
		api_route(res, [&] {
			if (!body->contains("id") || !(*body)["id"].is_number_integer()) throw ApiError(400, "\"id\" must be a whole number");
			const int64_t id = (*body)["id"].get<int64_t>();
			std::optional<std::string> role, password;
			std::optional<bool> disabled;
			std::string changed;
			if (body->contains("role")) { role = str_field(*body, "role", 32); changed += "role=" + *role + " "; }
			if (body->contains("password")) { password = str_field(*body, "password"); changed += "password "; } // the value is never logged
			if (body->contains("disabled")) {
				if (!(*body)["disabled"].is_boolean()) throw ApiError(400, "\"disabled\" must be true or false");
				disabled = (*body)["disabled"].get<bool>();
				changed += *disabled ? "disabled " : "enabled ";
			}
			auth_->update_user(id, role, disabled, password);
			sessions_.revoke_user(id); // a changed account signs in again, with its new role
			const auto actor = current_user(req);
			auth_->record(actor ? &*actor : nullptr, "user updated", "user:" + std::to_string(id), changed, req.remote_addr);
			return Json{{"ok", true}};
		});
	});
	svr.Get("/api/roles", [this](const httplib::Request&, httplib::Response& res) {
		api_route(res, [&] {
			Json a = Json::array();
			for (const auto& r : auth_->roles()) a.push_back({{"name", r.name}, {"description", r.description}, {"permissions", r.permissions}, {"builtin", r.builtin}, {"users", r.users}});
			return a;
		});
	});
	svr.Post("/api/roles", [this, current_user](const httplib::Request& req, httplib::Response& res) {
		const auto body = json_body(req, res);
		if (!body) return;
		api_route(res, [&] {
			std::vector<std::string> perms;
			if (body->contains("permissions")) {
				if (!(*body)["permissions"].is_array()) throw ApiError(400, "\"permissions\" must be a list");
				for (const Json& p : (*body)["permissions"]) {
					if (!p.is_string()) throw ApiError(400, "\"permissions\" must hold text");
					perms.push_back(p.get<std::string>());
				}
			}
			const auto role = auth_->create_role(str_field(*body, "name", 32), body->contains("description") ? str_field(*body, "description") : "", perms);
			const auto actor = current_user(req);
			auth_->record(actor ? &*actor : nullptr, "role created", "role:" + role.name, "", req.remote_addr);
			return Json{{"name", role.name}, {"permissions", role.permissions}};
		});
	});
	svr.Post("/api/roles/delete", [this, current_user](const httplib::Request& req, httplib::Response& res) {
		const auto body = json_body(req, res);
		if (!body) return;
		api_route(res, [&] {
			const std::string name = str_field(*body, "name", 32);
			auth_->delete_role(name);
			const auto actor = current_user(req);
			auth_->record(actor ? &*actor : nullptr, "role deleted", "role:" + name, "", req.remote_addr);
			return Json{{"ok", true}};
		});
	});
	svr.Get("/api/audit", [this](const httplib::Request& req, httplib::Response& res) {
		api_route(res, [&] {
			Json a = Json::array();
			for (const auto& e : auth_->audit(number_param(req, "limit", 100, 500)))
				a.push_back({{"id", e.id}, {"at", e.at}, {"user", e.user}, {"action", e.action}, {"entity", e.entity}, {"detail", e.detail}, {"source_ip", e.source_ip}});
			return a;
		});
	});
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
