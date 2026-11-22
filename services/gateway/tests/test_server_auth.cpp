#undef NDEBUG
#include <httplib.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <mutex>
#include <thread>

#include "server.hpp"
#include "sim_network.hpp"

using namespace proculus;
namespace fs = std::filesystem;

// An in-memory backend: passwords in the clear are fine for a test.
class FakeAuth : public web::AuthBackend {
public:
	struct U {
		int64_t id;
		std::string name, password, role;
		bool disabled = false;
	};
	explicit FakeAuth(bool empty = false) {
		roles_ = {{"admin", "All", web::all_permissions(), true, 0}, {"manager", "Runs scans", {"data.read", "data.edit", "data.create", "data.delete", "export", "scan.run"}, true, 0},
			{"viewer", "Read only", {"data.read", "export"}, true, 0}};
		if (!empty) users_ = {{1, "ann", "ann-password-1", "admin"}, {2, "mia", "mia-password-1", "manager"}, {3, "vic", "vic-password-1", "viewer"}};
	}
	std::optional<web::AuthUser> verify(const std::string& n, const std::string& p) override {
		std::lock_guard<std::mutex> l(m);
		for (const U& u : users_)
			if (u.name == n && u.password == p && !u.disabled) return as_user(u);
		return std::nullopt;
	}
	bool has_users() override {
		std::lock_guard<std::mutex> l(m);
		return !users_.empty();
	}
	web::UserInfo create_first_admin(const std::string& n, const std::string& p) override {
		std::lock_guard<std::mutex> l(m);
		if (p.size() < 10) throw web::AuthError(400, "the password must have at least 10 characters");
		if (!users_.empty()) throw web::AuthError(409, "the system is already set up");
		users_.push_back({1, n, p, "admin"});
		return {1, n, "admin", false, ""};
	}
	std::vector<web::UserInfo> users() override {
		std::lock_guard<std::mutex> l(m);
		std::vector<web::UserInfo> out;
		for (const U& u : users_) out.push_back({u.id, u.name, u.role, u.disabled, ""});
		return out;
	}
	std::vector<web::RoleInfo> roles() override { return roles_; }
	web::UserInfo create_user(const std::string& n, const std::string& p, const std::string& r) override {
		std::lock_guard<std::mutex> l(m);
		if (p.size() < 10) throw web::AuthError(400, "the password must have at least 10 characters");
		for (const U& u : users_)
			if (u.name == n) throw web::AuthError(409, "a user with that name already exists");
		users_.push_back({static_cast<int64_t>(users_.size() + 1), n, p, r});
		return {users_.back().id, n, r, false, ""};
	}
	void update_user(int64_t id, const std::optional<std::string>& role, const std::optional<bool>& disabled, const std::optional<std::string>& password) override {
		std::lock_guard<std::mutex> l(m);
		for (U& u : users_)
			if (u.id == id) {
				if (role) u.role = *role;
				if (disabled) u.disabled = *disabled;
				if (password) u.password = *password;
				return;
			}
		throw web::AuthError(404, "no such user");
	}
	web::RoleInfo create_role(const std::string& n, const std::string& d, const std::vector<std::string>& p) override {
		roles_.push_back({n, d, p, false, 0});
		return roles_.back();
	}
	void delete_role(const std::string& n) override {
		roles_.erase(std::remove_if(roles_.begin(), roles_.end(), [&](const web::RoleInfo& r) { return r.name == n; }), roles_.end());
	}
	std::vector<web::AuditEntry> audit(size_t) override {
		std::lock_guard<std::mutex> l(m);
		return log;
	}
	void record(const web::AuthUser* u, const std::string& action, const std::string& entity, const std::string& detail, const std::string& ip) override {
		std::lock_guard<std::mutex> l(m);
		log.insert(log.begin(), {static_cast<int64_t>(log.size() + 1), "now", u ? u->username : "", action, entity, detail, ip});
	}

	std::mutex m;
	std::vector<web::AuditEntry> log;

private:
	web::AuthUser as_user(const U& u) const {
		web::AuthUser a;
		a.id = u.id;
		a.username = u.name;
		a.role = u.role;
		for (const auto& r : roles_)
			if (r.name == u.role) a.permissions = r.permissions;
		return a;
	}
	std::vector<U> users_;
	std::vector<web::RoleInfo> roles_;
};

static httplib::Result login_on(httplib::Client& c, const std::string& user, const std::string& pass) {
	return c.Post("/api/login", Json{{"username", user}, {"password", pass}}.dump(), "application/json");
}

static ServiceRecord svc(uint16_t port, const char* name) {
	ServiceRecord s;
	s.port = port;
	s.name = name;
	return s;
}

int main() {
	const fs::path dir = fs::temp_directory_path() / ("proculus_srvauth_" + std::to_string(getpid()));
	fs::remove_all(dir);
	FileResultStore store(dir);
	RunRecord r;
	r.source = "test";
	r.started = r.finished = "2026-11-22T10:00:00Z";
	HostRecord h;
	h.ip = "10.20.0.2";
	h.services = {svc(23, "telnet")};
	r.hosts = {h};
	store.save(r);

	SimNetwork net = SimNetwork::generate(7, "10.20.0.0/22", 0.05);
	ScanPolicy policy;
	policy.enabled = true;
	policy.scope = "10.20.0.0/22";
	policy.allowed_ports = "22,80,443";
	RunnerDeps base;
	base.deadline_watchdog = false;
	base.make_backend = [&](std::atomic<bool>&) { return std::make_unique<SimBackend>(net); };
	FileResultStore scan_store(dir / "scans");
	ScanController scans(policy, &scan_store, base);

	FakeAuth auth;
	ServerConfig cfg;
	cfg.port = 0;
	cfg.control_token = "unused-when-login-is-on-0123456789"; // login replaces the control token
	WebServer server(store, cfg, &scans, &auth);
	const int port = server.bind();
	std::thread t([&] { server.run(); });
	httplib::Client c("127.0.0.1", port);
	c.set_read_timeout(5);

	auto login = [&](const std::string& user, const std::string& pass) {
		return c.Post("/api/login", Json{{"username", user}, {"password", pass}}.dump(), "application/json");
	};
	auto session = [&](const std::string& user, const std::string& pass) {
		auto res = login(user, pass);
		assert(res && res->status == 200);
		return Json::parse(res->body)["token"].get<std::string>();
	};
	auto hdr = [](const std::string& tok) { return httplib::Headers{{"X-Proculus-Session", tok}}; };

	// ---- before login: only health, auth status and login
	assert(c.Get("/api/health")->status == 200);
	assert(Json::parse(c.Get("/api/auth")->body)["enabled"] == true);
	for (const char* path : {"/api/runs", "/api/dashboard", "/api/services", "/api/diff?before=1&after=2", "/api/hosts", "/api/scan", "/api/me", "/api/users", "/api/roles", "/api/audit"})
		assert(c.Get(path)->status == 401);
	assert(c.Get("/api/runs", hdr("not-a-session"))->status == 401);
	assert(c.Post("/api/scan", Json{{"targets", {"10.20.0.1"}}}.dump(), "application/json")->status == 401);
	assert(c.Get("/api/nothing")->status == 404 && c.Post("/api/runs", "{}", "application/json")->status == 405); // unknown routes still do not exist

	// ---- login: the same answer for a wrong password and an unknown user, JSON only
	auto bad = login("ann", "wrong"), ghost = login("nobody", "wrong");
	assert(bad->status == 401 && ghost->status == 401 && bad->body == ghost->body);
	assert(c.Post("/api/login", "username=ann&password=ann-password-1", "application/x-www-form-urlencoded")->status == 415);
	assert(c.Post("/api/login", "{not json", "application/json")->status == 400);
	assert(c.Post("/api/login", Json{{"username", "ann"}}.dump(), "application/json")->status == 400);
	assert(c.Post("/api/login", Json{{"username", std::string(100, 'a')}, {"password", "x"}}.dump(), "application/json")->status == 400);

	// ---- a viewer reads, and nothing more
	const std::string viewer = session("vic", "vic-password-1");
	assert(c.Get("/api/runs", hdr(viewer))->status == 200 && c.Get("/api/dashboard", hdr(viewer))->status == 200 && c.Get("/api/scan", hdr(viewer))->status == 200);
	assert(c.Get("/api/users", hdr(viewer))->status == 403 && c.Get("/api/audit", hdr(viewer))->status == 403 && c.Get("/api/roles", hdr(viewer))->status == 403);
	assert(c.Post("/api/scan", hdr(viewer), Json{{"targets", {"10.20.0.1"}}}.dump(), "application/json")->status == 403);
	assert(c.Post("/api/scan/stop", hdr(viewer), "{}", "application/json")->status == 403);
	assert(c.Post("/api/users", hdr(viewer), Json{{"username", "evil.user"}, {"password", "long enough pw"}, {"role", "admin"}}.dump(), "application/json")->status == 403);
	auto me = Json::parse(c.Get("/api/me", hdr(viewer))->body)["user"];
	assert(me["username"] == "vic" && me["role"] == "viewer" && me["permissions"].size() == 2);
	// the old control token is not a way around login
	assert(c.Post("/api/scan", httplib::Headers{{"X-Proculus-Token", cfg.control_token}}, Json{{"targets", {"10.20.0.1"}}}.dump(), "application/json")->status == 401);

	// ---- a manager runs scans, with no control token
	const std::string manager = session("mia", "mia-password-1");
	assert(c.Get("/api/users", hdr(manager))->status == 403);
	assert(c.Post("/api/scan", hdr(manager), Json{{"targets", {"8.8.8.8"}}}.dump(), "application/json")->status == 400); // the policy still applies
	auto started = c.Post("/api/scan", hdr(manager), Json{{"targets", {"10.20.0.0/24"}}}.dump(), "application/json");
	assert(started && started->status == 200);
	scans.wait_idle();
	assert(scan_store.list().size() == 1);

	// ---- an administrator manages users and roles
	const std::string admin = session("ann", "ann-password-1");
	assert(Json::parse(c.Get("/api/users", hdr(admin))->body).size() == 3);
	assert(Json::parse(c.Get("/api/roles", hdr(admin))->body).size() == 3);
	auto made = c.Post("/api/users", hdr(admin), Json{{"username", "new.user"}, {"password", "a long password"}, {"role", "viewer"}}.dump(), "application/json");
	assert(made && made->status == 200 && Json::parse(made->body)["username"] == "new.user");
	assert(c.Post("/api/users", hdr(admin), Json{{"username", "new.user"}, {"password", "a long password"}, {"role", "viewer"}}.dump(), "application/json")->status == 409);
	assert(c.Post("/api/users", hdr(admin), Json{{"username", "weak.pw"}, {"password", "short"}, {"role", "viewer"}}.dump(), "application/json")->status == 400);
	assert(c.Post("/api/users", hdr(admin), Json{{"username", 5}}.dump(), "application/json")->status == 400);
	assert(c.Post("/api/roles", hdr(admin), Json{{"name", "auditor"}, {"description", "reads"}, {"permissions", {"data.read", "export"}}}.dump(), "application/json")->status == 200);
	assert(Json::parse(c.Get("/api/roles", hdr(admin))->body).size() == 4);
	assert(c.Post("/api/roles/delete", hdr(admin), Json{{"name", "auditor"}}.dump(), "application/json")->status == 200);

	// a changed account loses its sessions, and signs in again with its new role
	assert(c.Get("/api/runs", hdr(viewer))->status == 200);
	assert(c.Post("/api/users/update", hdr(admin), Json{{"id", 3}, {"role", "manager"}}.dump(), "application/json")->status == 200);
	assert(c.Get("/api/runs", hdr(viewer))->status == 401);
	assert(Json::parse(c.Get("/api/me", hdr(session("vic", "vic-password-1")))->body)["user"]["role"] == "manager");
	assert(c.Post("/api/users/update", hdr(admin), Json{{"id", 3}, {"disabled", true}}.dump(), "application/json")->status == 200);
	assert(login("vic", "vic-password-1")->status == 401); // disabled
	assert(c.Post("/api/users/update", hdr(admin), Json{{"id", 99}, {"role", "viewer"}}.dump(), "application/json")->status == 404);
	assert(c.Post("/api/users/update", hdr(admin), Json{{"id", "3"}}.dump(), "application/json")->status == 400);

	// ---- the audit log records who did what, and never a password
	const Json log = Json::parse(c.Get("/api/audit", hdr(admin))->body);
	std::string all = log.dump();
	for (const char* needle : {"login failed", "user created", "user updated", "role created", "role deleted", "scan started", "login"}) assert(all.find(needle) != std::string::npos);
	for (const char* secret : {"ann-password-1", "vic-password-1", "mia-password-1", "a long password", "wrong"}) assert(all.find(secret) == std::string::npos);
	bool scan_by_mia = false;
	for (const Json& e : log) scan_by_mia |= e["action"] == "scan started" && e["user"] == "mia";
	assert(scan_by_mia);

	// ---- logout ends the session
	assert(c.Post("/api/logout", hdr(manager), "{}", "application/json")->status == 200);
	assert(c.Get("/api/runs", hdr(manager))->status == 401);

	// ---- guessing passwords is limited, per user name
	for (int i = 0; i < 5; i++) login("mia", "guess " + std::to_string(i));
	assert(login("mia", "mia-password-1")->status == 429); // locked, even for the right password
	assert(login("ann", "ann-password-1")->status == 200); // other users are not affected

	// ---- the Host check still applies
	assert(c.Get("/api/health", httplib::Headers{{"Host", "attacker.example"}})->status == 403);
	assert(c.Post("/api/login", httplib::Headers{{"Host", "attacker.example"}}, Json{{"username", "ann"}, {"password", "ann-password-1"}}.dump(), "application/json")->status == 403);

	server.stop();
	t.join();

	// ---- first-run setup: no accounts yet, a setup token printed on the console
	{
		FakeAuth empty(true);
		ServerConfig scfg;
		scfg.port = 0;
		scfg.setup_token = "setup-token-0123456789abcdef";
		WebServer sserver(store, scfg, nullptr, &empty);
		const int sport = sserver.bind();
		std::thread st([&] { sserver.run(); });
		httplib::Client sc("127.0.0.1", sport);
		sc.set_read_timeout(5);
		auto setup = [&](const std::string& token, const std::string& user, const std::string& pass) {
			return sc.Post("/api/setup", Json{{"setup_token", token}, {"username", user}, {"password", pass}}.dump(), "application/json");
		};

		auto st0 = Json::parse(sc.Get("/api/auth")->body);
		assert(st0["enabled"] == true && st0["has_users"] == false && st0["setup_required"] == true);
		assert(sc.Get("/api/runs")->status == 401); // nothing is open before setup either
		assert(login_on(sc, "x", "y")->status == 401);
		assert(setup("wrong-token", "first.admin", "first admin password")->status == 401);
		assert(setup("", "first.admin", "first admin password")->status == 401);
		assert(sc.Post("/api/setup", "{not json", "application/json")->status == 400);
		assert(sc.Post("/api/setup", "x=1", "application/x-www-form-urlencoded")->status == 415);
		assert(!empty.has_users()); // wrong attempts created nothing
		assert(setup("setup-token-0123456789abcdef", "first.admin", "short")->status == 400); // the token is right, the password is not
		assert(!empty.has_users());

		auto made = setup("setup-token-0123456789abcdef", "first.admin", "first admin password");
		assert(made && made->status == 200);
		const Json made_json = Json::parse(made->body);
		assert(made_json["user"]["role"] == "admin" && made_json["user"]["permissions"].size() == 8);
		assert(sc.Get("/api/users", httplib::Headers{{"X-Proculus-Session", made_json["token"].get<std::string>()}})->status == 200); // signed in as the new admin
		assert(setup("setup-token-0123456789abcdef", "second.admin", "second admin password")->status == 409); // once only
		assert(setup("wrong-token", "second.admin", "second admin password")->status == 409);
		auto st1 = Json::parse(sc.Get("/api/auth")->body);
		assert(st1["has_users"] == true && st1["setup_required"] == false);
		assert(login_on(sc, "first.admin", "first admin password")->status == 200);

		sserver.stop();
		st.join();
	}
	// guessing the setup token is limited
	{
		FakeAuth empty(true);
		ServerConfig scfg;
		scfg.port = 0;
		scfg.setup_token = "setup-token-0123456789abcdef";
		WebServer sserver(store, scfg, nullptr, &empty);
		const int sport = sserver.bind();
		std::thread st([&] { sserver.run(); });
		httplib::Client sc("127.0.0.1", sport);
		sc.set_read_timeout(5);
		for (int i = 0; i < 5; i++) sc.Post("/api/setup", Json{{"setup_token", "guess" + std::to_string(i)}, {"username", "a.b.c"}, {"password", "long enough pw"}}.dump(), "application/json");
		assert(sc.Post("/api/setup", Json{{"setup_token", "setup-token-0123456789abcdef"}, {"username", "first.admin"}, {"password", "first admin password"}}.dump(), "application/json")->status == 429);
		assert(!empty.has_users());
		sserver.stop();
		st.join();
	}
	// without a setup token, setup is not offered
	{
		FakeAuth empty(true);
		ServerConfig scfg;
		scfg.port = 0;
		WebServer sserver(store, scfg, nullptr, &empty);
		const int sport = sserver.bind();
		std::thread st([&] { sserver.run(); });
		httplib::Client sc("127.0.0.1", sport);
		sc.set_read_timeout(5);
		assert(Json::parse(sc.Get("/api/auth")->body)["setup_required"] == false);
		assert(sc.Post("/api/setup", Json{{"setup_token", ""}, {"username", "first.admin"}, {"password", "first admin password"}}.dump(), "application/json")->status == 403);
		assert(!empty.has_users());
		sserver.stop();
		st.join();
	}

	fs::remove_all(dir);
	return 0;
}
