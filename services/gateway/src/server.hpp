#ifndef PROCULUS_GATEWAY_SERVER_HPP
#define PROCULUS_GATEWAY_SERVER_HPP

// The web server of the gateway: the JSON API that the UI service (services/ui)
// shows. It serves no pages. Everything is read-only except the scan routes
// (POST /api/scan, /api/scan/plan, /api/scan/stop), which need the control token.
//
// Until user accounts exist the server has no authentication, so it is meant
// for the local machine or a private network between containers: it listens
// on loopback by default, and it refuses requests whose Host header is not a
// loopback name or an explicitly allowed one, which stops a web page from
// reading it through DNS rebinding.

#include <memory>
#include <string>
#include <vector>

#include "api.hpp"
#include "scan_control.hpp"
#include "proculus/web/auth.hpp"
#include "token_guard.hpp"

namespace httplib {
class Server;
}

namespace proculus {

struct ServerConfig {
	std::string bind = "127.0.0.1";
	int port = 8081;                           // 0: pick a free port (tests)
	std::vector<std::string> allowed_hosts;    // besides localhost, 127.0.0.1 and [::1]
	std::string control_token;                 // needed to start or stop scans (X-Proculus-Token); empty: scans cannot be controlled
	std::string setup_token;                   // with login and no accounts yet: lets the first administrator be created (POST /api/setup); empty: setup is not offered
};

class WebServer {
public:
	// `scans` (optional, must outlive the server) enables the scan routes.
	// `auth` (optional, must outlive the server) turns on login: every route
	// except health and login then needs a session whose role has the route's
	// permission (see the rule table in server.cpp, denied by default); starting
	// scans needs the scan.run permission instead of the control token, and the
	// user, role and audit routes exist. Without it the server behaves as before.
	WebServer(const ResultStore& store, ServerConfig config, ScanController* scans = nullptr, web::AuthBackend* auth = nullptr);
	~WebServer();

	// Binds and returns the port; throws std::runtime_error if that fails.
	int bind();
	// Serves until stop() is called; bind() first.
	void run();
	void stop();

private:
	const ResultStore& store_;
	ServerConfig config_;
	Api api_;
	ScanController* scans_;
	TokenGuard guard_;
	TokenGuard setup_guard_;
	web::AuthBackend* auth_;
	web::SessionManager sessions_;
	web::LoginThrottle throttle_;
	std::unique_ptr<httplib::Server> server_;
	int port_ = 0;
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_SERVER_HPP
