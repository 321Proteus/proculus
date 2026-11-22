#ifndef PROCULUS_UI_SERVER_HPP
#define PROCULUS_UI_SERVER_HPP

// The web UI as its own service: it serves the pages (static files) and passes
// the page's /api/... requests on to the gateway, so the browser talks to one
// origin only. That keeps the Content-Security-Policy strict (connect-src
// 'self'), needs no CORS, and later lets login cookies work unchanged.
//
// The UI service holds no data and makes no decisions: who may see or change
// what is decided by the gateway, never here. What the proxy does guarantee:
//  * only GET and HEAD, only /api/ paths made of plain characters, forwarded to
//    the one configured upstream (the browser cannot choose the destination);
//    POST only to a fixed list of routes (scans, login, users, roles; see
//    is_postable_path), JSON only and small;
//  * only a JSON answer is passed back, within a size limit and a time limit;
//    anything else (a redirect, HTML, a huge body, an unreachable gateway)
//    becomes a clean 502;
//  * requests are forwarded without the browser's own headers (cookies and
//    Host are not passed on); the exceptions are the session token
//    (X-Proculus-Session) and the control token (X-Proculus-Token), which the
//    gateway checks.
// It has no login of its own, so like the gateway API it listens on loopback
// by default and checks the Host header (DNS rebinding).

#include <memory>
#include <string>
#include <vector>

#include "proculus/web/guard.hpp"

namespace httplib {
class Server;
}

namespace proculus {

struct UiConfig {
	std::string bind = "127.0.0.1";
	int port = 8080;                         // 0: pick a free port (tests)
	web::Upstream api{"127.0.0.1", 8081};    // the gateway
	std::vector<std::string> allowed_hosts;  // besides localhost, 127.0.0.1 and [::1]
	std::string web_dir;                     // serve the files from this directory instead of the built-in copy (for UI development)
	int api_timeout_seconds = 10;
	size_t max_api_body = 8 * 1024 * 1024;
	size_t max_post_body = 16 * 1024;
};

// Is `target` (path and query exactly as received) something the proxy will
// forward? Exposed for tests.
bool is_proxyable_target(const std::string& target);
// The paths that may be POSTed (without a query). Exposed for tests.
bool is_postable_path(const std::string& path);

class UiServer {
public:
	explicit UiServer(UiConfig config);
	~UiServer();

	// Binds and returns the port; throws std::runtime_error if that fails.
	int bind();
	void run();
	void stop();

private:
	UiConfig config_;
	std::unique_ptr<httplib::Server> server_;
};

} // namespace proculus

#endif // PROCULUS_UI_SERVER_HPP
