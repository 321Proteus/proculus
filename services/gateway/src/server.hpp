#ifndef PROCULUS_GATEWAY_SERVER_HPP
#define PROCULUS_GATEWAY_SERVER_HPP

// The web server of the gateway: the read-only JSON API that the UI service
// (services/ui) shows. It serves no pages.
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

namespace httplib {
class Server;
}

namespace proculus {

struct ServerConfig {
	std::string bind = "127.0.0.1";
	int port = 8081;                           // 0: pick a free port (tests)
	std::vector<std::string> allowed_hosts;    // besides localhost, 127.0.0.1 and [::1]
};

class WebServer {
public:
	WebServer(const ResultStore& store, ServerConfig config);
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
	std::unique_ptr<httplib::Server> server_;
	int port_ = 0;
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_SERVER_HPP
