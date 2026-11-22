#ifndef PROCULUS_WEB_GUARD_HPP
#define PROCULUS_WEB_GUARD_HPP

// Small pieces shared by the web-facing services (the API in the gateway and
// the UI server), so both apply the same rules.

#include <string>
#include <vector>

namespace proculus::web {

// Host header value ("localhost:8080", "[::1]:80", "a.example") -> host name
// without the port, lowercase.
std::string host_name_of(const std::string& host_header);

// The names a local server answers to by default.
std::vector<std::string> default_allowed_hosts();

// True if the Host header names one of `allowed` (names without ports,
// lowercase). Servers without login check this on every request: a web page on
// another site could otherwise reach them through DNS rebinding, because the
// browser would send the attacker's host name, not "localhost".
bool host_allowed(const std::string& host_header, const std::vector<std::string>& allowed);

// For pages that load only their own scripts and styles and talk only to
// their own origin.
extern const char* const kPageContentSecurityPolicy;
// For JSON responses: nothing may load or run.
extern const char* const kApiContentSecurityPolicy;

// A port number from text: 1..65535, digits only. Throws std::invalid_argument.
int parse_port(const std::string& text);

struct Upstream {
	std::string host;
	int port = 80;
};
// "http://host:port" (also without "http://", port optional): the only form
// accepted, so the UI cannot be pointed at other schemes or paths.
// Throws std::invalid_argument.
Upstream parse_upstream(const std::string& text);

} // namespace proculus::web

#endif // PROCULUS_WEB_GUARD_HPP
