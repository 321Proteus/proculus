#ifndef PROCULUS_PROBER_HPP
#define PROCULUS_PROBER_HPP

// Looks at a web service the way a browser's first request would, and writes
// down what it saw: status, headers, cookies, title, redirects, TLS
// certificate, favicon fingerprint. It does this safely:
//
//  * Only addresses inside the configured scope and ports inside the allowed
//    list are ever contacted; reserved addresses are refused unless allowed.
//  * Redirects are followed only when they stay on the same host (the address
//    probed, or the host name given for it). A redirect to anywhere else is
//    recorded and not followed, so a site cannot steer the scanner elsewhere.
//  * Only GET, only `/`, the favicon and a short, fixed list of plain paths the
//    caller asked for (ProbeLimits::probe_paths, normally what signatures need):
//    no logins, no forms, no query strings, no guessing.
//  * Cookie values (often session secrets) are not stored unless asked for.
//  * Requests are rate limited.

#include <chrono>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "analyze.hpp"
#include "http_types.hpp"
#include "transport.hpp"

namespace proculus {

struct ProbeLimits {
	std::string scope;           // required: addresses that may be probed
	std::string allowed_ports;   // required: ports that may be probed
	bool allow_reserved = false; // loopback, multicast, ...
	int max_redirects = 3;
	double max_requests_per_second = 10;
	bool fetch_favicon = true;
	bool keep_cookie_values = false;
	// Extra paths to fetch (GET, same final site, no redirects followed) once
	// the main exchange succeeded. Each must pass valid_path() and have no '?'.
	std::vector<std::string> probe_paths;
	size_t path_max_body = 64 * 1024;
	TransportLimits transport;
};

// A target the prober refuses to contact; what() says why.
struct ProbeRefused : std::runtime_error {
	using std::runtime_error::runtime_error;
};

// What an earlier scan (nmap) already said about the service; carried into the
// evidence so signatures can use it. All of it is untrusted text.
struct ServiceHint {
	std::string name, product, version;
	std::vector<std::string> hostnames;
};

struct ProbeTarget {
	ProbeTarget() = default;
	ProbeTarget(std::string ip, uint16_t port, std::optional<bool> tls = std::nullopt, std::string host = "")
		: ip(std::move(ip)), port(port), tls(tls), host(std::move(host)) {}

	std::string ip;
	uint16_t port = 0;
	std::optional<bool> tls;  // unset: https on the usual TLS ports (443, 8443, ...), http otherwise
	std::string host;         // Host header / SNI name; empty = the address itself
	ServiceHint service;
};

struct Hop {
	std::string url;       // what was requested
	int status = 0;
	std::string location;  // the Location header as sent, if any
	bool followed = false;
	std::string note;      // why a redirect was not followed
};

// One extra path that was fetched.
struct PathResult {
	std::string path;
	int status = 0;               // 0: no HTTP response
	std::string content_type;
	std::string title;
	std::string redirect;         // Location header, not followed
	std::vector<Header> headers;
	std::string body;
	FetchError error = FetchError::None;
};

struct HttpObservation {
	std::string ip;
	uint16_t port = 0;
	bool tls = false;      // of the final response
	std::string host;      // as probed

	std::string url;       // the final URL
	int status = 0;        // 0 if no HTTP response arrived
	std::string reason;
	std::string http_version;
	std::vector<Header> headers;
	std::vector<Cookie> cookies;  // set anywhere along the redirect chain
	std::string server;           // Server header
	std::string content_type;
	std::string title;
	size_t body_length = 0;       // bytes kept
	bool body_truncated = false;
	std::string body_sha256;      // of the bytes kept
	std::string body;             // kept in memory for signature matching; not part of the JSON unless asked

	std::vector<Hop> redirects;
	std::optional<TlsInfo> tls_info;
	std::optional<int32_t> favicon_hash;
	std::vector<PathResult> paths;
	ServiceHint service;          // copied from the target

	FetchError error = FetchError::None; // set together with a partial response, or alone
	std::string error_detail;
	std::string banner;           // when the service answered something that is not HTTP
	double elapsed_ms = 0;
	int requests = 0;             // requests sent, favicon included
};

// Spaces requests at most 1/rate seconds apart. The clock and the sleep are
// injectable so tests need not wait.
class RateGate {
public:
	using Clock = std::chrono::steady_clock;
	explicit RateGate(double per_second, std::function<Clock::time_point()> now = [] { return Clock::now(); },
		std::function<void(std::chrono::nanoseconds)> sleep = [](std::chrono::nanoseconds d) { std::this_thread::sleep_for(d); });
	void wait();

private:
	std::chrono::nanoseconds interval_;
	std::function<Clock::time_point()> now_;
	std::function<void(std::chrono::nanoseconds)> sleep_;
	std::optional<Clock::time_point> next_;
};

class HttpProber {
public:
	// Throws std::invalid_argument for an unusable configuration (no scope, no
	// allowed ports, bad rate). The transport must outlive the prober.
	HttpProber(HttpTransport& transport, ProbeLimits limits);
	HttpProber(HttpTransport& transport, ProbeLimits limits, RateGate gate);

	// Throws ProbeRefused if the target is not allowed (outside the scope,
	// port not allowed, reserved address, malformed address or host).
	// Network trouble is not an exception: it is in the observation.
	HttpObservation probe(const ProbeTarget& target);

private:
	struct Impl;
	HttpTransport& transport_;
	ProbeLimits limits_;
	RateGate gate_;
};

// Which port numbers are TLS by default.
bool default_tls_port(uint16_t port);

// Decides how to probe a service nmap found: nullopt if it does not look like a
// web service. `name` is nmap's service name ("http", "https", "http-proxy",
// "ssl/http", ...).
std::optional<bool> web_service_scheme(const std::string& name, uint16_t port);

} // namespace proculus

#endif // PROCULUS_PROBER_HPP
