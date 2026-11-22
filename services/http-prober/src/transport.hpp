#ifndef PROCULUS_TRANSPORT_HPP
#define PROCULUS_TRANSPORT_HPP

#include <string>

#include "http_types.hpp"

namespace proculus {

// Sends one GET request and reads the answer. The prober only talks to this
// interface, so it can be driven by a scripted fake in tests or by the
// emulated network, and by SocketTransport for real.
class HttpTransport {
public:
	virtual ~HttpTransport() = default;

	// Network trouble is reported in Exchange::error, never thrown. A partial
	// response can come back together with an error (e.g. Timeout while the
	// body was still arriving).
	virtual Exchange get(const Endpoint& endpoint, const std::string& path, const TransportLimits& limits) = 0;
};

// Real sockets, with TLS through OpenSSL. IPv4 only, no DNS lookups.
//
// What it will and will not do:
//  * GET only, HTTP/1.1, "Connection: close", "Accept-Encoding: identity".
//  * It sends no credentials, no cookies, no request body.
//  * Certificates are inspected but NOT verified: the point is to look at
//    servers whatever state their certificates are in. Nothing sensitive is
//    ever sent over such a connection.
//  * Every read and write is bounded by the total timeout, headers and body by
//    the size limits.
class SocketTransport : public HttpTransport {
public:
	Exchange get(const Endpoint& endpoint, const std::string& path, const TransportLimits& limits) override;
};

} // namespace proculus

#endif // PROCULUS_TRANSPORT_HPP
