#ifndef PROCULUS_HTTP_TYPES_HPP
#define PROCULUS_HTTP_TYPES_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace proculus {

struct Header {
	std::string name;
	std::string value;
};

// Where to connect. The address is always a literal IPv4 address (no DNS is
// done while probing); `host` is what goes into the Host header and the TLS
// SNI extension, and defaults to the address.
struct Endpoint {
	std::string ip;
	uint16_t port = 80;
	bool tls = false;
	std::string host;
};

struct TransportLimits {
	size_t max_body = 128 * 1024;       // body bytes kept; more is dropped and flagged
	size_t max_header_bytes = 64 * 1024; // status line + headers
	size_t max_headers = 100;
	int connect_timeout_ms = 3000;
	int total_timeout_ms = 8000;         // for the whole exchange
	std::string user_agent = "Proculus-Scanner/0.1";
};

struct HttpResponse {
	int status = 0;
	std::string reason;
	std::string version; // "HTTP/1.1"
	std::vector<Header> headers;
	std::string body;
	bool body_truncated = false;
};

struct CertInfo {
	std::string subject;     // RFC 2253 style, e.g. "CN=example.org,O=Example"
	std::string issuer;
	std::string serial;      // hex
	std::string not_before;  // UTC, 2026-11-21T00:00:00Z
	std::string not_after;
	std::vector<std::string> san; // DNS names and IP addresses
	std::string sha256;      // fingerprint of the DER certificate, hex
	std::string key_type;    // "RSA", "EC", "Ed25519", ...
	int key_bits = 0;
	std::string signature_algorithm;
	bool self_signed = false;
	bool expired = false;       // not_after is in the past
	bool not_yet_valid = false; // not_before is in the future
	std::optional<bool> hostname_match; // does the certificate cover Endpoint::host? (unset if not checked)
};

struct TlsInfo {
	std::string version; // "TLSv1.3"
	std::string cipher;
	std::optional<CertInfo> certificate; // the server's own certificate
	size_t chain_length = 0;
	std::string alpn;
};

enum class FetchError {
	None,
	ConnectRefused,
	ConnectTimeout,
	ConnectFailed, // unreachable, no route, ...
	Timeout,       // connected, but the exchange did not finish in time
	Reset,         // the peer closed or reset the connection too early
	TlsFailed,     // the TLS handshake did not complete
	NotHttp,       // the peer answered with something that is not HTTP
	Protocol,      // HTTP, but malformed or over a limit
};

const char* to_string(FetchError e);

// The result of one request. Network failures are reported here, not thrown.
struct Exchange {
	FetchError error = FetchError::None;
	std::string error_detail;
	std::optional<HttpResponse> response;
	std::optional<TlsInfo> tls;
	std::string banner; // when NotHttp: the first printable bytes the peer sent
	double connect_ms = 0;
	double total_ms = 0;
};

// First value of a header (case-insensitive name), or nullptr.
const std::string* find_header(const std::vector<Header>& headers, const std::string& name);

} // namespace proculus

#endif // PROCULUS_HTTP_TYPES_HPP
