#ifndef PROCULUS_ANALYZE_HPP
#define PROCULUS_ANALYZE_HPP

// Pure helpers for making sense of what a web server returned. Nothing here
// touches the network. Everything operates on untrusted input.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "http_types.hpp"

namespace proculus {

// The text of the first <title> element, with entities decoded, whitespace
// collapsed and control characters removed; at most 200 bytes. "" if none.
std::string extract_title(const std::string& html);

struct Cookie {
	std::string name;
	size_t value_length = 0;
	std::string value; // only filled when asked for: values are often session secrets
	bool secure = false;
	bool http_only = false;
	std::string same_site; // "Lax", "Strict", "None" or ""
	std::string path;
	std::string domain;
	bool has_expiry = false; // Expires or Max-Age present: a persistent cookie
};

// Parses one Set-Cookie header value. nullopt if it has no usable name.
std::optional<Cookie> parse_set_cookie(const std::string& header_value, bool keep_value = false);

struct Url {
	std::string scheme; // "http" or "https"
	std::string host;   // literal IPv4 address or host name, lowercase
	uint16_t port = 80;
	std::string path = "/"; // with query, no fragment

	std::string to_string() const; // default ports are omitted
};

// "http://host[:port]/path": http and https only, no userinfo, no IPv6 literals.
std::optional<Url> parse_url(const std::string& text);

// Resolves a Location header against the URL of the request. Handles absolute
// URLs, "//host/path", "/path" and relative paths (with "." and ".." segments).
// nullopt for other schemes, empty or oversized values.
std::optional<Url> resolve_location(const Url& base, const std::string& location);

// A literal IPv4 address or a syntactically valid host name: safe to put in a
// Host header. Rejects anything with whitespace, control characters or ports.
bool valid_host(const std::string& host);

// A request path that cannot smuggle extra headers or requests: starts with
// '/', printable ASCII only, no spaces, at most 2048 bytes.
bool valid_path(const std::string& path);

// The href of the first <link rel="icon"> / "shortcut icon" in the document,
// as written (not resolved). "" if there is none.
std::string find_icon_href(const std::string& html);

// MurmurHash3 (x86, 32-bit), as a signed integer like most fingerprint databases use.
int32_t murmur3_32(const std::string& data, uint32_t seed = 0);

// Base64 with a line break every 76 characters and a trailing one (what
// Python's base64.encodebytes produces).
std::string base64_mime(const std::string& bytes);

// The favicon fingerprint used by Shodan and similar tools: murmur3 over the
// MIME-base64 form of the icon bytes.
int32_t favicon_hash(const std::string& icon_bytes);

// Lowercase hex SHA-256.
std::string sha256_hex(const std::string& data);

} // namespace proculus

#endif // PROCULUS_ANALYZE_HPP
