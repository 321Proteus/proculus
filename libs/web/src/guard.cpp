#include "proculus/web/guard.hpp"

#include <algorithm>
#include <stdexcept>

namespace proculus::web {

namespace {

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

} // namespace

const char* const kPageContentSecurityPolicy =
	"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const char* const kApiContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";

std::string host_name_of(const std::string& header) {
	const std::string h = lower(header);
	if (!h.empty() && h[0] == '[') {
		const size_t end = h.find(']');
		return end == std::string::npos ? h : h.substr(0, end + 1);
	}
	return h.substr(0, h.find(':'));
}

std::vector<std::string> default_allowed_hosts() { return {"localhost", "127.0.0.1", "[::1]"}; }

bool host_allowed(const std::string& host_header, const std::vector<std::string>& allowed) {
	return std::find(allowed.begin(), allowed.end(), host_name_of(host_header)) != allowed.end();
}

int parse_port(const std::string& text) {
	if (text.empty() || text.size() > 5 || text.find_first_not_of("0123456789") != std::string::npos) throw std::invalid_argument("invalid port: " + text);
	const int p = std::stoi(text);
	if (p < 1 || p > 65535) throw std::invalid_argument("invalid port: " + text);
	return p;
}

Upstream parse_upstream(const std::string& text) {
	std::string rest = text;
	if (rest.compare(0, 7, "http://") == 0) rest = rest.substr(7);
	else if (rest.find("://") != std::string::npos) throw std::invalid_argument("only http:// upstreams are supported: " + text);
	if (!rest.empty() && rest.back() == '/') rest.pop_back();
	if (rest.empty() || rest.find('/') != std::string::npos || rest.find('@') != std::string::npos || rest.find('?') != std::string::npos)
		throw std::invalid_argument("expected http://host[:port], got: " + text);
	Upstream u;
	const size_t colon = rest.rfind(':');
	if (colon != std::string::npos) {
		u.host = rest.substr(0, colon);
		u.port = parse_port(rest.substr(colon + 1));
	} else {
		u.host = rest;
	}
	if (u.host.empty()) throw std::invalid_argument("missing host in upstream: " + text);
	for (unsigned char c : u.host)
		if (!(std::isalnum(c) || c == '.' || c == '-' || c == '_')) throw std::invalid_argument("bad host name in upstream: " + text);
	return u;
}

} // namespace proculus::web
