#include "analyze.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <cstring>

#include "proculus/netutil/target.h"

namespace proculus {

const char* to_string(FetchError e) {
	switch (e) {
	case FetchError::None: return "none";
	case FetchError::ConnectRefused: return "connection_refused";
	case FetchError::ConnectTimeout: return "connect_timeout";
	case FetchError::ConnectFailed: return "connect_failed";
	case FetchError::Timeout: return "timeout";
	case FetchError::Reset: return "reset";
	case FetchError::TlsFailed: return "tls_failed";
	case FetchError::NotHttp: return "not_http";
	case FetchError::Protocol: return "protocol_error";
	}
	return "?";
}

namespace {

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

bool iequals(const std::string& a, const std::string& b) { return a.size() == b.size() && lower(a) == lower(b); }

std::string trim(const std::string& s) {
	size_t a = 0, b = s.size();
	while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
	while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
	return s.substr(a, b - a);
}

void append_utf8(std::string& out, uint32_t cp) {
	if (cp < 0x80) out += static_cast<char>(cp);
	else if (cp < 0x800) {
		out += static_cast<char>(0xC0 | (cp >> 6));
		out += static_cast<char>(0x80 | (cp & 0x3F));
	} else if (cp < 0x10000) {
		out += static_cast<char>(0xE0 | (cp >> 12));
		out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
		out += static_cast<char>(0x80 | (cp & 0x3F));
	} else {
		out += static_cast<char>(0xF0 | (cp >> 18));
		out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
		out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
		out += static_cast<char>(0x80 | (cp & 0x3F));
	}
}

// The named entities that turn up in real page titles (typography, symbols and
// the common accented letters). 0 if the name is not one of them.
uint32_t named_entity(const std::string& name) {
	static const struct { const char* name; uint32_t cp; } table[] = {
		{"mdash", 0x2014}, {"ndash", 0x2013}, {"hellip", 0x2026}, {"copy", 0xA9}, {"reg", 0xAE}, {"trade", 0x2122},
		{"laquo", 0xAB}, {"raquo", 0xBB}, {"lsquo", 0x2018}, {"rsquo", 0x2019}, {"ldquo", 0x201C}, {"rdquo", 0x201D},
		{"bull", 0x2022}, {"middot", 0xB7}, {"euro", 0x20AC}, {"pound", 0xA3}, {"yen", 0xA5}, {"cent", 0xA2}, {"deg", 0xB0},
		{"times", 0xD7}, {"divide", 0xF7}, {"plusmn", 0xB1}, {"para", 0xB6}, {"sect", 0xA7},
		{"aacute", 0xE1}, {"eacute", 0xE9}, {"iacute", 0xED}, {"oacute", 0xF3}, {"uacute", 0xFA}, {"agrave", 0xE0},
		{"egrave", 0xE8}, {"auml", 0xE4}, {"ouml", 0xF6}, {"uuml", 0xFC}, {"szlig", 0xDF}, {"ccedil", 0xE7}, {"ntilde", 0xF1},
		{"acirc", 0xE2}, {"ecirc", 0xEA}, {"ocirc", 0xF4}, {"Aacute", 0xC1}, {"Eacute", 0xC9}, {"Oacute", 0xD3},
		{"Auml", 0xC4}, {"Ouml", 0xD6}, {"Uuml", 0xDC}, {"Ccedil", 0xC7}, {"Ntilde", 0xD1},
	};
	for (const auto& e : table)
		if (name == e.name) return e.cp;
	return 0;
}

// Decodes the entities that matter in titles; anything else stays as is.
std::string decode_entities(const std::string& s) {
	std::string out;
	for (size_t i = 0; i < s.size(); i++) {
		if (s[i] != '&') {
			out += s[i];
			continue;
		}
		const size_t semi = s.find(';', i);
		if (semi == std::string::npos || semi - i > 10) {
			out += s[i];
			continue;
		}
		const std::string name = s.substr(i + 1, semi - i - 1);
		if (name == "amp") out += '&';
		else if (name == "lt") out += '<';
		else if (name == "gt") out += '>';
		else if (name == "quot") out += '"';
		else if (name == "apos") out += '\'';
		else if (name == "nbsp") out += ' ';
		else if (const uint32_t cp = named_entity(name)) append_utf8(out, cp);
		else if (name.size() >= 2 && name[0] == '#') {
			const bool hex = name[1] == 'x' || name[1] == 'X';
			const std::string digits = name.substr(hex ? 2 : 1);
			char* end = nullptr;
			const unsigned long cp = digits.empty() ? 0 : std::strtoul(digits.c_str(), &end, hex ? 16 : 10);
			if (digits.empty() || *end != '\0' || cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
				out += s[i];
				continue;
			}
			append_utf8(out, static_cast<uint32_t>(cp));
		} else {
			out += s[i];
			continue;
		}
		i = semi;
	}
	return out;
}

} // namespace

const std::string* find_header(const std::vector<Header>& headers, const std::string& name) {
	for (const Header& h : headers)
		if (iequals(h.name, name)) return &h.value;
	return nullptr;
}

// ------------------------------------------------------------------- title

std::string extract_title(const std::string& html) {
	// Case-insensitive search for "<title" followed by '>' or whitespace.
	const std::string low = lower(html.substr(0, 256 * 1024));
	size_t pos = 0;
	size_t open = std::string::npos;
	while ((pos = low.find("<title", pos)) != std::string::npos) {
		const char next = pos + 6 < low.size() ? low[pos + 6] : '\0';
		if (next == '>' || std::isspace(static_cast<unsigned char>(next))) {
			open = pos;
			break;
		}
		pos += 6;
	}
	if (open == std::string::npos) return "";
	const size_t gt = low.find('>', open);
	if (gt == std::string::npos) return "";
	const size_t close = low.find("</title", gt);
	const size_t end = close == std::string::npos ? std::min(low.size(), gt + 1 + 1024) : close;

	std::string raw = decode_entities(html.substr(gt + 1, end - gt - 1));
	std::string out;
	bool pending_space = false;
	for (unsigned char c : raw) {
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			pending_space = !out.empty();
			continue;
		}
		if (c < 0x20 || c == 0x7f) continue; // other control characters are dropped
		if (pending_space) {
			out += ' ';
			pending_space = false;
		}
		out += static_cast<char>(c);
		if (out.size() >= 200) break;
	}
	return trim(out);
}

// ----------------------------------------------------------------- cookies

std::optional<Cookie> parse_set_cookie(const std::string& header_value, bool keep_value) {
	// name=value; Attr; Attr=value ...
	std::vector<std::string> parts;
	size_t start = 0;
	for (;;) {
		const size_t semi = header_value.find(';', start);
		parts.push_back(header_value.substr(start, semi == std::string::npos ? std::string::npos : semi - start));
		if (semi == std::string::npos) break;
		start = semi + 1;
	}
	const std::string first = trim(parts[0]);
	const size_t eq = first.find('=');
	if (eq == std::string::npos || eq == 0) return std::nullopt;

	Cookie c;
	c.name = trim(first.substr(0, eq));
	if (c.name.empty() || c.name.size() > 256) return std::nullopt;
	for (unsigned char ch : c.name)
		if (ch < 0x21 || ch == 0x7f || ch == '"') return std::nullopt; // not a token
	const std::string value = first.substr(eq + 1);
	c.value_length = value.size();
	if (keep_value) c.value = value;

	for (size_t i = 1; i < parts.size(); i++) {
		const std::string attr = trim(parts[i]);
		const size_t aeq = attr.find('=');
		const std::string key = lower(trim(aeq == std::string::npos ? attr : attr.substr(0, aeq)));
		const std::string val = aeq == std::string::npos ? "" : trim(attr.substr(aeq + 1));
		if (key == "secure") c.secure = true;
		else if (key == "httponly") c.http_only = true;
		else if (key == "samesite") {
			const std::string v = lower(val);
			c.same_site = v == "lax" ? "Lax" : v == "strict" ? "Strict" : v == "none" ? "None" : "";
		} else if (key == "path") c.path = val.substr(0, 256);
		else if (key == "domain") c.domain = val.substr(0, 256);
		else if (key == "expires" || key == "max-age") c.has_expiry = true;
	}
	return c;
}

std::string redact_set_cookie(const std::string& header_value) {
	const size_t semi = header_value.find(';');
	const std::string first = header_value.substr(0, semi);
	const size_t eq = first.find('=');
	if (eq == std::string::npos || eq == 0) return "<redacted>";
	return first.substr(0, eq + 1) + "<redacted>" + (semi == std::string::npos ? "" : header_value.substr(semi));
}

// -------------------------------------------------------------------- urls

namespace {

bool default_port(const std::string& scheme, uint16_t port) { return (scheme == "http" && port == 80) || (scheme == "https" && port == 443); }

// Removes "." and ".." segments from the path part (RFC 3986 section 5.2.4),
// leaving any query string untouched.
std::string normalize_path(const std::string& path_and_query) {
	const size_t q = path_and_query.find('?');
	std::string path = path_and_query.substr(0, q);
	const std::string query = q == std::string::npos ? "" : path_and_query.substr(q);
	if (path.empty() || path[0] != '/') path = "/" + path;

	std::vector<std::string> segments;
	size_t i = 1;
	for (;;) {
		const size_t slash = path.find('/', i);
		const bool last = slash == std::string::npos;
		const std::string seg = path.substr(i, last ? std::string::npos : slash - i);
		if (seg == ".") {
			if (last) segments.push_back(""); // "/a/." ends with a slash
		} else if (seg == "..") {
			if (!segments.empty()) segments.pop_back();
			if (last) segments.push_back("");
		} else {
			segments.push_back(seg);
		}
		if (last) break;
		i = slash + 1;
	}
	std::string out;
	for (const std::string& s : segments) out += "/" + s;
	return (out.empty() ? "/" : out) + query;
}

} // namespace

std::string Url::to_string() const {
	return scheme + "://" + host + (default_port(scheme, port) ? "" : ":" + std::to_string(port)) + path;
}

std::optional<Url> parse_url(const std::string& text) {
	if (text.size() > 2048) return std::nullopt;
	Url u;
	size_t rest;
	if (text.compare(0, 7, "http://") == 0 || text.compare(0, 7, "HTTP://") == 0) {
		u.scheme = "http";
		u.port = 80;
		rest = 7;
	} else if (text.compare(0, 8, "https://") == 0 || text.compare(0, 8, "HTTPS://") == 0) {
		u.scheme = "https";
		u.port = 443;
		rest = 8;
	} else {
		return std::nullopt;
	}
	const size_t end = text.find_first_of("/?#", rest);
	const std::string authority = text.substr(rest, end == std::string::npos ? std::string::npos : end - rest);
	if (authority.empty() || authority.find('@') != std::string::npos || authority.find('[') != std::string::npos) return std::nullopt;

	std::string host = authority;
	if (const size_t colon = authority.find(':'); colon != std::string::npos) {
		host = authority.substr(0, colon);
		const std::string port = authority.substr(colon + 1);
		if (port.empty() || port.size() > 5 || port.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
		const unsigned long p = std::stoul(port);
		if (p < 1 || p > 65535) return std::nullopt;
		u.port = static_cast<uint16_t>(p);
	}
	u.host = lower(host);
	if (!valid_host(u.host)) return std::nullopt;

	std::string tail = end == std::string::npos ? "/" : text.substr(end);
	if (const size_t hash = tail.find('#'); hash != std::string::npos) tail.erase(hash);
	if (tail.empty() || tail[0] == '?') tail = "/" + tail;
	u.path = tail;
	return u;
}

std::optional<Url> resolve_location(const Url& base, const std::string& location) {
	const std::string loc = trim(location);
	if (loc.empty() || loc.size() > 2048) return std::nullopt;
	for (unsigned char c : loc)
		if (c < 0x20 || c == 0x7f) return std::nullopt;

	if (loc.compare(0, 2, "//") == 0) return parse_url(base.scheme + ":" + loc);
	if (loc[0] == '/') {
		Url u = base;
		std::string p = loc;
		if (const size_t hash = p.find('#'); hash != std::string::npos) p.erase(hash);
		u.path = normalize_path(p.empty() ? "/" : p);
		return u;
	}
	// A string with a scheme: "http://...", "javascript:...", "mailto:...".
	const size_t colon = loc.find(':');
	const size_t slash = loc.find('/');
	if (colon != std::string::npos && (slash == std::string::npos || colon < slash)) {
		auto u = parse_url(loc);
		if (u) u->path = normalize_path(u->path);
		return u;
	}
	// relative path: resolve against the directory of the base path
	Url u = base;
	std::string p = loc;
	if (const size_t hash = p.find('#'); hash != std::string::npos) p.erase(hash);
	if (p.empty()) return u;
	if (p[0] == '?') {
		u.path = base.path.substr(0, base.path.find('?')) + p;
		return u;
	}
	const std::string base_path = base.path.substr(0, base.path.find('?'));
	const std::string dir = base_path.substr(0, base_path.rfind('/') + 1);
	u.path = normalize_path(dir + p);
	return u;
}

bool valid_host(const std::string& host) {
	if (host.empty() || host.size() > 253) return false;
	pc_target t;
	if (pc_target_parse(host.c_str(), &t) != 0) return false;
	// a single IP or a host name; a CIDR block or range is not a host
	return (t.kind == PC_TARGET_IP || t.kind == PC_TARGET_DOMAIN) && host.find_first_of(" \t\r\n") == std::string::npos;
}

bool valid_path(const std::string& path) {
	if (path.empty() || path[0] != '/' || path.size() > 2048) return false;
	for (unsigned char c : path)
		if (c <= 0x20 || c >= 0x7f) return false;
	return true;
}

std::string find_icon_href(const std::string& html) {
	const std::string head = html.substr(0, 256 * 1024);
	const std::string low = lower(head);
	size_t pos = 0;
	while ((pos = low.find("<link", pos)) != std::string::npos) {
		const size_t end = low.find('>', pos);
		if (end == std::string::npos) return "";
		const std::string tag = head.substr(pos, end - pos);
		pos = end;

		// pull the attributes out of the tag: name=value, name="value", name='value'
		std::string rel, href;
		size_t i = 5;
		while (i < tag.size()) {
			while (i < tag.size() && (std::isspace(static_cast<unsigned char>(tag[i])) || tag[i] == '/')) i++;
			size_t name_start = i;
			while (i < tag.size() && !std::isspace(static_cast<unsigned char>(tag[i])) && tag[i] != '=' && tag[i] != '/') i++;
			const std::string name = lower(tag.substr(name_start, i - name_start));
			while (i < tag.size() && std::isspace(static_cast<unsigned char>(tag[i]))) i++;
			if (i >= tag.size() || tag[i] != '=') continue;
			i++;
			while (i < tag.size() && std::isspace(static_cast<unsigned char>(tag[i]))) i++;
			std::string value;
			if (i < tag.size() && (tag[i] == '"' || tag[i] == '\'')) {
				const char q = tag[i++];
				const size_t close = tag.find(q, i);
				value = tag.substr(i, close == std::string::npos ? std::string::npos : close - i);
				i = close == std::string::npos ? tag.size() : close + 1;
			} else {
				const size_t vstart = i;
				while (i < tag.size() && !std::isspace(static_cast<unsigned char>(tag[i]))) i++;
				value = tag.substr(vstart, i - vstart);
			}
			if (name == "rel") rel = lower(value);
			else if (name == "href") href = value;
		}
		// rel is a space separated list of tokens; "icon" or "shortcut icon" qualify
		bool icon = false;
		size_t t = 0;
		while (t < rel.size()) {
			const size_t sp = rel.find(' ', t);
			const std::string token = rel.substr(t, sp == std::string::npos ? std::string::npos : sp - t);
			if (token == "icon") icon = true;
			if (sp == std::string::npos) break;
			t = sp + 1;
		}
		if (icon && !href.empty()) return decode_entities(trim(href));
	}
	return "";
}

// ------------------------------------------------------------- fingerprints

int32_t murmur3_32(const std::string& data, uint32_t seed) {
	const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());
	const size_t len = data.size();
	const size_t blocks = len / 4;
	uint32_t h = seed;
	const uint32_t c1 = 0xcc9e2d51, c2 = 0x1b873593;
	auto rotl = [](uint32_t x, int r) { return (x << r) | (x >> (32 - r)); };

	for (size_t i = 0; i < blocks; i++) {
		uint32_t k = static_cast<uint32_t>(p[i * 4]) | static_cast<uint32_t>(p[i * 4 + 1]) << 8 |
			static_cast<uint32_t>(p[i * 4 + 2]) << 16 | static_cast<uint32_t>(p[i * 4 + 3]) << 24;
		k *= c1;
		k = rotl(k, 15);
		k *= c2;
		h ^= k;
		h = rotl(h, 13);
		h = h * 5 + 0xe6546b64;
	}
	const uint8_t* tail = p + blocks * 4;
	uint32_t k = 0;
	switch (len & 3) {
	case 3: k ^= static_cast<uint32_t>(tail[2]) << 16; [[fallthrough]];
	case 2: k ^= static_cast<uint32_t>(tail[1]) << 8; [[fallthrough]];
	case 1:
		k ^= tail[0];
		k *= c1;
		k = rotl(k, 15);
		k *= c2;
		h ^= k;
	}
	h ^= static_cast<uint32_t>(len);
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return static_cast<int32_t>(h);
}

std::string base64_mime(const std::string& bytes) {
	static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out, line;
	size_t i = 0;
	auto emit = [&](char c) {
		line += c;
		if (line.size() == 76) {
			out += line + "\n";
			line.clear();
		}
	};
	for (; i + 2 < bytes.size(); i += 3) {
		const uint32_t v = static_cast<uint8_t>(bytes[i]) << 16 | static_cast<uint8_t>(bytes[i + 1]) << 8 | static_cast<uint8_t>(bytes[i + 2]);
		emit(tbl[v >> 18]);
		emit(tbl[(v >> 12) & 63]);
		emit(tbl[(v >> 6) & 63]);
		emit(tbl[v & 63]);
	}
	if (i + 1 == bytes.size()) {
		const uint32_t v = static_cast<uint8_t>(bytes[i]) << 16;
		emit(tbl[v >> 18]);
		emit(tbl[(v >> 12) & 63]);
		emit('=');
		emit('=');
	} else if (i + 2 == bytes.size()) {
		const uint32_t v = static_cast<uint8_t>(bytes[i]) << 16 | static_cast<uint8_t>(bytes[i + 1]) << 8;
		emit(tbl[v >> 18]);
		emit(tbl[(v >> 12) & 63]);
		emit(tbl[(v >> 6) & 63]);
		emit('=');
	}
	if (!line.empty()) out += line + "\n";
	return out;
}

int32_t favicon_hash(const std::string& icon_bytes) { return murmur3_32(base64_mime(icon_bytes)); }

std::string sha256_hex(const std::string& data) {
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n = 0;
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
	EVP_DigestUpdate(ctx, data.data(), data.size());
	EVP_DigestFinal_ex(ctx, md, &n);
	EVP_MD_CTX_free(ctx);
	static const char* hex = "0123456789abcdef";
	std::string out;
	for (unsigned int i = 0; i < n; i++) {
		out += hex[md[i] >> 4];
		out += hex[md[i] & 15];
	}
	return out;
}

} // namespace proculus
