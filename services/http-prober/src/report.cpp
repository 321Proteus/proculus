#include "report.hpp"

#include <algorithm>
#include <sstream>

namespace proculus {

namespace {

std::string printable(std::string s) {
	for (char& c : s)
		if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = '?';
	return s;
}

ProbeJson cert_json(const CertInfo& c) {
	ProbeJson j = { { "subject", c.subject }, { "issuer", c.issuer }, { "serial", c.serial }, { "not_before", c.not_before },
		{ "not_after", c.not_after }, { "san", c.san }, { "sha256", c.sha256 }, { "key_type", c.key_type },
		{ "key_bits", c.key_bits }, { "signature_algorithm", c.signature_algorithm }, { "self_signed", c.self_signed },
		{ "expired", c.expired }, { "not_yet_valid", c.not_yet_valid } };
	if (c.hostname_match) j["hostname_match"] = *c.hostname_match;
	return j;
}

const char* category_name(sig::Category c) { return sig::to_string(c); }

ProbeJson detection_json(const sig::Detection& d) {
	ProbeJson j = { { "id", d.id }, { "name", d.name }, { "category", category_name(d.category) }, { "confidence", d.confidence },
		{ "interest", d.interest }, { "builtin", d.builtin }, { "tags", d.tags }, { "evidence", d.evidence } };
	if (!d.version.empty()) j["version"] = d.version;
	return j;
}

} // namespace

ProbeJson probe_to_json(const HttpObservation& o, bool include_body, const Detections* detections) {
	ProbeJson j = { { "ip", o.ip }, { "port", o.port }, { "tls", o.tls }, { "host", o.host }, { "url", o.url }, { "status", o.status },
		{ "reason", o.reason }, { "http_version", o.http_version }, { "server", o.server }, { "content_type", o.content_type },
		{ "title", o.title } };

	j["headers"] = ProbeJson::array();
	for (const Header& h : o.headers) j["headers"].push_back({ { "name", h.name }, { "value", h.value } });

	j["cookies"] = ProbeJson::array();
	for (const Cookie& c : o.cookies) {
		ProbeJson cj = { { "name", c.name }, { "value_length", c.value_length }, { "secure", c.secure }, { "http_only", c.http_only },
			{ "same_site", c.same_site }, { "path", c.path }, { "domain", c.domain }, { "persistent", c.has_expiry } };
		if (!c.value.empty()) cj["value"] = c.value; // present only when the run asked to keep values
		j["cookies"].push_back(std::move(cj));
	}

	j["redirects"] = ProbeJson::array();
	for (const Hop& h : o.redirects)
		j["redirects"].push_back({ { "url", h.url }, { "status", h.status }, { "location", h.location }, { "followed", h.followed }, { "note", h.note } });

	j["body"] = { { "length", o.body_length }, { "truncated", o.body_truncated }, { "sha256", o.body_sha256 } };
	if (include_body) j["body"]["content"] = o.body;

	if (o.tls_info) {
		ProbeJson t = { { "version", o.tls_info->version }, { "cipher", o.tls_info->cipher }, { "chain_length", o.tls_info->chain_length } };
		if (o.tls_info->certificate) t["certificate"] = cert_json(*o.tls_info->certificate);
		j["tls_info"] = std::move(t);
	}
	if (o.favicon_hash) j["favicon_hash"] = *o.favicon_hash;
	if (!o.paths.empty()) {
		j["paths"] = ProbeJson::array();
		for (const PathResult& p : o.paths) {
			ProbeJson pj = { { "path", p.path }, { "status", p.status } };
			if (!p.content_type.empty()) pj["content_type"] = p.content_type;
			if (!p.title.empty()) pj["title"] = p.title;
			if (!p.redirect.empty()) pj["redirect"] = p.redirect;
			if (p.error != FetchError::None) pj["error"] = to_string(p.error);
			j["paths"].push_back(std::move(pj));
		}
	}
	if (detections) {
		j["detections"] = ProbeJson::array();
		for (const sig::Detection& d : detections->found) j["detections"].push_back(detection_json(d));
		j["signature_stats"] = { { "evaluated", detections->stats.signatures_evaluated }, { "regex_limit_hits", detections->stats.regex_limit_hits } };
	}
	if (o.error != FetchError::None) j["error"] = { { "kind", to_string(o.error) }, { "detail", o.error_detail } };
	if (!o.banner.empty()) j["banner"] = o.banner;
	j["requests"] = o.requests;
	j["elapsed_ms"] = o.elapsed_ms;
	return j;
}

std::string probe_to_text(const HttpObservation& o, const Detections* detections) {
	std::ostringstream out;
	out << o.ip << ":" << o.port;
	if (!o.host.empty()) out << " (" << printable(o.host) << ")";
	out << "  ->  " << printable(o.url) << "\n";

	if (o.status == 0) {
		out << "  no HTTP response: " << to_string(o.error);
		if (!o.error_detail.empty()) out << " (" << printable(o.error_detail) << ")";
		if (!o.banner.empty()) out << "; the service said: \"" << printable(o.banner) << "\"";
		out << "\n";
		if (o.tls_info) out << "  tls: " << o.tls_info->version << " " << o.tls_info->cipher << "\n";
		return out.str();
	}

	out << "  " << o.status << " " << printable(o.reason);
	if (!o.server.empty()) out << "  server: " << printable(o.server);
	if (!o.content_type.empty()) out << "  type: " << printable(o.content_type);
	out << "\n";
	if (o.error != FetchError::None) out << "  incomplete: " << to_string(o.error) << " (" << printable(o.error_detail) << ")\n";
	if (!o.title.empty()) out << "  title: " << printable(o.title) << "\n";
	for (const Hop& h : o.redirects) {
		out << "  redirect " << h.status << ": " << printable(h.url) << " -> " << printable(h.location);
		out << (h.followed ? "" : "  [not followed: " + printable(h.note) + "]") << "\n";
	}
	if (!o.cookies.empty()) {
		out << "  cookies:";
		for (const Cookie& c : o.cookies) {
			out << " " << printable(c.name);
			std::string flags;
			if (c.secure) flags += "Secure,";
			if (c.http_only) flags += "HttpOnly,";
			if (!c.same_site.empty()) flags += "SameSite=" + c.same_site + ",";
			if (!flags.empty()) flags.pop_back();
			out << (flags.empty() ? "" : " (" + flags + ")");
		}
		out << "\n";
	}
	if (o.tls_info) {
		out << "  tls: " << o.tls_info->version << " " << printable(o.tls_info->cipher);
		if (const auto& c = o.tls_info->certificate) {
			out << "\n  certificate: " << printable(c->subject) << ", " << c->key_type << " " << c->key_bits << ", valid " << c->not_before
			    << " .. " << c->not_after;
			if (c->self_signed) out << ", self-signed";
			if (c->expired) out << ", EXPIRED";
			if (c->not_yet_valid) out << ", NOT YET VALID";
			if (c->hostname_match && !*c->hostname_match) out << ", does not match the host name";
		}
		out << "\n";
	}
	if (o.favicon_hash) out << "  favicon hash: " << *o.favicon_hash << "\n";
	for (const PathResult& p : o.paths)
		if (p.status != 0 && p.status != 404) out << "  path " << printable(p.path) << ": " << p.status << "\n";
	if (detections) {
		if (detections->found.empty()) out << "  detections: none\n";
		for (const sig::Detection& d : detections->found) {
			out << "  detected: " << printable(d.name);
			if (!d.version.empty()) out << " " << printable(d.version);
			out << "  [" << sig::to_string(d.category) << ", confidence " << static_cast<int>(d.confidence * 100 + 0.5) << "%]\n";
		}
		if (detections->stats.regex_limit_hits)
			out << "  note: " << detections->stats.regex_limit_hits << " pattern search(es) hit the effort limit\n";
	}
	out << "  body: " << o.body_length << " bytes" << (o.body_truncated ? " (truncated)" : "") << ", sha256 " << o.body_sha256.substr(0, 16) << "...\n";
	return out.str();
}

} // namespace proculus
