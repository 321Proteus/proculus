#include "evidence.hpp"

#include <algorithm>

namespace proculus {

namespace {

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

} // namespace

sig::Evidence to_evidence(const HttpObservation& o) {
	sig::Evidence e;
	e.set("port", static_cast<int>(o.port));
	e.set("tls", o.tls);
	if (!o.host.empty()) e.set("host", o.host);
	if (!o.url.empty()) e.set("url", o.url);

	if (!o.service.name.empty()) e.set("service.name", o.service.name);
	if (!o.service.product.empty()) e.set("service.product", o.service.product);
	if (!o.service.version.empty()) e.set("service.version", o.service.version);
	if (!o.service.hostnames.empty()) e.set_list("hostnames", o.service.hostnames);

	if (o.status > 0) {
		e.set("status", o.status);
		e.set("body_length", static_cast<double>(o.body_length));
		e.set("body", o.body);
		if (!o.server.empty()) e.set("server", o.server);
		if (!o.content_type.empty()) e.set("content_type", o.content_type);
		if (!o.title.empty()) e.set("title", o.title);
		if (o.favicon_hash) e.set("favicon_hash", static_cast<double>(*o.favicon_hash));

		std::vector<std::string> names;
		for (const Header& h : o.headers) {
			const std::string n = lower(h.name);
			e.add("header:" + n, h.value);
			if (std::find(names.begin(), names.end(), n) == names.end()) names.push_back(n);
		}
		e.set_list("header_names", names);
	}

	for (const Cookie& c : o.cookies) {
		e.add("cookie", c.name);
		if (!c.secure) e.add("cookie_insecure", c.name);
		if (!c.http_only) e.add("cookie_no_httponly", c.name);
	}
	for (const Hop& h : o.redirects) e.add("redirect_location", h.location);

	if (o.tls_info) {
		const TlsInfo& t = *o.tls_info;
		e.set("tls.version", t.version);
		e.set("tls.cipher", t.cipher);
		if (const auto& c = t.certificate) {
			e.set("tls.subject", c->subject);
			e.set("tls.issuer", c->issuer);
			e.set("tls.key_type", c->key_type);
			e.set("tls.key_bits", c->key_bits);
			e.set("tls.signature_algorithm", c->signature_algorithm);
			e.set("tls.self_signed", c->self_signed);
			e.set("tls.expired", c->expired);
			e.set("tls.not_yet_valid", c->not_yet_valid);
			if (c->hostname_match) e.set("tls.hostname_match", *c->hostname_match);
			e.set_list("tls.san", c->san);
		}
	}

	for (const PathResult& p : o.paths) {
		if (p.status <= 0) continue;
		const std::string pre = "path:" + p.path + ":";
		e.set(pre + "status", p.status);
		e.set(pre + "body", p.body);
		if (!p.content_type.empty()) e.set(pre + "content_type", p.content_type);
		if (!p.title.empty()) e.set(pre + "title", p.title);
		if (!p.redirect.empty()) e.set(pre + "redirect", p.redirect);
		for (const Header& h : p.headers) e.add(pre + "header:" + lower(h.name), h.value);
	}
	return e;
}

} // namespace proculus
