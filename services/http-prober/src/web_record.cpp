#include "web_record.hpp"

#include <algorithm>

namespace proculus {

namespace {

constexpr size_t kMaxHeaders = 100;
constexpr size_t kMaxText = 1024;
constexpr size_t kMaxList = 100;

std::string cap(const std::string& s) { return s.size() > kMaxText ? s.substr(0, kMaxText) : s; }

} // namespace

DetectionRecord to_detection_record(const sig::Detection& d) {
	DetectionRecord r;
	r.id = d.id;
	r.name = d.name;
	r.category = sig::to_string(d.category);
	r.confidence = d.confidence;
	r.interest = d.interest;
	r.version = d.version;
	r.builtin = d.builtin;
	r.tags = d.tags;
	r.evidence = d.evidence;
	if (r.evidence.size() > kMaxList) r.evidence.resize(kMaxList);
	for (std::string& e : r.evidence) e = cap(e);
	return r;
}

WebRecord to_web_record(const HttpObservation& o, const std::vector<sig::Detection>& detections) {
	WebRecord w;
	w.url = cap(o.url);
	w.status = o.status;
	w.title = o.title;
	w.server = o.server;
	w.content_type = o.content_type;
	for (const Header& h : o.headers) {
		if (w.headers.size() >= kMaxHeaders) break;
		w.headers.emplace_back(cap(h.name), cap(h.value));
	}
	for (const Cookie& c : o.cookies) w.cookies.push_back({c.name, c.secure, c.http_only, c.same_site});
	for (const Hop& h : o.redirects) {
		if (w.redirects.size() >= kMaxList) break;
		w.redirects.push_back(cap(h.location));
	}
	if (o.tls_info && o.tls_info->certificate) {
		const CertInfo& c = *o.tls_info->certificate;
		TlsRecord t;
		t.version = o.tls_info->version;
		t.cipher = o.tls_info->cipher;
		t.subject = cap(c.subject);
		t.issuer = cap(c.issuer);
		t.not_before = c.not_before;
		t.not_after = c.not_after;
		t.sha256 = c.sha256;
		t.key_type = c.key_type;
		t.key_bits = c.key_bits;
		t.self_signed = c.self_signed;
		t.expired = c.expired;
		t.not_yet_valid = c.not_yet_valid;
		t.hostname_match = c.hostname_match;
		for (const std::string& s : c.san) {
			if (t.san.size() >= kMaxList) break;
			t.san.push_back(cap(s));
		}
		w.tls = std::move(t);
	} else if (o.tls_info) {
		TlsRecord t;
		t.version = o.tls_info->version;
		t.cipher = o.tls_info->cipher;
		w.tls = std::move(t);
	}
	w.favicon_hash = o.favicon_hash;
	for (const sig::Detection& d : detections) w.detections.push_back(to_detection_record(d));
	return w;
}

} // namespace proculus
