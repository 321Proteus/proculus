#undef NDEBUG
#include <cassert>

#include "evidence.hpp"
#include "proculus/sig/builtin.hpp"
#include "web_record.hpp"

using namespace proculus;

static HttpObservation sample() {
	HttpObservation o;
	o.url = "https://10.0.0.5/";
	o.status = 200;
	o.title = "Hello";
	o.server = "nginx/1.24.0";
	o.content_type = "text/html";
	o.headers = {{"Server", "nginx/1.24.0"}, {"Set-Cookie", "sid=<redacted>; HttpOnly"}};
	o.body = "TOP-SECRET-BODY";
	Cookie c;
	c.name = "sid";
	c.value = "should-never-be-stored";
	c.http_only = true;
	c.same_site = "Lax";
	o.cookies = {c};
	Hop h;
	h.location = "/login";
	o.redirects = {h};
	TlsInfo t;
	t.version = "TLSv1.3";
	t.cipher = "X";
	CertInfo ci;
	ci.subject = "CN=a";
	ci.sha256 = "ab";
	ci.key_type = "RSA";
	ci.key_bits = 2048;
	ci.self_signed = true;
	ci.san = {"a.example"};
	ci.hostname_match = false;
	t.certificate = ci;
	o.tls_info = t;
	o.favicon_hash = 42;
	return o;
}

static void test_conversion() {
	const sig::SignatureSet set = sig::builtin_signatures();
	const HttpObservation o = sample();
	const auto found = sig::evaluate(set, to_evidence(o));
	const WebRecord w = to_web_record(o, found);

	assert(w.url == o.url && w.status == 200 && w.title == "Hello" && w.server == o.server);
	assert(w.headers.size() == 2 && w.headers[1].second == "sid=<redacted>; HttpOnly");
	assert(w.cookies.size() == 1 && w.cookies[0].name == "sid" && w.cookies[0].http_only && w.cookies[0].same_site == "Lax");
	assert(w.redirects == std::vector<std::string>{"/login"});
	assert(w.tls && w.tls->version == "TLSv1.3" && w.tls->self_signed && w.tls->sha256 == "ab" && w.tls->hostname_match && !*w.tls->hostname_match);
	assert(w.favicon_hash && *w.favicon_hash == 42);
	assert(w.detections.size() == found.size() && !w.detections.empty());
	bool nginx = false;
	for (const DetectionRecord& d : w.detections) nginx |= d.id == "nginx" && d.version == "1.24.0" && d.category == "server" && d.confidence > 0.9;
	assert(nginx);

	// neither the body nor cookie values reach the stored form
	RunRecord run;
	HostRecord h;
	h.ip = "10.0.0.5";
	ServiceRecord s;
	s.port = 443;
	s.web = w;
	h.services.push_back(s);
	run.hosts.push_back(h);
	const std::string stored = dump_json(run_to_json(run));
	assert(stored.find("TOP-SECRET-BODY") == std::string::npos && stored.find("should-never-be-stored") == std::string::npos);

	// a service that answered but had no certificate details still records the TLS version
	HttpObservation plain = sample();
	plain.tls_info->certificate.reset();
	assert(to_web_record(plain, {}).tls && to_web_record(plain, {}).tls->subject.empty());
	plain.tls_info.reset();
	assert(!to_web_record(plain, {}).tls);
}

int main() {
	test_conversion();
	return 0;
}
