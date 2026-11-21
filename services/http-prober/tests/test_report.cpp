#undef NDEBUG
#include <cassert>

#include "report.hpp"

using namespace proculus;

static HttpObservation sample() {
	HttpObservation o;
	o.ip = "10.0.0.5";
	o.port = 80;
	o.tls = true;
	o.url = "https://10.0.0.5/login";
	o.status = 200;
	o.reason = "OK";
	o.http_version = "HTTP/1.1";
	o.server = "nginx/1.24.0";
	o.content_type = "text/html";
	o.title = "Sign in";
	o.headers = {{"Server", "nginx/1.24.0"}, {"X-Powered-By", "PHP/8.2"}};
	Cookie c;
	c.name = "PHPSESSID";
	c.value_length = 26;
	c.http_only = true;
	c.same_site = "Lax";
	o.cookies = {c};
	o.redirects = {{"http://10.0.0.5/", 301, "https://10.0.0.5/login", true, ""}};
	o.body = "<html>secret page</html>";
	o.body_length = o.body.size();
	o.body_sha256 = sha256_hex(o.body);
	TlsInfo t;
	t.version = "TLSv1.3";
	t.cipher = "TLS_AES_256_GCM_SHA384";
	t.chain_length = 1;
	CertInfo cert;
	cert.subject = "CN=test.example";
	cert.issuer = "CN=test.example";
	cert.key_type = "EC";
	cert.key_bits = 256;
	cert.not_before = "2026-01-01T00:00:00Z";
	cert.not_after = "2025-12-31T00:00:00Z";
	cert.self_signed = true;
	cert.expired = true;
	cert.hostname_match = false;
	cert.san = {"test.example"};
	t.certificate = cert;
	o.tls_info = t;
	o.favicon_hash = -1234567;
	o.requests = 3;
	return o;
}

static void test_json() {
	HttpObservation o = sample();
	ProbeJson j = probe_to_json(o);

	// round trip through text, as a consumer would see it
	ProbeJson r = ProbeJson::parse(j.dump());
	assert(r["status"] == 200 && r["title"] == "Sign in" && r["server"] == "nginx/1.24.0" && r["tls"] == true && r["favicon_hash"] == -1234567);
	assert(r["headers"].size() == 2 && r["headers"][1]["name"] == "X-Powered-By");
	assert(r["redirects"][0]["followed"] == true && r["redirects"][0]["status"] == 301);
	assert(r["tls_info"]["version"] == "TLSv1.3" && r["tls_info"]["certificate"]["self_signed"] == true);
	assert(r["tls_info"]["certificate"]["hostname_match"] == false && r["tls_info"]["certificate"]["san"][0] == "test.example");
	assert(r["requests"] == 3 && !r.contains("error") && !r.contains("banner"));

	// the page itself is not included by default: only its size and fingerprint
	assert(!r["body"].contains("content") && r["body"]["length"] == o.body.size() && r["body"]["sha256"] == sha256_hex(o.body));
	assert(j.dump().find("secret page") == std::string::npos);
	assert(probe_to_json(o, true)["body"]["content"] == o.body);

	// cookie values are never in the output unless they were kept
	assert(r["cookies"][0]["name"] == "PHPSESSID" && r["cookies"][0]["value_length"] == 26 && !r["cookies"][0].contains("value"));
	assert(r["cookies"][0]["http_only"] == true && r["cookies"][0]["same_site"] == "Lax" && r["cookies"][0]["persistent"] == false);
	o.cookies[0].value = "s3cret";
	assert(probe_to_json(o)["cookies"][0]["value"] == "s3cret");

	// failures
	HttpObservation f;
	f.ip = "10.0.0.6";
	f.port = 22;
	f.error = FetchError::NotHttp;
	f.error_detail = "";
	f.banner = "SSH-2.0-OpenSSH_8.9";
	ProbeJson fj = probe_to_json(f);
	assert(fj["status"] == 0 && fj["error"]["kind"] == "not_http" && fj["banner"] == "SSH-2.0-OpenSSH_8.9" && !fj.contains("tls_info") && !fj.contains("favicon_hash"));

	// invalid UTF-8 from the network cannot break serialisation
	HttpObservation bad = sample();
	bad.title = std::string("bad \xff\xfe title");
	const std::string text = bad.title.empty() ? "" : probe_to_json(bad).dump(-1, ' ', false, ProbeJson::error_handler_t::replace);
	assert(text.find("title") != std::string::npos);
}

static void test_text() {
	std::string t = probe_to_text(sample());
	assert(t.find("10.0.0.5:80  ->  https://10.0.0.5/login") != std::string::npos);
	assert(t.find("200 OK  server: nginx/1.24.0  type: text/html") != std::string::npos);
	assert(t.find("title: Sign in") != std::string::npos);
	assert(t.find("redirect 301: http://10.0.0.5/ -> https://10.0.0.5/login") != std::string::npos);
	assert(t.find("cookies: PHPSESSID (HttpOnly,SameSite=Lax)") != std::string::npos);
	assert(t.find("tls: TLSv1.3 TLS_AES_256_GCM_SHA384") != std::string::npos);
	assert(t.find("self-signed") != std::string::npos && t.find("EXPIRED") != std::string::npos && t.find("does not match the host name") != std::string::npos);
	assert(t.find("favicon hash: -1234567") != std::string::npos && t.find("secret page") == std::string::npos);

	HttpObservation f;
	f.ip = "10.0.0.6";
	f.port = 22;
	f.error = FetchError::NotHttp;
	f.banner = "SSH-2.0-OpenSSH_8.9";
	std::string ft = probe_to_text(f);
	assert(ft.find("no HTTP response: not_http") != std::string::npos && ft.find("\"SSH-2.0-OpenSSH_8.9\"") != std::string::npos);

	HttpObservation partial = sample();
	partial.error = FetchError::Timeout;
	partial.error_detail = "timed out while the body was arriving";
	assert(probe_to_text(partial).find("incomplete: timeout") != std::string::npos);

	HttpObservation stuck = sample();
	stuck.redirects = {{"http://10.0.0.5/", 302, "http://evil.example/", false, "redirect leaves the target host (evil.example); not followed"}};
	assert(probe_to_text(stuck).find("[not followed: redirect leaves the target host") != std::string::npos);

	// text from the network cannot move the cursor or inject escape sequences
	HttpObservation hostile = sample();
	hostile.title = "\x1b[2J\x1b]0;pwned\x07 title";
	hostile.server = "evil\r\nServer";
	hostile.cookies[0].name = "a\x1b[31mb";
	hostile.tls_info->certificate->subject = "CN=\x1b[1mbold";
	hostile.redirects[0].location = "http://x/\x07";
	const std::string h = probe_to_text(hostile);
	assert(h.find('\x1b') == std::string::npos && h.find('\x07') == std::string::npos && h.find('\r') == std::string::npos);
}

int main() {
	test_json();
	test_text();
	return 0;
}
