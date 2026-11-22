#undef NDEBUG
#include <cassert>

#include "evidence.hpp"
#include "proculus/sig/builtin.hpp"
#include "proculus/sig/engine.hpp"
#include "proculus/sig/evidence_json.hpp"

using namespace proculus;

static std::string str(const sig::Evidence& e, const std::string& f) {
	auto* v = e.find(f);
	assert(v && std::holds_alternative<std::string>(*v));
	return std::get<std::string>(*v);
}
static std::vector<std::string> list(const sig::Evidence& e, const std::string& f) {
	auto* v = e.find(f);
	assert(v && std::holds_alternative<std::vector<std::string>>(*v));
	return std::get<std::vector<std::string>>(*v);
}

static HttpObservation sample() {
	HttpObservation o;
	o.ip = "10.0.0.5";
	o.port = 443;
	o.tls = true;
	o.url = "https://10.0.0.5/";
	o.status = 200;
	o.headers = {{"Server", "nginx/1.24.0"}, {"X-Powered-By", "PHP/8.2.1"}, {"Set-Cookie", "a=b"}};
	o.server = "nginx/1.24.0";
	o.content_type = "text/html";
	o.title = "Hello";
	o.body = "<html>hello</html>";
	o.body_length = o.body.size();
	Cookie c1; c1.name = "PHPSESSID"; c1.secure = true;
	Cookie c2; c2.name = "theme"; c2.http_only = true;
	o.cookies = {c1, c2};
	Hop h; h.location = "/login"; o.redirects = {h};
	o.favicon_hash = -123;
	TlsInfo t; t.version = "TLSv1.3"; t.cipher = "X";
	CertInfo ci; ci.key_type = "RSA"; ci.key_bits = 2048; ci.self_signed = true; ci.san = {"a.example"}; ci.hostname_match = false;
	t.certificate = ci;
	o.tls_info = t;
	PathResult p; p.path = "/wp-login.php"; p.status = 200; p.body = "user_login"; p.headers = {{"X-A", "1"}};
	PathResult gone; gone.path = "/nope"; gone.status = 0;
	o.paths = {p, gone};
	o.service.product = "nginx"; o.service.hostnames = {"www.example"};
	return o;
}

static void test_mapping() {
	const sig::Evidence e = to_evidence(sample());
	assert(std::get<double>(*e.find("status")) == 200);
	assert(std::get<double>(*e.find("port")) == 443);
	assert(std::get<bool>(*e.find("tls")));
	assert(str(e, "server") == "nginx/1.24.0" && str(e, "title") == "Hello");
	assert(list(e, "header:x-powered-by") == std::vector<std::string>{"PHP/8.2.1"});
	assert((list(e, "header_names") == std::vector<std::string>{"server", "x-powered-by", "set-cookie"}));
	assert((list(e, "cookie") == std::vector<std::string>{"PHPSESSID", "theme"}));
	assert((list(e, "cookie_insecure") == std::vector<std::string>{"theme"}));
	assert((list(e, "cookie_no_httponly") == std::vector<std::string>{"PHPSESSID"}));
	assert(list(e, "redirect_location")[0] == "/login");
	assert(str(e, "tls.key_type") == "RSA" && std::get<double>(*e.find("tls.key_bits")) == 2048);
	assert(std::get<bool>(*e.find("tls.self_signed")) && !std::get<bool>(*e.find("tls.hostname_match")));
	assert(str(e, "path:/wp-login.php:body") == "user_login");
	assert(std::get<double>(*e.find("path:/wp-login.php:status")) == 200);
	assert(list(e, "path:/wp-login.php:header:x-a")[0] == "1");
	assert(!e.has("path:/nope:status")); // nothing came back: no facts
	assert(str(e, "service.product") == "nginx" && list(e, "hostnames")[0] == "www.example");
	assert(!e.has("service.name"));

	// every field produced is part of the catalog
	for (const auto& [field, value] : e.all()) {
		std::string err;
		assert(sig::field_type(field, err) && "field is not in the catalog");
	}
	// and survives the JSON form used by `signatures match`
	sig::Evidence back;
	std::vector<sig::EvidenceProblem> problems;
	assert(sig::evidence_from_json(sig::evidence_to_json(e), back, problems) && problems.empty());
	assert(back.size() == e.size());
}

static void test_no_response() {
	HttpObservation o;
	o.ip = "10.0.0.5"; o.port = 80; o.error = FetchError::Timeout;
	const sig::Evidence e = to_evidence(o);
	assert(!e.has("status") && !e.has("body") && !e.has("header_names"));
}

static void test_detection_end_to_end() {
	const sig::SignatureSet set = sig::builtin_signatures();
	const auto found = sig::evaluate(set, to_evidence(sample()));
	bool nginx = false, php = false;
	for (const auto& d : found) {
		nginx |= d.id == "nginx";
		php |= d.id == "php";
	}
	assert(nginx && php);
}

int main() {
	test_mapping();
	test_no_response();
	test_detection_end_to_end();
	return 0;
}
