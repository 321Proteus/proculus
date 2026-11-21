#undef NDEBUG
#include <cassert>
#include <map>

#include "prober.hpp"

using namespace proculus;

// --------------------------------------------------------------- fake network

class Fake : public HttpTransport {
public:
	struct Call {
		Endpoint ep;
		std::string path;
		TransportLimits limits;
	};
	std::map<std::string, Exchange> routes;
	std::vector<Call> calls;

	static std::string key(const std::string& ip, uint16_t port, bool tls, const std::string& path) {
		return ip + ":" + std::to_string(port) + (tls ? "s" : "p") + path;
	}
	void add(const std::string& ip, uint16_t port, bool tls, const std::string& path, Exchange ex) { routes[key(ip, port, tls, path)] = std::move(ex); }

	Exchange get(const Endpoint& ep, const std::string& path, const TransportLimits& limits) override {
		calls.push_back({ep, path, limits});
		auto it = routes.find(key(ep.ip, ep.port, ep.tls, path));
		if (it != routes.end()) return it->second;
		Exchange miss;
		miss.error = FetchError::ConnectRefused;
		miss.error_detail = "no route in the fake";
		return miss;
	}
};

static Exchange page(int status, std::vector<Header> headers, const std::string& body) {
	Exchange ex;
	HttpResponse r;
	r.status = status;
	r.reason = status == 200 ? "OK" : "X";
	r.version = "HTTP/1.1";
	r.headers = std::move(headers);
	r.body = body;
	ex.response = std::move(r);
	return ex;
}

static Exchange redirect(int status, const std::string& location, std::vector<Header> extra = {}) {
	extra.push_back({"Location", location});
	return page(status, std::move(extra), "");
}

static ProbeLimits limits() {
	ProbeLimits l;
	l.scope = "10.0.0.0/16";
	l.allowed_ports = "80,443,8080,8443";
	l.max_requests_per_second = 1000;
	return l;
}

static RateGate no_wait() { return RateGate(1e6, [] { return RateGate::Clock::now(); }, [](std::chrono::nanoseconds) {}); }

static bool refused(HttpProber& p, const ProbeTarget& t, const char* why = "") {
	try {
		p.probe(t);
	} catch (const ProbeRefused& e) {
		return std::string(e.what()).find(why) != std::string::npos;
	}
	return false;
}

static const std::string kHtml = "<html><head><title>Welcome &amp; hello</title><link rel=\"icon\" href=\"/static/i.png\"></head><body>hi</body></html>";

// --------------------------------------------------------------------- tests

static void test_target_checks() {
	Fake net;
	HttpProber p(net, limits(), no_wait());
	assert(refused(p, {"10.1.0.1", 80}, "outside the allowed scope"));
	assert(refused(p, {"192.168.0.1", 80}, "outside"));
	assert(refused(p, {"10.0.0.1", 22}, "not in the allowed list"));
	assert(refused(p, {"10.0.0.1", 0}, "port 0"));
	assert(refused(p, {"nonsense", 80}, "not an IPv4"));
	assert(refused(p, {"10.0.0.1", 80, std::nullopt, "evil.example\r\nX: y"}, "invalid host"));
	assert(refused(p, {"10.0.0.1", 80, std::nullopt, "a b"}, "invalid host"));
	assert(net.calls.empty());                                                  // nothing was sent for any of those

	// reserved space needs an explicit opt-in even when it is in scope
	ProbeLimits l = limits();
	l.scope = "127.0.0.0/8";
	HttpProber strict(net, l, no_wait());
	assert(refused(strict, {"127.0.0.1", 80}, "reserved"));
	l.allow_reserved = true;
	HttpProber loose(net, l, no_wait());
	assert(loose.probe({"127.0.0.1", 80}).error == FetchError::ConnectRefused);   // allowed through (fake has no route)
	assert(net.calls.size() == 1);

	// a prober without limits cannot be made
	for (auto edit : {+[](ProbeLimits& x) { x.scope = ""; }, +[](ProbeLimits& x) { x.allowed_ports = ""; },
		     +[](ProbeLimits& x) { x.max_redirects = -1; }, +[](ProbeLimits& x) { x.max_redirects = 11; },
		     +[](ProbeLimits& x) { x.max_requests_per_second = 0; }}) {
		ProbeLimits bad = limits();
		edit(bad);
		bool threw = false;
		try { HttpProber x(net, bad); } catch (const std::invalid_argument&) { threw = true; }
		assert(threw);
	}
}

static void test_basic_observation() {
	Fake net;
	Exchange ex = page(200, {{"Server", "nginx/1.24.0"}, {"Content-Type", "text/html; charset=utf-8"}, {"X-Powered-By", "PHP/8.2"},
		     {"Set-Cookie", "PHPSESSID=abc123secret; Path=/; HttpOnly"}, {"Set-Cookie", "theme=dark; Max-Age=86400; Secure"}}, kHtml);
	TlsInfo tls;
	tls.version = "TLSv1.3";
	tls.cipher = "TLS_AES_256_GCM_SHA384";
	ex.tls = tls;
	net.add("10.0.0.5", 443, true, "/", ex);
	HttpProber p(net, limits(), no_wait());

	HttpObservation o = p.probe({"10.0.0.5", 443});
	assert(o.error == FetchError::None && o.status == 200 && o.reason == "OK" && o.http_version == "HTTP/1.1");
	assert(o.tls && o.url == "https://10.0.0.5/" && o.ip == "10.0.0.5" && o.port == 443);   // port 443 defaults to TLS
	assert(o.server == "nginx/1.24.0" && o.content_type == "text/html; charset=utf-8");
	assert(o.title == "Welcome & hello" && *find_header(o.headers, "x-powered-by") == "PHP/8.2");
	assert(o.body == kHtml && o.body_length == kHtml.size() && o.body_sha256 == sha256_hex(kHtml) && !o.body_truncated);
	assert(o.tls_info && o.tls_info->version == "TLSv1.3");

	// cookies: names and attributes, never the values
	assert(o.cookies.size() == 2 && o.cookies[0].name == "PHPSESSID" && o.cookies[0].http_only && !o.cookies[0].secure);
	assert(o.cookies[0].value.empty() && o.cookies[0].value_length == 12);
	assert(o.cookies[1].name == "theme" && o.cookies[1].secure && o.cookies[1].has_expiry);
	assert(net.calls[0].ep.host.empty() && net.calls[0].ep.tls && net.calls[0].path == "/");

	// values only when explicitly requested
	ProbeLimits keep = limits();
	keep.keep_cookie_values = true;
	HttpProber p2(net, keep, no_wait());
	assert(p2.probe({"10.0.0.5", 443}).cookies[0].value == "abc123secret");
}

static void test_scheme_selection() {
	assert(default_tls_port(443) && default_tls_port(8443) && !default_tls_port(80) && !default_tls_port(8080));
	Fake net;
	net.add("10.0.0.5", 80, false, "/", page(200, {}, "<title>plain</title>"));
	net.add("10.0.0.5", 8443, false, "/", page(200, {}, "<title>forced plain</title>"));
	net.add("10.0.0.5", 80, true, "/", page(200, {}, "<title>forced tls</title>"));
	HttpProber p(net, limits(), no_wait());
	assert(p.probe({"10.0.0.5", 80}).title == "plain" && !p.probe({"10.0.0.5", 80}).tls);
	assert(p.probe({"10.0.0.5", 8443, false}).title == "forced plain");
	assert(p.probe({"10.0.0.5", 80, true}).title == "forced tls");

	assert(web_service_scheme("http", 80) == false && web_service_scheme("https", 443) == true && web_service_scheme("ssl/http", 8443) == true);
	assert(web_service_scheme("http-proxy", 8080) == false && web_service_scheme("http-alt", 8443) == true && web_service_scheme("HTTPS-alt", 9000) == true);
	assert(web_service_scheme("unknown", 8080) == false && web_service_scheme("", 443) == true);
	assert(!web_service_scheme("ssh", 22) && !web_service_scheme("mysql", 3306) && !web_service_scheme("unknown", 5000));
}

static void test_redirects_within_the_site() {
	Fake net;
	net.add("10.0.0.5", 80, false, "/", redirect(301, "https://10.0.0.5/", {{"Set-Cookie", "lang=en"}}));
	net.add("10.0.0.5", 443, true, "/", redirect(302, "/app/login", {{"Set-Cookie", "sid=zzz; HttpOnly"}}));
	net.add("10.0.0.5", 443, true, "/app/login", page(200, {{"Content-Type", "text/html"}, {"Server", "Apache"}}, "<title>Sign in</title>"));
	HttpProber p(net, limits(), no_wait());

	HttpObservation o = p.probe({"10.0.0.5", 80});
	assert(o.status == 200 && o.title == "Sign in" && o.url == "https://10.0.0.5/app/login" && o.tls && o.port == 80);
	assert(o.redirects.size() == 2 && o.redirects[0].status == 301 && o.redirects[0].followed && o.redirects[0].url == "http://10.0.0.5/");
	assert(o.redirects[0].location == "https://10.0.0.5/" && o.redirects[1].location == "/app/login" && o.redirects[1].followed);
	assert(o.cookies.size() == 2 && o.cookies[0].name == "lang" && o.cookies[1].name == "sid");   // cookies set during the redirects are kept
	// page, two redirects, then the favicon of the page it ended on
	assert(net.calls.size() == 4 && net.calls[1].ep.port == 443 && net.calls[1].ep.tls && net.calls[1].ep.ip == "10.0.0.5");
	assert(net.calls[3].path == "/favicon.ico" && net.calls[3].ep.port == 443 && o.requests == 4 && !o.favicon_hash);
}

static void test_redirects_that_must_not_be_followed() {
	auto run = [](const std::string& location, std::vector<Header> extra = {}) {
		Fake net;
		net.add("10.0.0.5", 80, false, "/", redirect(302, location, std::move(extra)));
		net.add("10.0.0.5", 443, true, "/", page(200, {}, "followed!"));
		net.add("10.0.0.6", 80, false, "/", page(200, {}, "elsewhere!"));
		net.add("10.0.0.5", 22, false, "/", page(200, {}, "wrong port!"));
		HttpProber p(net, limits(), no_wait());
		HttpObservation o = p.probe({"10.0.0.5", 80});
		return std::make_pair(o, net.calls.size());
	};

	// another host, even in scope, even another address of the same network
	auto [other, n1] = run("http://10.0.0.6/");
	assert(other.status == 302 && !other.redirects[0].followed && other.redirects[0].note.find("leaves the target host") != std::string::npos && n1 == 1);
	assert(other.body.empty() && other.url == "http://10.0.0.5/");               // the redirect itself is the answer
	auto [external, n2] = run("http://evil.example/steal");
	assert(!external.redirects[0].followed && n2 == 1 && external.redirects[0].location == "http://evil.example/steal");
	auto [scheme_rel, n3] = run("//evil.example/x");
	assert(!scheme_rel.redirects[0].followed && n3 == 1);
	// a port that is not allowed
	auto [bad_port, n4] = run("http://10.0.0.5:22/");
	assert(!bad_port.redirects[0].followed && bad_port.redirects[0].note.find("not in the allowed list") != std::string::npos && n4 == 1);
	// things that are not web URLs at all
	for (const char* junk : {"javascript:alert(1)", "ftp://10.0.0.5/", "", "http://user:pw@10.0.0.5/"}) {
		auto [o, n] = run(junk);
		assert(!o.redirects.empty() && !o.redirects[0].followed && n == 1 && o.status == 302);
	}
	// a 3xx without Location is just a response
	Fake net;
	net.add("10.0.0.5", 80, false, "/", page(302, {}, "moved"));
	HttpProber p(net, limits(), no_wait());
	HttpObservation o = p.probe({"10.0.0.5", 80});
	assert(o.status == 302 && o.redirects.empty() && o.body == "moved");
	// and 304 / 300 are not followed even with a Location
	net.add("10.0.0.5", 80, false, "/", redirect(304, "/x"));
	assert(p.probe({"10.0.0.5", 80}).redirects.empty());
}

static void test_redirect_loops_and_limits() {
	Fake net;
	net.add("10.0.0.5", 80, false, "/", redirect(302, "/a"));
	net.add("10.0.0.5", 80, false, "/a", redirect(302, "/"));
	HttpProber p(net, limits(), no_wait());
	HttpObservation o = p.probe({"10.0.0.5", 80});
	assert(o.redirects.size() == 2 && o.redirects.back().note == "redirect loop" && net.calls.size() == 2);

	Fake chain;
	for (int i = 0; i < 10; i++) chain.add("10.0.0.5", 80, false, i == 0 ? "/" : "/p" + std::to_string(i), redirect(302, "/p" + std::to_string(i + 1)));
	ProbeLimits l = limits();
	l.max_redirects = 3;
	HttpProber q(chain, l, no_wait());
	HttpObservation c = q.probe({"10.0.0.5", 80});
	assert(chain.calls.size() == 4 && c.redirects.back().note == "too many redirects" && c.status == 302);   // 1 request + 3 redirects

	l.max_redirects = 0;
	Fake none;
	none.add("10.0.0.5", 80, false, "/", redirect(302, "/next"));
	none.add("10.0.0.5", 80, false, "/next", page(200, {}, "x"));
	HttpProber r(none, l, no_wait());
	assert(r.probe({"10.0.0.5", 80}).status == 302 && none.calls.size() == 1);
}

static void test_host_names() {
	Fake net;
	net.add("10.0.0.5", 80, false, "/", redirect(301, "https://Intranet.Example/home"));
	net.add("10.0.0.5", 443, true, "/home", page(200, {{"Content-Type", "text/html"}}, "<title>Home</title>"));
	HttpProber p(net, limits(), no_wait());

	// by name: the redirect to the same name is followed, and the name goes into the Host header / SNI
	HttpObservation o = p.probe({"10.0.0.5", 80, std::nullopt, "Intranet.Example"});
	assert(o.status == 200 && o.title == "Home" && o.host == "intranet.example");
	assert(net.calls[0].ep.host == "intranet.example" && net.calls[1].ep.host == "intranet.example" && net.calls[1].ep.ip == "10.0.0.5");

	// by address only: a redirect to a name is "another host"
	net.calls.clear();
	HttpObservation o2 = p.probe({"10.0.0.5", 80});
	assert(o2.status == 301 && !o2.redirects[0].followed && net.calls.size() == 1 && net.calls[0].ep.host.empty());
}

static void test_favicon() {
	auto setup = [](Fake& net, const std::string& page_body, int icon_status, const std::string& icon_body, const std::string& icon_type) {
		net.add("10.0.0.5", 80, false, "/", page(200, {{"Content-Type", "text/html"}}, page_body));
		std::vector<Header> h;
		if (!icon_type.empty()) h.push_back({"Content-Type", icon_type});
		net.add("10.0.0.5", 80, false, "/static/i.png", page(icon_status, h, icon_body));
		net.add("10.0.0.5", 80, false, "/favicon.ico", page(icon_status, h, icon_body));
	};
	const std::string icon = std::string("\x89PNG\r\n\x1a\n", 8) + "pixels";

	Fake net;
	setup(net, kHtml, 200, icon, "image/png");
	HttpProber p(net, limits(), no_wait());
	HttpObservation o = p.probe({"10.0.0.5", 80});
	assert(o.favicon_hash && *o.favicon_hash == favicon_hash(icon) && o.requests == 2);
	assert(net.calls[1].path == "/static/i.png");                                 // the page's own <link> wins
	assert(net.calls[1].limits.max_body == 64 * 1024);                            // icons get a small body limit

	Fake net2;
	setup(net2, "<html><title>No link</title></html>", 200, icon, "image/x-icon");
	HttpProber p2(net2, limits(), no_wait());
	assert(*p2.probe({"10.0.0.5", 80}).favicon_hash == favicon_hash(icon) && net2.calls[1].path == "/favicon.ico");

	Fake net3;                                                                     // missing icon: no hash, no failure
	setup(net3, kHtml, 404, "not found", "text/html");
	HttpProber p3(net3, limits(), no_wait());
	assert(!p3.probe({"10.0.0.5", 80}).favicon_hash && p3.probe({"10.0.0.5", 80}).status == 200);

	Fake net4;                                                                     // a "not found" page served with 200 is not an icon
	setup(net4, kHtml, 200, "<html>soft 404</html>", "text/html; charset=utf-8");
	HttpProber p4(net4, limits(), no_wait());
	assert(!p4.probe({"10.0.0.5", 80}).favicon_hash);

	Fake net5;                                                                     // icon on another host: never fetched
	net5.add("10.0.0.5", 80, false, "/", page(200, {{"Content-Type", "text/html"}}, "<title>x</title><link rel=\"icon\" href=\"http://evil.example/f.ico\">"));
	HttpProber p5(net5, limits(), no_wait());
	assert(!p5.probe({"10.0.0.5", 80}).favicon_hash && net5.calls.size() == 1);

	Fake net6;                                                                     // switched off
	setup(net6, kHtml, 200, icon, "image/png");
	ProbeLimits off = limits();
	off.fetch_favicon = false;
	HttpProber p6(net6, off, no_wait());
	assert(!p6.probe({"10.0.0.5", 80}).favicon_hash && net6.calls.size() == 1);

	Fake net7;                                                                     // not looked for on errors or non-HTML
	net7.add("10.0.0.5", 80, false, "/", page(500, {{"Content-Type", "text/html"}}, kHtml));
	HttpProber p7(net7, limits(), no_wait());
	assert(p7.probe({"10.0.0.5", 80}).status == 500 && net7.calls.size() == 1);
	Fake net8;
	net8.add("10.0.0.5", 80, false, "/", page(200, {{"Content-Type", "application/json"}}, "{\"a\":1}"));
	HttpProber p8(net8, limits(), no_wait());
	assert(p8.probe({"10.0.0.5", 80}).title.empty() && net8.calls.size() == 1);

	// a truncated icon would give a wrong hash: not used
	Fake net9;
	setup(net9, kHtml, 200, icon, "image/png");
	Exchange big = net9.routes[Fake::key("10.0.0.5", 80, false, "/static/i.png")];
	big.response->body_truncated = true;
	net9.routes[Fake::key("10.0.0.5", 80, false, "/static/i.png")] = big;
	HttpProber p9(net9, limits(), no_wait());
	assert(!p9.probe({"10.0.0.5", 80}).favicon_hash);
}

static void test_errors_are_data() {
	Fake net;
	Exchange refused_ex;
	refused_ex.error = FetchError::ConnectRefused;
	refused_ex.error_detail = "Connection refused";
	net.add("10.0.0.5", 80, false, "/", refused_ex);
	Exchange ssh;
	ssh.error = FetchError::NotHttp;
	ssh.banner = "SSH-2.0-OpenSSH_8.9";
	net.add("10.0.0.6", 80, false, "/", ssh);
	Exchange partial = page(200, {{"Content-Type", "text/html"}, {"Server", "slow"}}, "<title>Half a page");
	partial.error = FetchError::Timeout;
	partial.error_detail = "timed out while the body was arriving";
	net.add("10.0.0.7", 80, false, "/", partial);
	HttpProber p(net, limits(), no_wait());

	HttpObservation a = p.probe({"10.0.0.5", 80});
	assert(a.status == 0 && a.error == FetchError::ConnectRefused && a.error_detail == "Connection refused" && a.body.empty() && a.requests == 1);
	HttpObservation b = p.probe({"10.0.0.6", 80});
	assert(b.status == 0 && b.error == FetchError::NotHttp && b.banner == "SSH-2.0-OpenSSH_8.9" && b.title.empty());
	HttpObservation c = p.probe({"10.0.0.7", 80});
	assert(c.status == 200 && c.error == FetchError::Timeout && c.server == "slow" && c.title == "Half a page");   // partial data is kept
	assert(net.calls.size() == 3);                                                                                  // and no favicon request after a failed or partial exchange
}

static void test_request_budget_and_rate() {
	// worst case: the page, up to 3 redirects, then the favicon
	Fake net;
	net.add("10.0.0.5", 80, false, "/", redirect(302, "/a"));
	net.add("10.0.0.5", 80, false, "/a", redirect(302, "/b"));
	net.add("10.0.0.5", 80, false, "/b", redirect(302, "/c"));
	net.add("10.0.0.5", 80, false, "/c", page(200, {{"Content-Type", "text/html"}}, "<title>end</title>"));
	net.add("10.0.0.5", 80, false, "/favicon.ico", page(200, {{"Content-Type", "image/x-icon"}}, "ico"));
	HttpProber p(net, limits(), no_wait());
	HttpObservation o = p.probe({"10.0.0.5", 80});
	assert(o.requests == 5 && net.calls.size() == 5 && o.favicon_hash);

	// rate limiting against a fake clock
	RateGate::Clock::time_point now{};
	std::chrono::nanoseconds slept{0};
	RateGate gate(5, [&] { return now; }, [&](std::chrono::nanoseconds d) {
		slept += d;
		now += d;
	});
	for (int i = 0; i < 6; i++) gate.wait();                                       // 6 calls at 5/s need 5 gaps of 200 ms
	assert(slept >= std::chrono::milliseconds(990) && slept <= std::chrono::milliseconds(1010));
	slept = std::chrono::nanoseconds(0);
	now += std::chrono::seconds(10);                                              // a quiet spell: no catching up in a burst
	gate.wait();
	gate.wait();
	assert(slept >= std::chrono::milliseconds(190) && slept <= std::chrono::milliseconds(210));

	// the prober really goes through the gate
	Fake net2;
	net2.add("10.0.0.5", 80, false, "/", page(200, {}, "x"));
	RateGate::Clock::time_point t2{};
	std::chrono::nanoseconds slept2{0};
	HttpProber q(net2, limits(), RateGate(10, [&] { return t2; }, [&](std::chrono::nanoseconds d) { slept2 += d; t2 += d; }));
	for (int i = 0; i < 4; i++) q.probe({"10.0.0.5", 80});
	assert(slept2 >= std::chrono::milliseconds(290) && slept2 <= std::chrono::milliseconds(310));
	bool threw = false;
	try { RateGate bad(0); } catch (const std::invalid_argument&) { threw = true; }
	assert(threw);
}

int main() {
	test_target_checks();
	test_basic_observation();
	test_scheme_selection();
	test_redirects_within_the_site();
	test_redirects_that_must_not_be_followed();
	test_redirect_loops_and_limits();
	test_host_names();
	test_favicon();
	test_errors_are_data();
	test_request_budget_and_rate();
	return 0;
}
