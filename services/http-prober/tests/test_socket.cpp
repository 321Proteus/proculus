#undef NDEBUG
#include <cassert>

#include "test_server.hpp"
#include "transport.hpp"

using namespace proculus;
using namespace testsrv;

static Endpoint ep(const Server& s, bool tls = false, const std::string& host = "") {
	Endpoint e;
	e.ip = "127.0.0.1";
	e.port = s.port();
	e.tls = tls;
	e.host = host;
	return e;
}

static TransportLimits quick() {
	TransportLimits l;
	l.connect_timeout_ms = 1000;
	l.total_timeout_ms = 2000;
	return l;
}

static bool contains(const std::string& s, const std::string& what) { return s.find(what) != std::string::npos; }

static void test_plain_response_and_request_shape() {
	Server s([](const std::string&) { return reply(http_ok("<html><title>Hi</title></html>", "Server: testsrv/1.0\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2; HttpOnly\r\n")); });
	SocketTransport t;
	Exchange ex = t.get(ep(s), "/x?y=1", quick());

	assert(ex.error == FetchError::None && ex.response);
	assert(ex.response->status == 200 && ex.response->reason == "OK" && ex.response->version == "HTTP/1.1");
	assert(ex.response->body == "<html><title>Hi</title></html>" && !ex.response->body_truncated);
	assert(*find_header(ex.response->headers, "server") == "testsrv/1.0");
	int cookies = 0;
	for (const Header& h : ex.response->headers) cookies += h.name == "Set-Cookie";
	assert(cookies == 2);                                                      // repeated headers are all kept
	assert(!ex.tls && ex.connect_ms >= 0 && ex.total_ms >= ex.connect_ms);

	// exactly what we sent: a plain GET, identifying itself, nothing else
	const std::string req = s.last_request();
	assert(req.rfind("GET /x?y=1 HTTP/1.1\r\n", 0) == 0);
	assert(contains(req, "\r\nHost: 127.0.0.1:" + std::to_string(s.port()) + "\r\n"));
	assert(contains(req, "\r\nUser-Agent: Proculus-Scanner/0.1\r\n") && contains(req, "\r\nConnection: close\r\n"));
	assert(contains(req, "\r\nAccept-Encoding: identity\r\n"));
	assert(!contains(req, "Cookie:") && !contains(req, "Authorization") && !contains(req, "Content-Length"));
	assert(req.size() > 4 && req.substr(req.size() - 4) == "\r\n\r\n");
}

static void test_host_header() {
	Server s([](const std::string&) { return reply(http_ok("x")); });
	SocketTransport t;
	t.get(ep(s, false, "intranet.example"), "/", quick());
	assert(contains(s.last_request(), "\r\nHost: intranet.example:" + std::to_string(s.port()) + "\r\n"));
}

static void test_bodies() {
	SocketTransport t;
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.error == FetchError::None && ex.response->body == "hello world" && !ex.response->body_truncated);
	}
	{
		// a chunked body dribbled out a few bytes at a time, framing split anywhere
		Script sc;
		const std::string whole = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
		for (size_t i = 0; i < whole.size(); i += 3) sc.parts.push_back(whole.substr(i, 3));
		Server s([&](const std::string&) { return sc; });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.error == FetchError::None && ex.response->body == "Wikipedia");
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.0 200 OK\r\nServer: old\r\n\r\nbody until close"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.error == FetchError::None && ex.response->body == "body until close" && ex.response->version == "HTTP/1.0");
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.response->status == 204 && ex.response->body.empty() && ex.error == FetchError::None);
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.response->status == 200 && ex.response->body == "ok");           // the interim response is skipped
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 200\r\nContent-Length: 1\r\n\r\nx"); });   // no reason phrase
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.response && ex.response->status == 200 && ex.response->reason.empty());
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 200 OK\nContent-Length: 2\n\nhi"); });       // bare LF line endings
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.response && ex.response->body == "hi");
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"); });
		Exchange ex = t.get(ep(s), "/missing", quick());
		assert(ex.response->status == 404 && ex.error == FetchError::None);        // an HTTP error is still a successful exchange
	}
}

static void test_size_limits() {
	SocketTransport t;
	TransportLimits lim = quick();
	lim.max_body = 1000;
	const std::string big(1000000, 'A');
	{
		Server s([&](const std::string&) { return reply(http_ok(big)); });
		Exchange ex = t.get(ep(s), "/", lim);
		assert(ex.response && ex.response->body.size() == 1000 && ex.response->body_truncated && ex.error == FetchError::None);
	}
	{
		Server s([&](const std::string&) { return reply("HTTP/1.1 200 OK\r\n\r\n" + big); });                  // read until close
		Exchange ex = t.get(ep(s), "/", lim);
		assert(ex.response && ex.response->body.size() == 1000 && ex.response->body_truncated);
	}
	{
		std::string chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
		for (int i = 0; i < 100; i++) chunked += "400\r\n" + std::string(1024, 'B') + "\r\n";
		chunked += "0\r\n\r\n";
		Server s([&](const std::string&) { return reply(chunked); });
		Exchange ex = t.get(ep(s), "/", lim);
		assert(ex.response && ex.response->body.size() == 1000 && ex.response->body_truncated);
	}
	{
		// a body within the limit is not flagged
		Server s([](const std::string&) { return reply(http_ok(std::string(1000, 'C'))); });
		Exchange ex = t.get(ep(s), "/", lim);
		assert(ex.response->body.size() == 1000 && !ex.response->body_truncated);
	}
	{
		TransportLimits tight = quick();
		tight.max_header_bytes = 2048;
		Server s([](const std::string&) { return reply("HTTP/1.1 200 OK\r\nX-Big: " + std::string(200000, 'h') + "\r\n\r\n"); });
		Exchange ex = t.get(ep(s), "/", tight);
		assert(!ex.response && ex.error == FetchError::Protocol && contains(ex.error_detail, "headers exceed"));
	}
	{
		std::string many = "HTTP/1.1 200 OK\r\n";
		for (int i = 0; i < 300; i++) many += "X-H" + std::to_string(i) + ": v\r\n";
		Server s([&](const std::string&) { return reply(many + "\r\n"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(!ex.response && ex.error == FetchError::Protocol && contains(ex.error_detail, "too many headers"));
	}
}

static void test_header_parsing() {
	Server s([](const std::string&) {
		return reply("HTTP/1.1 200 OK\r\nServer:   spaced   \r\nX-Folded: part one\r\n   part two\r\nthis line has no colon\r\n: nameless\r\n"
			     "Bad Name: ignored\r\nX-Ctl: a\x01" "b\r\nContent-Length: 0\r\n\r\n");
	});
	Exchange ex = SocketTransport().get(ep(s), "/", quick());
	assert(ex.response);
	assert(*find_header(ex.response->headers, "Server") == "spaced");
	assert(*find_header(ex.response->headers, "X-Folded") == "part one part two");
	assert(!find_header(ex.response->headers, "Bad Name") && *find_header(ex.response->headers, "X-Ctl") == "a b");
	assert(ex.response->headers.size() == 4);
}

static void test_not_http_and_malformed() {
	SocketTransport t;
	{
		Server s([](const std::string&) { return reply("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(!ex.response && ex.error == FetchError::NotHttp && ex.banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3");
	}
	{
		Server s([](const std::string&) { return reply(std::string("\x16\x03\x01\x02\x00\x01\x00\xff\xfe", 9)); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(!ex.response && ex.error == FetchError::NotHttp && ex.banner.find('\x16') == std::string::npos);   // banner is printable
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 20 OK\r\n\r\n"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(!ex.response && ex.error == FetchError::Protocol && contains(ex.error_detail, "status line"));
	}
	{
		Server s([](const std::string&) { return reply(""); });                                              // closes without a word
		Exchange ex = t.get(ep(s), "/", quick());
		assert(!ex.response && ex.error == FetchError::Reset);
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 200 OK\r\nServer: cut"); });                // dies inside the headers
		Exchange ex = t.get(ep(s), "/", quick());
		assert(!ex.response && ex.error == FetchError::Reset && contains(ex.error_detail, "headers"));
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nx\r\n"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.response && ex.error == FetchError::Protocol && contains(ex.error_detail, "chunk"));
	}
}

static void test_timeouts_and_partial_responses() {
	SocketTransport t;
	TransportLimits lim;
	lim.connect_timeout_ms = 500;
	lim.total_timeout_ms = 400;
	{
		Script silent;
		silent.hold_open_ms = 1500;                                           // accepts, reads the request, says nothing
		Server s([&](const std::string&) { return silent; });
		Exchange ex = t.get(ep(s), "/", lim);
		assert(!ex.response && ex.error == FetchError::Timeout);
		assert(ex.total_ms >= 350 && ex.total_ms < 1200);                     // gave up at the deadline, not later
	}
	{
		Script stall;
		stall.parts = {"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial data"};
		stall.hold_open_ms = 1500;
		Server s([&](const std::string&) { return stall; });
		Exchange ex = t.get(ep(s), "/", lim);
		// the headers and what arrived are kept, with the timeout reported next to them
		assert(ex.response && ex.response->status == 200 && ex.response->body == "partial data" && ex.error == FetchError::Timeout);
	}
	{
		Server s([](const std::string&) { return reply("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly ten b"); });
		Exchange ex = t.get(ep(s), "/", quick());
		assert(ex.response && ex.response->body == "only ten b" && ex.error == FetchError::Reset);
	}
	{
		// a server that drips bytes forever cannot hold us past the total deadline
		Script drip;
		drip.parts.push_back("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
		for (int i = 0; i < 100; i++) drip.parts.push_back("x");
		drip.part_delay_ms = 20;
		Server s([&](const std::string&) { return drip; });
		TransportLimits l2 = lim;
		l2.total_timeout_ms = 300;
		Exchange ex = t.get(ep(s), "/", l2);
		assert(ex.error == FetchError::Timeout && ex.total_ms < 1000);
	}
}

static void test_connect_errors_and_validation() {
	SocketTransport t;
	uint16_t closed_port;
	{
		Server s([](const std::string&) { return reply(""); });
		closed_port = s.port();
	}                                                                          // server gone: the port is closed now
	Endpoint e;
	e.ip = "127.0.0.1";
	e.port = closed_port;
	Exchange ex = t.get(e, "/", quick());
	assert(!ex.response && ex.error == FetchError::ConnectRefused);

	Server s([](const std::string&) { return reply(http_ok("x")); });
	Endpoint good = ep(s);
	// invalid requests are refused without any connection being made
	for (const char* bad : {"", "noslash", "/a b", "/a\r\nX-Injected: 1", "/\x01"}) {
		Exchange r = t.get(good, bad, quick());
		assert(!r.response && r.error == FetchError::Protocol);
	}
	Endpoint bad_host = good;
	bad_host.host = "evil.example\r\nX-Injected: 1";
	assert(t.get(bad_host, "/", quick()).error == FetchError::Protocol);
	Endpoint not_ip = good;
	not_ip.ip = "localhost";
	assert(t.get(not_ip, "/", quick()).error == FetchError::ConnectFailed);   // no DNS: only literal addresses
	Endpoint zero_port = good;
	zero_port.port = 0;
	assert(t.get(zero_port, "/", quick()).error == FetchError::Protocol);
	assert(s.connections() == 0);                                              // none of those reached the server
}

static void test_tls() {
	Cert cert;
	make_cert(cert, "test.example", "DNS:test.example,DNS:*.test.example,IP:127.0.0.1");
	SocketTransport t;
	{
		Server s([](const std::string&) { return reply(http_ok("secure hello", "Server: tlssrv\r\n")); }, &cert);
		Exchange ex = t.get(ep(s, true, "test.example"), "/", quick());
		assert(ex.error == FetchError::None && ex.response && ex.response->body == "secure hello");
		assert(ex.tls && (ex.tls->version == "TLSv1.3" || ex.tls->version == "TLSv1.2") && !ex.tls->cipher.empty());
		assert(ex.tls->chain_length >= 1 && ex.tls->certificate);

		const CertInfo& c = *ex.tls->certificate;
		assert(c.subject.find("CN=test.example") != std::string::npos && c.subject.find("O=Proculus Test") != std::string::npos);
		assert(c.issuer == c.subject && c.self_signed && !c.expired && !c.not_yet_valid);
		assert(c.key_type == "EC" && c.key_bits == 256 && c.signature_algorithm.find("ecdsa") != std::string::npos);
		assert(c.serial == "C0FFEE" && c.sha256.size() == 64 && c.not_before.size() == 20 && c.not_after > c.not_before);
		assert(std::find(c.san.begin(), c.san.end(), "test.example") != c.san.end() && std::find(c.san.begin(), c.san.end(), "127.0.0.1") != c.san.end());
		assert(c.hostname_match && *c.hostname_match);
		assert(s.last_sni() == "test.example");                                // SNI carries the host name
		assert(contains(s.last_request(), "\r\nHost: test.example:" + std::to_string(s.port()) + "\r\n"));
	}
	{
		Server s([](const std::string&) { return reply(http_ok("x")); }, &cert);
		Exchange ex = t.get(ep(s, true, "wrong.example"), "/", quick());
		assert(ex.tls->certificate->hostname_match && !*ex.tls->certificate->hostname_match);   // reported, not fatal
		assert(ex.response && s.last_sni() == "wrong.example");
	}
	{
		Server s([](const std::string&) { return reply(http_ok("x")); }, &cert);
		Exchange ex = t.get(ep(s, true, ""), "/", quick());                     // by address: no SNI, matched against the IP SAN
		assert(ex.response && s.last_sni().empty());
		assert(ex.tls->certificate->hostname_match == std::nullopt);            // no host given: not checked
	}
	{
		Server s([](const std::string&) { return reply(http_ok("x")); }, &cert);
		Endpoint e = ep(s, true, "127.0.0.1");
		Exchange ex = t.get(e, "/", quick());
		assert(ex.tls->certificate->hostname_match && *ex.tls->certificate->hostname_match && s.last_sni().empty());
	}
	{
		Cert old;
		make_cert(old, "old.example", "DNS:old.example", 400, 365);              // expired 35 days ago
		Server s([](const std::string&) { return reply(http_ok("x")); }, &old);
		Exchange ex = t.get(ep(s, true, "old.example"), "/", quick());
		assert(ex.response && ex.tls->certificate->expired && !ex.tls->certificate->not_yet_valid);   // still reachable
		Cert future;
		make_cert(future, "future.example", "DNS:future.example", -10, 365);     // valid from 10 days ahead
		Server s2([](const std::string&) { return reply(http_ok("x")); }, &future);
		Exchange ex2 = t.get(ep(s2, true, "future.example"), "/", quick());
		assert(ex2.tls->certificate->not_yet_valid && !ex2.tls->certificate->expired);
	}
}

static void test_tls_mismatches() {
	SocketTransport t;
	{
		Server plain([](const std::string&) { return reply("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"); }, nullptr, true);
		Exchange ex = t.get(ep(plain, true, "x.example"), "/", quick());        // TLS to a plain HTTP port
		assert(!ex.response && ex.error == FetchError::TlsFailed && !ex.error_detail.empty());
	}
	{
		Cert cert;
		make_cert(cert, "x.example", "DNS:x.example");
		Server tls([](const std::string&) { return reply(http_ok("x")); }, &cert);
		Exchange ex = t.get(ep(tls, false), "/", quick());                       // plain HTTP to a TLS port
		assert(!ex.response && ex.error != FetchError::None);
	}
}

static void test_peer_that_slams_the_connection() {
	// Servers that close right after the handshake make the request write fail.
	// That must come back as an error, never as SIGPIPE killing this process
	// (SIGPIPE is deliberately left at its default action here).
	Cert cert;
	make_cert(cert, "x.example", "DNS:x.example");
	SocketTransport t;
	Server tls_drop([](const std::string&) { return reply(""); }, &cert, false, true);
	Server plain_drop([](const std::string&) { return reply(""); }, nullptr, false, true);
	TransportLimits lim = quick();
	for (int i = 0; i < 60; i++) {
		Exchange a = t.get(ep(tls_drop, true, "x.example"), "/", lim);
		Exchange b = t.get(ep(plain_drop), "/", lim);
		assert(!a.response && a.error != FetchError::None);
		assert(!b.response && b.error != FetchError::None);
	}
	// and a big response aborted by the client (it stops reading at max_body) is fine too
	TransportLimits tiny = quick();
	tiny.max_body = 100;
	Server big([](const std::string&) { return reply(http_ok(std::string(5000000, 'z'))); }, &cert);
	for (int i = 0; i < 5; i++) {
		Exchange ex = t.get(ep(big, true, "x.example"), "/", tiny);
		assert(ex.response && ex.response->body.size() == 100 && ex.response->body_truncated);
	}
}

int main() {
	test_peer_that_slams_the_connection();
	test_plain_response_and_request_shape();
	test_host_header();
	test_bodies();
	test_size_limits();
	test_header_parsing();
	test_not_http_and_malformed();
	test_timeouts_and_partial_responses();
	test_connect_errors_and_validation();
	test_tls();
	test_tls_mismatches();
	return 0;
}
