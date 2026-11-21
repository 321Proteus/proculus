#undef NDEBUG
#include <cassert>

#include "analyze.hpp"

using namespace proculus;

static void test_title() {
	assert(extract_title("<html><head><title>Hello</title></head></html>") == "Hello");
	assert(extract_title("<TITLE>Upper</TITLE>") == "Upper");
	assert(extract_title("<title lang=\"en\">With attribute</title>") == "With attribute");
	assert(extract_title("<title>  spaced \n\t out  \r\n title </title>") == "spaced out title");
	assert(extract_title("<title>Tom &amp; Jerry &lt;3 &quot;x&quot; &#39;y&#39; &#x41;&#65;</title>") == "Tom & Jerry <3 \"x\" 'y' AA");
	assert(extract_title("<title>caf&eacute; &mdash; &copy; 2026 &laquo;x&raquo; &Ouml;l &euro;5</title>") == "caf\xc3\xa9 \xe2\x80\x94 \xc2\xa9 2026 \xc2\xab" "x\xc2\xbb \xc3\x96l \xe2\x82\xac" "5");
	assert(extract_title("<title>a &bogus; b &amp c &#12 d</title>") == "a &bogus; b &amp c &#12 d");   // unknown or unterminated: left alone
	assert(extract_title("<title>&#0;&#xD800;&#99999999;x</title>") == "&#0;&#xD800;&#99999999;x");
	assert(extract_title("<title>a\x01\x02" "b\x1b[31m</title>") == "ab[31m");       // control characters removed
	assert(extract_title("<title></title>").empty() && extract_title("<title>   </title>").empty());
	assert(extract_title("no title here").empty() && extract_title("").empty());
	assert(extract_title("<titlex>nope</titlex>").empty());                         // not the title element
	assert(extract_title("<title>first</title><title>second</title>") == "first");
	assert(extract_title("<title>unclosed and then the page goes on and on").find("unclosed") == 0);
	assert(extract_title("<title").empty() && extract_title("<title>").empty());
	assert(extract_title(std::string("<title>") + std::string(5000, 'x') + "</title>").size() == 200);
	// non-ASCII text passes through unchanged
	assert(extract_title("<title>Za\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87</title>") == "Za\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87");
	// a huge document does not matter
	assert(extract_title(std::string(1 << 20, ' ') + "<title>late</title>").empty()); // beyond what is inspected
}

static void test_cookies() {
	auto c = parse_set_cookie("sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600; Domain=example.org");
	assert(c && c->name == "sessionid" && c->value_length == 6 && c->value.empty());
	assert(c->secure && c->http_only && c->same_site == "Lax" && c->path == "/" && c->domain == "example.org" && c->has_expiry);

	c = parse_set_cookie("PHPSESSID=x", true);
	assert(c && c->value == "x" && !c->secure && !c->http_only && c->same_site.empty() && !c->has_expiry);

	c = parse_set_cookie("  a = b ; SECURE ;httponly; samesite=NONE; EXPIRES=Wed, 21 Oct 2026 07:28:00 GMT");
	assert(c && c->name == "a" && c->secure && c->http_only && c->same_site == "None" && c->has_expiry);

	assert(parse_set_cookie("empty=")->value_length == 0);
	assert(parse_set_cookie("x=y=z")->value_length == 3);                           // only the first '=' splits
	assert(parse_set_cookie("x=1; SameSite=Bogus")->same_site.empty());
	for (const char* bad : {"", "novalue", "=nonamed", "; Secure", "bad name=1", "q\"uote=1", "ctl\x01=1"})
		assert(!parse_set_cookie(bad));
	assert(!parse_set_cookie(std::string(300, 'n') + "=1"));
	assert(parse_set_cookie("x=1; Path=" + std::string(1000, 'p'))->path.size() == 256);
}

static void test_urls() {
	auto u = parse_url("http://10.0.0.1/");
	assert(u && u->scheme == "http" && u->host == "10.0.0.1" && u->port == 80 && u->path == "/" && u->to_string() == "http://10.0.0.1/");
	u = parse_url("HTTPS://Example.ORG:8443/a/b?x=1#frag");
	assert(u && u->scheme == "https" && u->host == "example.org" && u->port == 8443 && u->path == "/a/b?x=1");
	assert(u->to_string() == "https://example.org:8443/a/b?x=1");
	assert(parse_url("http://10.0.0.1")->path == "/" && parse_url("http://10.0.0.1?q=1")->path == "/?q=1");
	assert(parse_url("https://h:443/")->to_string() == "https://h/");               // default port omitted

	for (const char* bad : {"", "ftp://x/", "javascript:alert(1)", "//x/", "/path", "http://", "http:///x", "http://u:p@host/", "http://[::1]/",
		     "http://h:0/", "http://h:65536/", "http://h:abc/", "http://h:/", "http://bad host/"})
		assert(!parse_url(bad));
	assert(!parse_url("http://" + std::string(300, 'a') + "/"));
	assert(!parse_url("http://example.org/" + std::string(3000, 'a')));
}

static void test_redirect_resolution() {
	const Url base = *parse_url("http://10.0.0.1:8080/dir/page.html?q=1");
	auto r = [&](const char* loc) { return resolve_location(base, loc); };

	assert(r("http://other.example/x")->to_string() == "http://other.example/x");
	assert(r("https://10.0.0.1/login")->to_string() == "https://10.0.0.1/login");
	assert(r("//cdn.example/lib.js")->to_string() == "http://cdn.example/lib.js");   // keeps the scheme
	assert(r("/admin")->to_string() == "http://10.0.0.1:8080/admin");
	assert(r("other.html")->to_string() == "http://10.0.0.1:8080/dir/other.html");
	assert(r("../up.html")->to_string() == "http://10.0.0.1:8080/up.html");
	assert(r("./same/./x")->to_string() == "http://10.0.0.1:8080/dir/same/x");
	assert(r("../../../../too/far")->to_string() == "http://10.0.0.1:8080/too/far");
	assert(r("?page=2")->to_string() == "http://10.0.0.1:8080/dir/page.html?page=2");
	assert(r("sub/")->to_string() == "http://10.0.0.1:8080/dir/sub/");
	assert(r("/a/b/..")->to_string() == "http://10.0.0.1:8080/a/");
	assert(r("/a//b")->to_string() == "http://10.0.0.1:8080/a//b");
	assert(r("/x#frag")->to_string() == "http://10.0.0.1:8080/x");
	assert(r("  /padded  ")->to_string() == "http://10.0.0.1:8080/padded");

	for (const char* bad : {"", "   ", "javascript:alert(1)", "mailto:a@b", "data:text/html,x", "ftp://x/", "http://u:p@x/", "/a\r\nSet-Cookie: x=1",
		     "http://[::1]/"})
		assert(!r(bad));
	assert(!r(std::string(3000, 'a').c_str()));
}

static void test_host_and_path_validation() {
	for (const char* ok : {"10.0.0.1", "example.org", "a-b.example", "localhost", "web1.dc2.example.pl"}) assert(valid_host(ok));
	for (const char* bad : {"", "10.0.0.1:80", "ex ample.org", "a\r\nb", "evil.com\r\nX: y", "10.0.0.0/24", "10.0.0.1-5", "a..b", "-a.com", "*.example.org",
		     "256.1.1.1", "http://x"})
		assert(!valid_host(bad));
	assert(!valid_host(std::string(300, 'a')));

	for (const char* ok : {"/", "/index.html", "/a/b?x=1&y=%20z", "/favicon.ico"}) assert(valid_path(ok));
	for (const char* bad : {"", "index", "/a b", "/a\r\nHost: evil", "/a\nb", "/a\tb", "/\x7f", "/\xc3\xa9", "http://x/"}) assert(!valid_path(bad));
	assert(!valid_path("/" + std::string(2100, 'a')));
}

static void test_icon_link() {
	assert(find_icon_href("<link rel=\"icon\" href=\"/fav.png\">") == "/fav.png");
	assert(find_icon_href("<link rel=\"shortcut icon\" href=\"/static/favicon.ico\" type=\"image/x-icon\">") == "/static/favicon.ico");
	assert(find_icon_href("<LINK REL='ICON' HREF='a.ico'/>") == "a.ico");
	assert(find_icon_href("<link href=/x.png rel=icon>") == "/x.png");                    // unquoted, any order
	assert(find_icon_href("<link rel=\"stylesheet\" href=\"/s.css\"><link rel=\"icon\" href=\"/i.png\">") == "/i.png");
	assert(find_icon_href("<link rel=\"apple-touch-icon\" href=\"/t.png\">").empty());   // not a plain icon
	assert(find_icon_href("<link rel=\"icon\">").empty() && find_icon_href("<link rel=\"icon\" href=\"\">").empty());
	assert(find_icon_href("<link rel=\"icon\" href=\"/a&amp;b.png\">") == "/a&b.png");
	assert(find_icon_href("no links at all").empty() && find_icon_href("").empty() && find_icon_href("<link rel=\"icon\" href=\"/x").empty());
	assert(find_icon_href("<link rel=\"icon\" href=\"http://other.example/f.ico\">") == "http://other.example/f.ico");  // resolved elsewhere
}

static void test_fingerprints() {
	// MurmurHash3 x86 32-bit reference values
	assert(murmur3_32("", 0) == 0);
	assert(murmur3_32("", 1) == 0x514E28B7);
	assert(murmur3_32("hello", 0) == 0x248bfa47);
	assert(murmur3_32("The quick brown fox jumps over the lazy dog", 0) == 0x2e4ff723);
	assert(murmur3_32("a", 0) == static_cast<int32_t>(0x3c2569b2));
	assert(murmur3_32("abc", 0) == static_cast<int32_t>(0xb3dd93fa));
	assert(murmur3_32("abcd", 0) == 0x43ed676a);
	assert(murmur3_32(std::string("\0\0\0\0", 4), 0) == 0x2362f9de);
	assert(murmur3_32("hello", 0) > 0 && murmur3_32("abc", 0) < 0);                  // signed result

	assert(base64_mime("") == "");
	assert(base64_mime("f") == "Zg==\n" && base64_mime("fo") == "Zm8=\n" && base64_mime("foo") == "Zm9v\n" && base64_mime("foobar") == "Zm9vYmFy\n");
	assert(base64_mime("abc") == "YWJj\n");
	std::string long_input(100, 'A');                                              // 100 bytes -> 136 chars: 76 + 60
	std::string enc = base64_mime(long_input);
	assert(enc.size() == 76 + 1 + 60 + 1 && enc[76] == '\n' && enc.back() == '\n');
	assert(base64_mime(std::string("\xff\xfe\xfd", 3)) == "//79\n");

	// the favicon hash is murmur3 over the MIME base64 text
	assert(favicon_hash("abc") == murmur3_32("YWJj\n"));
	assert(favicon_hash("abc") == favicon_hash("abc") && favicon_hash("abc") != favicon_hash("abd"));

	assert(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	assert(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_headers() {
	std::vector<Header> h = {{"Content-Type", "text/html"}, {"SERVER", "nginx"}, {"Set-Cookie", "a=1"}, {"set-cookie", "b=2"}};
	assert(*find_header(h, "content-type") == "text/html" && *find_header(h, "Server") == "nginx");
	assert(*find_header(h, "SET-COOKIE") == "a=1");                                 // first one
	assert(find_header(h, "X-Missing") == nullptr && find_header({}, "x") == nullptr);
	assert(std::string(to_string(FetchError::TlsFailed)) == "tls_failed" && std::string(to_string(FetchError::None)) == "none");
}

int main() {
	test_title();
	test_cookies();
	test_urls();
	test_redirect_resolution();
	test_host_and_path_validation();
	test_icon_link();
	test_fingerprints();
	test_headers();
	return 0;
}
