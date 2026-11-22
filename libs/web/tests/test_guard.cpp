#undef NDEBUG
#include <cassert>

#include "proculus/web/guard.hpp"

using namespace proculus::web;

static bool throws(const std::string& s) {
	try {
		parse_upstream(s);
	} catch (const std::invalid_argument&) {
		return true;
	}
	return false;
}

int main() {
	assert(host_name_of("localhost:8080") == "localhost" && host_name_of("LOCALHOST") == "localhost");
	assert(host_name_of("127.0.0.1:80") == "127.0.0.1" && host_name_of("[::1]:8080") == "[::1]" && host_name_of("[::1]") == "[::1]");
	assert(host_name_of("evil.example:80") == "evil.example" && host_name_of("") == "");

	const auto allowed = default_allowed_hosts();
	assert(host_allowed("localhost:8080", allowed) && host_allowed("127.0.0.1", allowed) && host_allowed("[::1]:1", allowed));
	assert(!host_allowed("attacker.example", allowed) && !host_allowed("", allowed) && !host_allowed("127.0.0.1.attacker.example", allowed));
	assert(!host_allowed("localhost.attacker.example:80", allowed));
	assert(host_allowed("proculus.lan:80", {"proculus.lan"}));

	assert(parse_port("8080") == 8080 && parse_port("1") == 1 && parse_port("65535") == 65535);
	for (const char* bad : {"", "0", "65536", "-1", "80a", "123456", " 80"}) {
		bool threw = false;
		try {
			parse_port(bad);
		} catch (const std::invalid_argument&) {
			threw = true;
		}
		assert(threw);
	}

	Upstream u = parse_upstream("http://api:8081");
	assert(u.host == "api" && u.port == 8081);
	u = parse_upstream("127.0.0.1:9000/");
	assert(u.host == "127.0.0.1" && u.port == 9000);
	u = parse_upstream("http://gateway");
	assert(u.host == "gateway" && u.port == 80);
	assert(throws("https://api:1") && throws("ftp://x") && throws("http://") && throws("http://a/b") && throws("http://u:p@host") && throws("http://host:0"));
	assert(throws("http://ho st") && throws("http://host?x=1") && throws(""));
	return 0;
}
