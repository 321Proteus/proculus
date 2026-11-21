#undef NDEBUG
#include <cassert>

#include "compare.hpp"

using namespace proculus;

static ServiceRecord S(uint16_t port, const char* product, const char* version, const char* protocol = "tcp") {
	ServiceRecord s;
	s.port = port;
	s.protocol = protocol;
	s.name = "svc";
	s.product = product;
	s.version = version;
	return s;
}

static HostRecord H(const char* ip, std::vector<ServiceRecord> services = {}) {
	HostRecord h;
	h.ip = ip;
	h.services = std::move(services);
	return h;
}

static RunRecord R(int64_t id, std::vector<HostRecord> hosts) {
	RunRecord r;
	r.id = id;
	r.hosts = std::move(hosts);
	return r;
}

static void test_basic() {
	RunRecord a = R(1, {H("10.0.0.2", {S(80, "nginx", "1.24.0"), S(22, "OpenSSH", "8.2")}), H("10.0.0.10"), H("10.0.0.3")});
	RunRecord b = R(2, {H("10.0.0.2", {S(80, "nginx", "1.25.3"), S(443, "nginx", "1.25.3")}), H("10.0.0.10"), H("10.0.0.9", {S(80, "x", "1")})});
	Comparison c = compare_runs(a, b);

	assert(c.before_id == 1 && c.after_id == 2);
	assert(c.new_hosts == std::vector<std::string>{"10.0.0.9"});
	assert(c.gone_hosts == std::vector<std::string>{"10.0.0.3"});
	assert(c.changed_services.size() == 1 && c.changed_services[0].ip == "10.0.0.2" && c.changed_services[0].port == 80);
	assert(c.changed_services[0].before == "nginx 1.24.0" && c.changed_services[0].after == "nginx 1.25.3");
	assert(c.new_services.size() == 1 && c.new_services[0].port == 443 && c.new_services[0].before.empty());
	assert(c.gone_services.size() == 1 && c.gone_services[0].port == 22 && c.gone_services[0].after.empty());
	// services of a host that is itself new are not listed separately
	for (const auto& s : c.new_services) assert(s.ip != "10.0.0.9");
}

static void test_identical_and_empty() {
	RunRecord a = R(1, {H("10.0.0.1", {S(80, "nginx", "1.24.0")})});
	Comparison same = compare_runs(a, a);
	assert(same.new_hosts.empty() && same.gone_hosts.empty() && same.new_services.empty() && same.gone_services.empty() &&
		same.changed_services.empty());

	Comparison from_nothing = compare_runs(R(1, {}), a);
	assert(from_nothing.new_hosts.size() == 1 && from_nothing.gone_hosts.empty());
	Comparison to_nothing = compare_runs(a, R(2, {}));
	assert(to_nothing.gone_hosts.size() == 1 && to_nothing.new_hosts.empty());
	assert(compare_runs(R(1, {}), R(2, {})).new_hosts.empty());
}

static void test_ordering_and_protocols() {
	// numeric address order, not text order ("10.0.0.100" sorts before "10.0.0.20" as text)
	Comparison c = compare_runs(R(1, {}), R(2, {H("10.0.0.100"), H("10.0.0.20"), H("10.0.0.3")}));
	assert((c.new_hosts == std::vector<std::string>{"10.0.0.3", "10.0.0.20", "10.0.0.100"}));

	// same port on tcp and udp are different services
	RunRecord a = R(1, {H("10.0.0.1", {S(53, "BIND", "9", "tcp")})});
	RunRecord b = R(2, {H("10.0.0.1", {S(53, "BIND", "9", "tcp"), S(53, "BIND", "9", "udp")})});
	Comparison d = compare_runs(a, b);
	assert(d.new_services.size() == 1 && d.new_services[0].protocol == "udp" && d.changed_services.empty());

	// unparsable addresses are skipped rather than crashing the comparison
	Comparison e = compare_runs(R(1, {H("not-an-ip")}), R(2, {H("10.0.0.1")}));
	assert(e.new_hosts.size() == 1 && e.gone_hosts.empty());
}

static void test_description_fallback() {
	ServiceRecord named;
	named.port = 8080;
	named.protocol = "tcp";
	named.name = "http-proxy";
	RunRecord a = R(1, {H("10.0.0.1", {named})});
	named.product = "Jetty";
	RunRecord b = R(2, {H("10.0.0.1", {named})});
	Comparison c = compare_runs(a, b);
	assert(c.changed_services.size() == 1 && c.changed_services[0].before == "http-proxy" && c.changed_services[0].after == "Jetty");
}

int main() {
	test_basic();
	test_identical_and_empty();
	test_ordering_and_protocols();
	test_description_fallback();
	return 0;
}
