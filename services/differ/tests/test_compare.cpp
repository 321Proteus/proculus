#undef NDEBUG
#include <cassert>

#include "compare.hpp"
#include "report.hpp"

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

static ServiceRecord W(uint16_t port, WebRecord w) {
	ServiceRecord s = S(port, "nginx", "1.24.0");
	s.web = std::move(w);
	return s;
}

static WebRecord web(const char* title, int status = 200) {
	WebRecord w;
	w.status = status;
	w.title = title;
	w.server = "nginx";
	return w;
}

static DetectionRecord det(const char* id, const char* version = "") {
	DetectionRecord d;
	d.id = id;
	d.name = id;
	d.version = version;
	return d;
}

static const WebChange* find_change(const Comparison& c, const std::string& what) {
	for (const WebChange& w : c.web_changes)
		if (w.what == what) return &w;
	return nullptr;
}

static void test_web_changes() {
	WebRecord a = web("Welcome");
	a.cookies = {{"sid", true, true, ""}};
	a.detections = {det("wordpress", "6.4"), det("php")};
	a.tls = TlsRecord{};
	a.tls->sha256 = "aa";
	WebRecord b = web("Maintenance", 503);
	b.server = "Apache";
	b.redirects = {"/login"};
	b.cookies = {{"sid", true, true, ""}, {"track", false, false, ""}};
	b.detections = {det("wordpress", "6.5"), det("phpmyadmin")};
	b.tls = TlsRecord{};
	b.tls->sha256 = "bb";
	b.tls->self_signed = true;

	Comparison c = compare_runs(R(1, {H("10.0.0.1", {W(443, a)})}), R(2, {H("10.0.0.1", {W(443, b)})}));
	assert(c.changed_services.empty()); // the identification (nginx 1.24.0) did not change
	auto w = find_change(c, "title");
	assert(w && w->ip == "10.0.0.1" && w->port == 443 && w->before == "Welcome" && w->after == "Maintenance");
	assert(find_change(c, "status")->before == "200" && find_change(c, "status")->after == "503");
	assert(find_change(c, "server")->after == "Apache" && find_change(c, "redirect")->after == "/login");
	assert(find_change(c, "cookies")->before == "sid" && find_change(c, "cookies")->after == "sid, track");
	assert(find_change(c, "tls certificate")->after == "bb");
	assert(find_change(c, "tls problems")->before.empty() && find_change(c, "tls problems")->after == "self-signed");
	assert(find_change(c, "technology version")->before == "wordpress 6.4" && find_change(c, "technology version")->after == "wordpress 6.5");
	assert(find_change(c, "technology added")->after == "phpmyadmin");
	assert(find_change(c, "technology removed")->before == "php");

	// both report forms show the web changes; text from the network is neutralised
	WebRecord evil = web("bad\x1b[31m");
	const RunRecord ra = R(1, {H("10.0.0.1", {W(443, a)})}), rb = R(2, {H("10.0.0.1", {W(443, evil)})});
	const Comparison ce = compare_runs(ra, rb);
	const std::string text = render_comparison(ra, rb, ce, {});
	assert(text.find("web: ") != std::string::npos && text.find("title: 'Welcome' -> 'bad") != std::string::npos && text.find('\x1b') == std::string::npos);
	ReportOptions jo;
	jo.json = true;
	const std::string js = render_comparison(ra, rb, ce, jo);
	assert(js.find("\"web_changes\"") != std::string::npos && js.find("\"what\": \"title\"") != std::string::npos);

	// identical web data: nothing to report
	assert(compare_runs(R(1, {H("10.0.0.1", {W(443, a)})}), R(2, {H("10.0.0.1", {W(443, a)})})).web_changes.empty());
	// probed for the first time (or no longer probed): there is no baseline, so no change
	assert(compare_runs(R(1, {H("10.0.0.1", {S(443, "nginx", "1.24.0")})}), R(2, {H("10.0.0.1", {W(443, b)})})).web_changes.empty());
	assert(compare_runs(R(1, {H("10.0.0.1", {W(443, b)})}), R(2, {H("10.0.0.1", {S(443, "nginx", "1.24.0")})})).web_changes.empty());
}

int main() {
	test_web_changes();
	test_basic();
	test_identical_and_empty();
	test_ordering_and_protocols();
	test_description_fallback();
	return 0;
}
