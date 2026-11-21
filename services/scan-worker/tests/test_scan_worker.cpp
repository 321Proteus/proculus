#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>

#include "job.hpp"
#include "nmap_xml.hpp"
#include "process.hpp"
#include <nlohmann/json.hpp>

#include "result_json.hpp"

using namespace proculus;

static const char* XML = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///opt/local/share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1" version="7.99">
<host starttime="1" endtime="2"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
<hostnames><hostname name="web.lab" type="PTR"/></hostnames>
<ports>
<extraports state="closed" count="997"/>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="http" product="nginx" version="1.24.0" extrainfo="Ubuntu &quot;lts&quot;" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="0"/></port>
</ports></host>
<host><status state="down" reason="no-response"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
<runstats><finished time="3" elapsed="1.25" exit="success"/><hosts up="1" down="1" total="2"/></runstats>
</nmaprun>)";

static void test_parse() {
	NmapResult r = parse_nmap_xml(XML);
	assert(r.nmap_version == "7.99");
	assert(r.hosts_up == 1 && r.hosts_down == 1 && r.elapsed_seconds == 1.25);
	assert(r.hosts.size() == 2);

	const HostResult& h = r.hosts[0];
	assert(h.address == "10.0.0.5" && h.state == "up" && h.reason == "syn-ack");
	assert(h.hostnames.size() == 1 && h.hostnames[0] == "web.lab");
	assert(h.ports.size() == 3);
	assert(h.ports[0].port == 80 && h.ports[0].state == "open" &&
		h.ports[0].protocol == "tcp");
	assert(h.ports[0].has_service);
	const ServiceInfo& s = h.ports[0].service;
	assert(s.name == "http" && s.product == "nginx" && s.version == "1.24.0");
	assert(s.extrainfo == "Ubuntu \"lts\"" && s.confidence == 10 &&
		s.method == "probed");
	assert(
		s.cpes.size() == 2 && s.cpes[0] == "cpe:/a:igor_sysoev:nginx:1.24.0");
	assert(
		h.ports[1].service.name == "ssh" && h.ports[1].service.product.empty());
	assert(!h.ports[2].has_service);

	assert(r.hosts[1].address == "10.0.0.6" && r.hosts[1].state == "down" &&
		r.hosts[1].ports.empty());

	std::string j = to_json(r);
	assert(j.find("\"address\": \"10.0.0.5\"") != std::string::npos);
	assert(j.find("Ubuntu \\\"lts\\\"") != std::string::npos);
	// the output is valid JSON that reads back to the same data
	auto doc = nlohmann::json::parse(j);
	assert(doc.at("hosts").size() == 2 && doc.at("hosts")[0].at("ports")[0].at("service").at("extrainfo") == "Ubuntu \"lts\"");
	assert(doc.at("hosts")[0].at("ports")[0].at("service").at("cpes").size() == 2 && doc.at("hosts_up") == 1);
	assert(doc.at("elapsed_seconds") == 1.25);

	// invalid UTF-8 from a banner is replaced, not fatal
	r.hosts[0].ports[0].service.product = std::string("evil \xff\xfe");
	assert(nlohmann::json::parse(to_json(r)).at("hosts")[0].at("ports")[0].at("service").at("product").get<std::string>().find("evil") == 0);
}

static void test_parse_errors() {
	auto bad = [](const std::string& xml) {
		try {
			parse_nmap_xml(xml);
		} catch (const std::runtime_error&) { return true; }
		return false;
	};
	assert(bad("<nmaprun><host>")); // truncated
	assert(bad("")); // empty
	assert(bad("not xml at all"));
	assert(bad(
		"<!DOCTYPE x [<!ENTITY a \"b\">]><nmaprun/>")); // entity declaration
	assert(!bad("<nmaprun/>"));
	assert(parse_nmap_xml("<nmaprun/>").hosts.empty());
}

static JobLimits limits() {
	JobLimits l;
	l.scope = "10.0.0.0/16,192.168.0.0/24";
	l.allowed_ports = "22,80,443,8000-8100";
	return l;
}

static bool has(const NmapCommand& c, const std::string& a) {
	return std::find(c.argv.begin(), c.argv.end(), a) != c.argv.end();
}

static bool rejected(
	const ScanJob& j, const JobLimits& l, const char* contains = "") {
	try {
		build_command(j, l);
	} catch (const JobRejected& e) {
		return std::string(e.what()).find(contains) != std::string::npos;
	}
	return false;
}

static void test_command_building() {
	ScanJob j;
	j.targets = "10.0.1.0/24,192.168.0.5";
	NmapCommand c = build_command(j, limits());
	assert(c.target_count == 257 && c.reserved_stripped == 0);
	assert(
		c.argv[0] == "nmap" && has(c, "-sn") && has(c, "-n") && has(c, "-oX"));
	assert(has(c, "-PS80,443") && !has(c, "-PE") && !has(c, "-sT"));
	assert(has(c, "10.0.1.0/24") && has(c, "192.168.0.5"));
	assert(has(c, "--max-rate") && has(c, "100") && has(c, "-T3"));

	j.stage = Stage::Services;
	j.privileged = true;
	c = build_command(j, limits());
	assert(has(c, "-sS") && has(c, "-Pn") && has(c, "--open") && has(c, "-sV"));
	assert(has(c, "22,80,443,8000-8100")); // default: all allowed ports
	j.ports = "80,8080";
	j.privileged = false;
	j.version_detect = false;
	c = build_command(j, limits());
	assert(has(c, "-sT") && !has(c, "-sV") && has(c, "80,8080"));

	// reserved targets are stripped, not scanned
	j = ScanJob{};
	j.targets = "10.0.0.0/30,127.0.0.1,224.0.0.5";
	c = build_command(j, [] {
		auto l = limits();
		l.scope += ",0.0.0.0/0";
		return l;
	}());
	assert(c.target_count == 4 && c.reserved_stripped == 2);

	// probe ports are narrowed to the allowed list
	j = ScanJob{};
	j.targets = "10.0.0.1";
	j.probe_ports = "80,3389";
	assert(has(build_command(j, limits()), "-PS80"));
	j.probe_ports = "3389";
	c = build_command(j, limits());
	assert(std::none_of(c.argv.begin(), c.argv.end(),
		[](const std::string& a) { return a.rfind("-PS", 0) == 0; }));
}

static void test_rejections() {
	ScanJob j;
	j.targets = "10.0.1.0/24";
	JobLimits l = limits();

	ScanJob out = j;
	out.targets = "10.0.1.0/24,10.1.0.1";
	assert(rejected(out, l, "outside the allowed scope"));
	out.targets = "8.8.8.8";
	assert(rejected(out, l, "10.1.0.1") == false);
	assert(rejected(out, l, "8.8.8.8"));

	out = j;
	out.targets = "";
	assert(rejected(out, l));
	out.targets = "10.0.0.1; rm -rf /";
	assert(rejected(out, l, "invalid targets"));
	out.targets = "-oN /etc/passwd";
	assert(rejected(out, l, "invalid targets"));
	out.targets = "127.0.0.1";
	assert(rejected(out, l, "no scannable targets"));

	out = j;
	out.stage = Stage::Services;
	out.ports = "80,3306";
	assert(rejected(out, l, "outside the allowed list"));
	out.ports = "80 --script vuln";
	assert(rejected(out, l, "invalid ports"));

	out = j;
	out.rate = 5000;
	assert(rejected(out, l, "exceeds"));
	out.rate = 0;
	assert(rejected(out, l));
	out = j;
	out.timing = 5;
	assert(rejected(out, l, "-T5"));
	out = j;
	out.retries = 99;
	assert(rejected(out, l));

	JobLimits none = l;
	none.scope = "";
	assert(rejected(j, none, "no scope"));
	none = l;
	none.allowed_ports = "";
	assert(rejected(j, none, "no allowed ports"));

	// timeout is capped by the limit
	l.max_timeout_s = 30;
	j.timeout_s = 600;
	assert(build_command(j, l).timeout_s == 30);
}

static void test_process() {
	RunResult r = run_process({ "sh", "-c", "echo out; echo err >&2; exit 3" });
	assert(r.exit_code == 3 && r.out == "out\n" && r.err == "err\n" &&
		!r.timed_out);

	// larger than a pipe buffer: must not deadlock
	r = run_process({ "sh", "-c",
		"head -c 300000 /dev/zero | tr '\\0' x; head -c 300000 /dev/zero | tr "
		"'\\0' y >&2" });
	assert(
		r.exit_code == 0 && r.out.size() == 300000 && r.err.size() == 300000);

	RunOptions o;
	o.timeout = std::chrono::seconds(1);
	o.kill_grace = std::chrono::milliseconds(300);
	auto t0 = std::chrono::steady_clock::now();
	r = run_process({ "sleep", "30" }, o);
	assert(r.timed_out && r.term_signal != 0);
	assert(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5));

	// grandchildren in the same group die too, even when SIGTERM is ignored
	t0 = std::chrono::steady_clock::now();
	r = run_process({ "sh", "-c", "trap '' TERM; sleep 30 & sleep 30" }, o);
	assert(r.timed_out);
	assert(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(6));

	std::atomic<bool> cancel{ false };
	o = RunOptions{};
	o.cancel = &cancel;
	std::thread t([&] {
		std::this_thread::sleep_for(std::chrono::milliseconds(300));
		cancel = true;
	});
	r = run_process({ "sleep", "30" }, o);
	t.join();
	assert(r.cancelled && !r.timed_out);

	o = RunOptions{};
	o.max_output = 1000;
	r = run_process({ "sh", "-c", "yes" }, o);
	assert(r.output_truncated && r.out.size() <= 1000);

	r = run_process({ "/nonexistent/binary" });
	assert(r.exit_code == 127);
}

int main() {
	test_parse();
	test_parse_errors();
	test_command_building();
	test_rejections();
	test_process();
	return 0;
}
