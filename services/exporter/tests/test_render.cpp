#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <sstream>

#include "render.hpp"

using namespace proculus;

static RunRecord sample() {
	RunRecord r;
	r.id = 3;
	r.source = "sim";
	r.started = "2026-11-21T22:00:00Z";
	r.finished = "2026-11-22T22:00:45Z";
	r.addresses_scanned = 1000;
	r.chunks = 9;
	r.pauses = 1;
	HostRecord h;
	h.ip = "10.20.0.12";
	h.hostname = "web-5";
	ServiceRecord s;
	s.port = 80;
	s.name = "http";
	s.product = "nginx";
	s.version = "1.24.0";
	s.extrainfo = "Ubuntu";
	s.confidence = 10;
	h.services.push_back(s);
	r.hosts.push_back(h);
	HostRecord bare;
	bare.ip = "10.20.0.13";
	r.hosts.push_back(bare);
	return r;
}

static std::vector<std::string> lines(const std::string& s) {
	std::vector<std::string> out;
	std::istringstream in(s);
	std::string l;
	while (std::getline(in, l)) out.push_back(l);
	return out;
}

static void test_formats() {
	assert(parse_format("text") == Format::Text && parse_format("json") == Format::Json && parse_format("csv") == Format::Csv);
	for (const char* bad : {"", "JSON", "xml", "yaml"}) {
		bool threw = false;
		try { parse_format(bad); } catch (const std::invalid_argument&) { threw = true; }
		assert(threw);
	}
}

static void test_json_is_the_stored_form() {
	RunRecord r = sample();
	std::string text = render_run(r, Format::Json);
	RunRecord back = run_from_json(Json::parse(text)); // what the exporter writes can be read back
	assert(back.id == 3 && back.hosts.size() == 2 && back.hosts[0].services[0].product == "nginx");
	assert(text.back() == '\n');
}

static void test_csv() {
	auto l = lines(render_run(sample(), Format::Csv));
	assert(l.size() == 3);
	assert(l[0] == "run,ip,hostname,port,protocol,state,service,product,version,extrainfo,confidence");
	assert(l[1] == "3,10.20.0.12,web-5,80,tcp,open,http,nginx,1.24.0,Ubuntu,10");
	assert(l[2] == "3,10.20.0.13,,,,,,,,,"); // a host without services still appears; same column count
	assert(std::count(l[1].begin(), l[1].end(), ',') == std::count(l[2].begin(), l[2].end(), ','));

	// quoting
	assert(csv_field("plain") == "plain" && csv_field("a,b") == "\"a,b\"" && csv_field("say \"hi\"") == "\"say \"\"hi\"\"\"");
	assert(csv_field("two\nlines") == "\"two\nlines\"" && csv_field("") == "");

	// spreadsheet formula injection from scanned banners is neutralised
	assert(csv_field("=HYPERLINK(\"http://evil\")") == "\"'=HYPERLINK(\"\"http://evil\"\")\"");
	assert(csv_field("+1") == "'+1" && csv_field("-2") == "'-2" && csv_field("@SUM(A1)") == "'@SUM(A1)");
	assert(csv_field("\tcmd") == "\"'\tcmd\"" || csv_field("\tcmd") == "'\tcmd");
	assert(csv_field("=1+1", false) == "=1+1");
	assert(csv_field("a=b") == "a=b"); // only a leading character matters

	RunRecord r = sample();
	r.hosts[0].services[0].product = "=cmd|' /C calc'!A0";
	r.hosts[0].hostname = "x,\"y\"";
	l = lines(render_run(r, Format::Csv));
	assert(l[1].find(",'=cmd|' /C calc'!A0,") != std::string::npos);
	assert(l[1].find(",\"x,\"\"y\"\"\",") != std::string::npos);
}

static void test_text() {
	std::string t = render_run(sample(), Format::Text);
	assert(t.find("Run 3  (sim)  2026-11-21T22:00:00Z -> 2026-11-22T22:00:45Z") != std::string::npos);
	assert(t.find("2 hosts, 1 services; 1000 addresses scanned in 9 chunks (1 pauses, 0 chunks cut off)") != std::string::npos);
	assert(t.find("10.20.0.12  web-5") != std::string::npos);
	assert(t.find("80/tcp") != std::string::npos && t.find("nginx 1.24.0 (Ubuntu)") != std::string::npos);
	assert(t.find("(no open services found)") != std::string::npos);

	// escape sequences from a hostile banner never reach the terminal
	RunRecord r = sample();
	r.hosts[0].services[0].extrainfo = "\x1b[2J\x1b]0;pwned\x07";
	r.hosts[0].hostname = "a\rb";
	t = render_run(r, Format::Text);
	assert(t.find('\x1b') == std::string::npos && t.find('\x07') == std::string::npos && t.find('\r') == std::string::npos);
}

static void test_list() {
	RunSummary a{1, "sim", "2026-11-21T22:00:00Z", "2026-11-21T22:01:00Z", 320, 553};
	RunSummary b{2, "nmap", "2026-11-22T22:00:00Z", "2026-11-22T22:02:00Z", 5, 9};
	assert(render_list({}, Format::Text) == "no runs stored\n");
	assert(lines(render_list({a, b}, Format::Text)).size() == 3);
	assert(render_list({a, b}, Format::Text).find("320") != std::string::npos);

	auto csv = lines(render_list({a, b}, Format::Csv));
	assert(csv.size() == 3 && csv[0] == "id,source,started,finished,hosts,services" &&
		csv[2] == "2,nmap,2026-11-22T22:00:00Z,2026-11-22T22:02:00Z,5,9");

	Json j = Json::parse(render_list({a, b}, Format::Json));
	assert(j.size() == 2 && j[1].at("hosts").get<int>() == 5 && j[0].at("source") == "sim");
	assert(Json::parse(render_list({}, Format::Json)).empty());
}

int main() {
	test_formats();
	test_json_is_the_stored_form();
	test_csv();
	test_text();
	test_list();
	return 0;
}
