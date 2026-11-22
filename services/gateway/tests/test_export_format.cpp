#undef NDEBUG
#include <cassert>
#include <map>

#include "api.hpp"
#include "export_format.hpp"

using namespace proculus;

static const std::set<std::string> kNames = {"ip", "port", "title"};

static std::string fill(const std::string& tmpl, std::map<std::string, std::string> v) {
	return RowTemplate::parse(tmpl, kNames, "t").render([&](const std::string& n) { return v[n]; });
}

static bool refused(const std::string& tmpl) {
	try {
		RowTemplate::parse(tmpl, kNames, "t");
	} catch (const ApiError& e) {
		return e.status == 400;
	}
	return false;
}

int main() {
	assert(fill("{ip}:{port}", {{"ip", "10.0.0.1"}, {"port", "22"}}) == "10.0.0.1:22");
	assert(fill("plain text", {}) == "plain text");
	assert(fill("{ip}\\n{port}\\t{ip}", {{"ip", "a"}, {"port", "b"}}) == "a\nb\ta");
	assert(fill("\\{{ip}\\}", {{"ip", "x"}}) == "{x}");
	assert(fill("{ ip | upper }", {{"ip", "ab"}}) == "AB");

	// values from the network are not trusted: no control characters, so no extra lines
	assert(fill("{title}", {{"title", "a\nb\rc\x01" "d"}}) == "a b c d");
	assert(fill("{title|json}", {{"title", "say \"hi\" \\ \n"}}) == "\"say \\\"hi\\\" \\\\  \"");

	// CSV: quoting, and spreadsheet formulas are defused
	assert(fill("{title|csv}", {{"title", "a,b"}}) == "\"a,b\"");
	assert(fill("{title|csv}", {{"title", "say \"x\""}}) == "\"say \"\"x\"\"\"");
	assert(fill("{title|csv}", {{"title", "=HYPERLINK(\"x\")"}}) == "\"'=HYPERLINK(\"\"x\"\")\"");
	assert(fill("{title|csv}", {{"title", "+1"}}) == "'+1" && fill("{title|csv}", {{"title", "plain"}}) == "plain");

	// the other modifiers
	assert(fill("{title|default:none}", {{"title", ""}}) == "none" && fill("{title|default:none}", {{"title", "x"}}) == "x");
	assert(fill("{title|trim|max:3}", {{"title", "  abcdef "}}) == "abc");
	assert(fill("{title|max:2}", {{"title", "\xc5\x82\xc5\x82\xc5\x82"}}) == "\xc5\x82\xc5\x82"); // cut between characters, not bytes
	assert(fill("{title|lower|upper}", {{"title", "aB"}}) == "AB");

	// everything not understood is refused
	for (const char* bad : {"{nope}", "{ip", "}", "{ip}}", "{ip|}", "{ip|zap}", "{ip|upper:2}", "{ip|default}", "{ip|max}", "{ip|max:0}", "{ip|max:abc}", "\\", "\\x", "{}"}) assert(refused(bad));
	assert(refused(std::string(501, 'a')));
	assert(refused("{ip|upper|upper|upper|upper|upper|upper|upper}"));
	return 0;
}
