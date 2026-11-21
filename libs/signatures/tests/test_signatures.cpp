#undef NDEBUG
#include <cassert>
#include <unistd.h>

#include <cmath>
#include <fstream>

#include "proculus/sig/engine.hpp"
#include "proculus/sig/evidence_json.hpp"

using namespace proculus::sig;

// ------------------------------------------------------------------ helpers

static LoadResult load(SignatureSet& set, const std::string& json, bool builtin = false, LoadPolicy policy = {}) {
	return set.add_json(json, "test.json", builtin, policy);
}

static std::string wrap(const std::string& signature) { return "{\"signatures\":[" + signature + "]}"; }

// One signature with a single signal; `match` is the signal's condition.
static std::string sig(const std::string& id, const std::string& match, const std::string& extra = "") {
	return "{\"id\":\"" + id + "\",\"name\":\"" + id + "\",\"category\":\"other\"," + extra +
		"\"signals\":[{\"weight\":0.8,\"match\":" + match + "}]}";
}

static std::string leaf(const std::string& field, const std::string& op, const std::string& value) {
	return "{\"field\":\"" + field + "\",\"op\":\"" + op + "\",\"value\":" + value + "}";
}

static bool has_error(const LoadResult& r, const std::string& fragment) {
	for (const Diagnostic& d : r.diagnostics)
		if (d.level == Diagnostic::Level::Error && describe(d).find(fragment) != std::string::npos) return true;
	return false;
}

static bool has_warning(const LoadResult& r, const std::string& fragment) {
	for (const Diagnostic& d : r.diagnostics)
		if (d.level == Diagnostic::Level::Warning && describe(d).find(fragment) != std::string::npos) return true;
	return false;
}

static bool detects(const std::string& signature, const Evidence& ev) {
	SignatureSet set;
	const LoadResult r = load(set, wrap(signature));
	assert(!r.has_errors());
	return !evaluate(set, ev).empty();
}

// ------------------------------------------------------------------- fields

static void test_field_catalog() {
	std::string error;
	assert(field_type("status", error) == FieldType::Number && field_type("title", error) == FieldType::String);
	assert(field_type("tls.self_signed", error) == FieldType::Bool && field_type("cookie", error) == FieldType::StringList);
	assert(field_type("header:x-powered-by", error) == FieldType::StringList && field_type("header:X_Custom-1", error) == FieldType::StringList);
	assert(field_type("path:/wp-login.php:status", error) == FieldType::Number);
	assert(field_type("path:/login:body", error) == FieldType::String && field_type("path:/a/b:header:server", error) == FieldType::StringList);

	for (const char* bad : {"", "Status", "nonsense", "header:", "header:bad name", "header:a:b", "path:status", "path:/x", "path:/x:nope", "path:relative:status",
		     "path:/x?y=1:status", "path:/../etc:status", "path:/x:header", "path:/x:status:extra", "path:/x:header:bad name"}) {
		error.clear();
		assert(!field_type(bad, error) && !error.empty());
	}

	assert(valid_probe_path("/login") && valid_probe_path("/wp-login.php") && valid_probe_path("/a/b_c.d~e%20f/") && valid_probe_path("/"));
	for (const char* bad : {"", "login", "/a b", "/a?b=1", "/a#frag", "/../x", "/a/../b", "//x", "/a//b", "/a\r\nb", "/\xc3\xa9", "/a;b", "/a:b"})
		assert(!valid_probe_path(bad));
	assert(!valid_probe_path("/" + std::string(250, 'a')));

	assert(probe_path_of("path:/wp-login.php:status") == "/wp-login.php" && !probe_path_of("title") && !probe_path_of("header:x"));
	assert(op_allowed(FieldType::Number, Op::Gt) && !op_allowed(FieldType::Number, Op::Contains) && !op_allowed(FieldType::Bool, Op::Regex));
	assert(op_allowed(FieldType::StringList, Op::Regex) && !op_allowed(FieldType::String, Op::Lt));
	assert(parse_op("regex") == Op::Regex && !parse_op("matches") && std::string(to_string(Op::Ge)) == "ge");
}

static void test_evidence() {
	Evidence ev;
	ev.set("status", 200);
	ev.set("title", "Hello World");
	ev.set("tls", true);
	ev.add("cookie", "a");
	ev.add("cookie", "b");
	ev.set_list("header:server", {"nginx"});
	assert(ev.size() == 5 && ev.has("status") && !ev.has("nope"));
	assert(std::get<double>(*ev.find("status")) == 200 && std::get<std::string>(*ev.find("title")) == "Hello World");
	assert(std::get<std::vector<std::string>>(*ev.find("cookie")).size() == 2);
	assert(ev.lowered("title") == "hello world" && ev.lowered("status").empty() && ev.lowered("nope").empty());
	ev.set("title", "CHANGED");                                  // replacing invalidates the cached lowercase
	assert(ev.lowered("title") == "changed");
	ev.add("title", "x");                                        // add() on a non-list replaces it with a list
	assert(std::holds_alternative<std::vector<std::string>>(*ev.find("title")));
}

// ------------------------------------------------------------------- loading

static void test_loading_a_valid_signature() {
	SignatureSet set;
	const LoadResult r = load(set, R"J({
	  "format": 1,
	  "signatures": [{
	    "id": "wordpress", "name": "WordPress", "category": "cms", "tags": ["php", "blog"], "interest": 2,
	    "description": "A CMS", "references": ["https://wordpress.org/"], "threshold": 0.6,
	    "signals": [
	      {"weight": 0.7, "label": "theme files", "match": {"field": "body", "op": "contains", "value": "/wp-content/"}},
	      {"weight": 0.9, "required": false, "match": {"all": [
	          {"field": "path:/wp-login.php:status", "op": "equals", "value": [200, 302]},
	          {"not": {"field": "header:x-frame-options", "op": "exists"}}]}}
	    ],
	    "exclude": {"field": "title", "op": "contains", "value": "honeypot"},
	    "version": {"field": "body", "regex": "WordPress ([0-9.]+)"},
	    "examples": [{"name": "theme", "evidence": {"body": "x /wp-content/ y"}, "expect": "match"}]
	  }]})J");
	assert(!r.has_errors() && r.warnings() == 0 && r.loaded == 1 && set.size() == 1);

	const Signature& s = *set.find("wordpress");
	assert(s.name == "WordPress" && s.category == Category::Cms && s.interest == 2 && s.threshold == 0.6 && s.enabled && !s.builtin);
	assert(s.tags.size() == 2 && s.references.size() == 1 && s.signals.size() == 2 && s.examples.size() == 1 && s.exclude && s.version);
	assert(s.signals[0].label == "theme files" && s.signals[1].match.kind == Condition::Kind::All && s.signals[1].match.children[1].kind == Condition::Kind::Not);
	assert(s.signals[1].match.children[0].leaf.numbers.size() == 2 && s.source == "test.json");
	assert(set.required_paths() == std::vector<std::string>{"/wp-login.php"});
}

static void test_structure_errors() {
	SignatureSet set;
	assert(has_error(load(set, "not json"), "not valid JSON") && set.size() == 0);
	assert(has_error(load(set, "[]"), "top level must be an object"));
	assert(has_error(load(set, "{}"), "needs a \"signatures\" list"));
	assert(has_error(load(set, "{\"format\":2,\"signatures\":[]}"), "unsupported format"));
	assert(has_error(load(set, "{\"signatures\":{}}"), "expected a list"));
	assert(has_error(load(set, "{\"signatures\":[],\"extra\":1}"), "unknown key \"extra\""));
	assert(has_error(load(set, "{\"signatures\":[5]}"), "must be an object"));
	assert(!load(set, "{\"signatures\":[]}").has_errors());             // an empty list is fine
	LoadPolicy small;
	small.max_signatures_per_source = 2;
	assert(has_error(load(set, "{\"signatures\":[{},{},{}]}", false, small), "more than 2 signatures"));
}

static void test_typos_are_caught_with_hints() {
	SignatureSet set;
	LoadResult r = load(set, wrap(R"J({"id":"a","name":"A","category":"cms","signals":[{"wieght":0.5,"match":{"field":"title","op":"contains","value":"x"}}]})J"));
	assert(has_error(r, "signals[0].wieght") && has_error(r, "did you mean \"weight\"?") && set.size() == 0);
	r = load(set, wrap(R"J({"id":"a","name":"A","categroy":"cms","signals":[]})J"));
	assert(has_error(r, "did you mean \"category\"?"));
	r = load(set, wrap(sig("a", R"J({"field":"title","oper":"contains","value":"x"})J")));
	assert(has_error(r, "unknown key \"oper\"") && has_error(r, "did you mean \"op\"?"));
	r = load(set, wrap(sig("a", R"J({"all":[{"field":"title","op":"contains","value":"x"}],"any":[]})J")));
	assert(has_error(r, "only one of"));
	r = load(set, wrap(sig("a", R"J({"field":"title","op":"contains","value":"x","all":[]})J")));
	assert(has_error(r, "only one of") || has_error(r, "unknown key"));
}

static void test_signature_field_errors() {
	auto fails = [](const std::string& body, const std::string& fragment) {
		SignatureSet set;
		const LoadResult r = load(set, wrap(body));
		return has_error(r, fragment) && set.size() == 0;
	};
	const std::string ok_signals = R"J("signals":[{"weight":0.8,"match":{"field":"title","op":"contains","value":"x"}}])J";
	assert(fails("{\"name\":\"A\",\"category\":\"cms\"," + ok_signals + "}", "needs an \"id\""));
	for (const char* bad_id : {"", "UPPER", "has space", "-start", "a/b", "é"})
		assert(fails(std::string("{\"id\":\"") + bad_id + "\",\"name\":\"A\",\"category\":\"cms\"," + ok_signals + "}", "id"));
	assert(fails("{\"id\":\"" + std::string(65, 'a') + "\",\"name\":\"A\",\"category\":\"cms\"," + ok_signals + "}", "id"));
	assert(fails("{\"id\":\"a\",\"category\":\"cms\"," + ok_signals + "}", "needs a \"name\""));
	assert(fails("{\"id\":\"a\",\"name\":\"A\"," + ok_signals + "}", "needs a \"category\""));
	assert(fails("{\"id\":\"a\",\"name\":\"A\",\"category\":\"gizmo\"," + ok_signals + "}", "must be one of cms"));
	assert(fails("{\"id\":\"a\",\"name\":\"\",\"category\":\"cms\"," + ok_signals + "}", "name"));
	assert(fails("{\"id\":\"a\",\"name\":\"A\",\"category\":\"cms\"}", "needs a non-empty list of \"signals\""));
	assert(fails("{\"id\":\"a\",\"name\":\"A\",\"category\":\"cms\",\"signals\":[]}", "needs a non-empty list"));
	const std::string head = "{\"id\":\"a\",\"name\":\"A\",\"category\":\"cms\",";
	assert(fails(head + "\"interest\":6," + ok_signals + "}", "0 to 5"));
	assert(fails(head + "\"interest\":1.5," + ok_signals + "}", "0 to 5"));
	assert(fails(head + "\"threshold\":0," + ok_signals + "}", "threshold"));
	assert(fails(head + "\"threshold\":1.2," + ok_signals + "}", "threshold"));
	assert(fails(head + "\"tags\":[\"UPPER\"]," + ok_signals + "}", "tags"));
	assert(fails(head + "\"tags\":\"x\"," + ok_signals + "}", "tags"));
	assert(fails(head + "\"references\":[\"ftp://x\"]," + ok_signals + "}", "http://"));
	assert(fails(head + "\"enabled\":\"yes\"," + ok_signals + "}", "true or false"));
	assert(fails(head + "\"signals\":[{\"weight\":0,\"match\":" + leaf("title", "contains", "\"x\"") + "}]}", "weight"));
	assert(fails(head + "\"signals\":[{\"weight\":1.5,\"match\":" + leaf("title", "contains", "\"x\"") + "}]}", "weight"));
	assert(fails(head + "\"signals\":[{\"match\":" + leaf("title", "contains", "\"x\"") + "}]}", "weight"));
	assert(fails(head + "\"signals\":[{\"weight\":0.5}]}", "needs a \"match\""));
	assert(fails(head + "\"signals\":[{\"weight\":0.5,\"match\":" + leaf("title", "contains", "\"x\"") + ",\"required\":1}]}", "true or false"));

	// the threshold must be reachable by the signals together
	assert(fails(head + "\"threshold\":0.95,\"signals\":[{\"weight\":0.5,\"match\":" + leaf("title", "contains", "\"x\"") + "}]}", "can never be reached"));
	SignatureSet set;
	assert(!load(set, wrap(head + "\"threshold\":0.95,\"signals\":[{\"weight\":0.8,\"match\":" + leaf("title", "contains", "\"x\"") + "},{\"weight\":0.8,\"match\":" + leaf("body", "contains", "\"y\"") + "}]}")).has_errors());
}

static void test_leaf_errors() {
	auto bad = [](const std::string& match, const std::string& fragment) {
		SignatureSet set;
		const LoadResult r = load(set, wrap(sig("a", match)));
		return has_error(r, fragment) && set.size() == 0;
	};
	assert(bad(R"J({"op":"equals","value":"x"})J", "needs a \"field\""));
	assert(bad(R"J({"field":"nonsense","op":"equals","value":"x"})J", "unknown field"));
	assert(bad(R"J({"field":"title","value":"x"})J", "needs an \"op\""));
	assert(bad(R"J({"field":"title","op":"matches","value":"x"})J", "unknown operator"));
	assert(bad(R"J({"field":"status","op":"contains","value":"x"})J", "does not apply to number field"));
	assert(bad(R"J({"field":"title","op":"gt","value":1})J", "does not apply to string field"));
	assert(bad(R"J({"field":"tls","op":"regex","value":"x"})J", "does not apply to bool field"));
	assert(bad(R"J({"field":"title","op":"contains"})J", "needs a \"value\""));
	assert(bad(R"J({"field":"title","op":"contains","value":5})J", "expected a string"));
	assert(bad(R"J({"field":"title","op":"contains","value":""})J", "empty string"));
	assert(bad(R"J({"field":"title","op":"contains","value":[]})J", "non-empty list"));
	assert(bad(R"J({"field":"title","op":"contains","value":["a",3]})J", "value[1]"));
	assert(bad(leaf("title", "contains", "\"" + std::string(301, 'a') + "\""), "longer than 300"));
	assert(bad(R"J({"field":"status","op":"equals","value":"200"})J", "expected a number"));
	assert(bad(R"J({"field":"status","op":"gt","value":[1,2]})J", "single number"));
	assert(bad(R"J({"field":"tls","op":"equals","value":"yes"})J", "true or false"));
	assert(bad(R"J({"field":"title","op":"exists","value":"maybe"})J", "true (must exist) or false"));
	assert(bad(R"J({"field":"title","op":"contains","value":"x","case_sensitive":"yes"})J", "true or false"));
	assert(bad(R"J({"field":"title","op":"regex","value":"(oops"})J", "bad regular expression"));
	assert(bad(R"J({"field":"title","op":"regex","value":["fine","(oops"]})J", "value[1]"));
	assert(bad(leaf("title", "regex", "\"" + std::string(600, 'a') + "\""), "longer than"));
	assert(bad(R"J({"field":"path:/x?y=1:status","op":"equals","value":200})J", "not an allowed probe path"));
	assert(bad(R"J({"all":[]})J", "non-empty list of conditions"));
	assert(bad(R"J({"not":5})J", "expected an object"));
	assert(bad(R"J(5)J", "expected an object"));

	// short patterns on big fields are flagged, not refused
	SignatureSet set;
	const LoadResult r = load(set, wrap(sig("a", leaf("body", "contains", "\"ab\""))));
	assert(!r.has_errors() && has_warning(r, "very short") && set.size() == 1);
	SignatureSet set2;
	assert(load(set2, wrap(sig("a", leaf("header:server", "contains", "\"ab\"")))).warnings() == 0);   // fine for short fields

	// nesting and size limits
	std::string deep = leaf("title", "contains", "\"x\"");
	for (int i = 0; i < 8; i++) deep = "{\"all\":[" + deep + "]}";
	assert(bad(deep, "nested more than"));
	std::string many = "{\"any\":[";
	for (int i = 0; i < 45; i++) many += (i ? "," : "") + leaf("title", "contains", "\"x\"");
	assert(bad(many + "]}", "more than 40 matchers"));
}

static void test_ids_overrides_and_disable() {
	SignatureSet set;
	assert(load(set, wrap(sig("nginx", leaf("server", "contains", "\"nginx\""))), true).loaded == 1);
	assert(set.find("nginx")->builtin);

	// two with the same id in one file
	SignatureSet dup;
	LoadResult r = load(dup, "{\"signatures\":[" + sig("same", leaf("title", "contains", "\"x\"")) + "," + sig("same", leaf("title", "contains", "\"y\"")) + "]}");
	assert(r.loaded == 1 && has_error(r, "duplicate id in this file"));

	// a custom file may not silently shadow a built-in...
	r = load(set, wrap(sig("nginx", leaf("title", "contains", "\"mine\""))));
	assert(r.loaded == 0 && has_error(r, "built-in signature") && set.find("nginx")->builtin);
	// ...but can replace it on request
	r = load(set, wrap(sig("nginx", leaf("title", "contains", "\"mine\""), "\"override\":true,")));
	assert(r.loaded == 1 && !set.find("nginx")->builtin && set.size() == 1);
	// override has no effect on a non-builtin duplicate
	r = load(set, wrap(sig("nginx", leaf("title", "contains", "\"again\""), "\"override\":true,")));
	assert(r.loaded == 0 && has_error(r, "already defined in test.json"));
	// and a built-in cannot override anything
	SignatureSet b;
	load(b, wrap(sig("x", leaf("title", "contains", "\"1\""))), true);
	assert(load(b, wrap(sig("x", leaf("title", "contains", "\"2\""), "\"override\":true,")), true).loaded == 0);

	// disabling
	SignatureSet d;
	load(d, wrap(sig("one", leaf("title", "contains", "\"abc\""))), true);
	load(d, wrap(sig("two", leaf("title", "contains", "\"abc\""))), true);
	r = load(d, R"J({"disable":["one","ghost"]})J");
	assert(!r.has_errors() && has_warning(r, "no signature \"ghost\"") && !d.find("one")->enabled && d.find("two")->enabled && d.enabled_count() == 1);
	Evidence ev;
	ev.set("title", "abc");
	assert(evaluate(d, ev).size() == 1 && evaluate(d, ev)[0].id == "two");
	assert(has_error(load(d, R"J({"disable":"one"})J"), "list of signature ids"));
	assert(d.set_enabled("one", true) && d.enabled_count() == 2 && !d.set_enabled("ghost", true));
}

static void test_one_bad_signature_does_not_block_the_rest() {
	SignatureSet set;
	const LoadResult r = load(set, "{\"signatures\":[" + sig("good1", leaf("title", "contains", "\"abc\"")) + "," + sig("bad", leaf("nosuchfield", "equals", "\"x\"")) + "," +
					       sig("good2", leaf("title", "contains", "\"def\"")) + "]}");
	assert(r.loaded == 2 && r.errors() == 1 && set.find("good1") && set.find("good2") && !set.find("bad"));
	assert(r.diagnostics[0].signature == "bad" && r.diagnostics[0].where == "signatures[1].signals[0].match.field");
}

static void test_probe_path_limits() {
	auto with_paths = [](int n) {
		std::string list = "{\"signatures\":[";
		for (int i = 0; i < n; i++) list += (i ? "," : "") + sig("s" + std::to_string(i), leaf("path:/p" + std::to_string(i) + ":status", "equals", "200"));
		return list + "]}";
	};
	LoadPolicy policy;
	policy.max_probe_paths = 5;
	SignatureSet ok;
	assert(load(ok, with_paths(5), false, policy).loaded == 5);
	SignatureSet over;
	const LoadResult r = load(over, with_paths(6), false, policy);
	assert(r.loaded == 0 && over.size() == 0 && has_error(r, "asks the prober to fetch 6 different paths") && has_error(r, "nothing from this file was loaded"));
	// the same path used by many signatures counts once
	std::string shared = "{\"signatures\":[";
	for (int i = 0; i < 30; i++) shared += (i ? "," : "") + sig("t" + std::to_string(i), leaf("path:/login:status", "equals", "200"));
	SignatureSet s2;
	assert(load(s2, shared + "]}", false, policy).loaded == 30);
	// built-in data is exempt from the limit
	SignatureSet b;
	assert(load(b, with_paths(9), true, policy).loaded == 9);
}

static void test_required_paths_ordering() {
	// /rare: one signature, interest 4. /common: three signatures, interest 1. /middle: two, interest 2.
	SignatureSet set;
	const std::string all = "{\"signatures\":[" +
		sig("s1", leaf("path:/rare:status", "equals", "200"), "\"interest\":4,") + "," +
		sig("s2", leaf("path:/common:status", "equals", "200"), "\"interest\":1,") + "," +
		sig("s3", leaf("path:/common:body", "contains", "\"xyz\""), "\"interest\":1,") + "," +
		sig("s4", leaf("path:/common:title", "contains", "\"xyz\""), "\"interest\":1,") + "," +
		sig("s5", leaf("path:/middle:status", "equals", "200"), "\"interest\":2,") + "," +
		sig("s6", leaf("path:/middle:status", "equals", "404"), "\"interest\":2,") + "," +
		sig("s7", leaf("path:/aaa:status", "equals", "200"), "\"interest\":2,") + "]}";
	assert(!load(set, all).has_errors());
	// most valuable first: interest, then how many want it, then name
	assert((set.required_paths() == std::vector<std::string>{"/rare", "/middle", "/aaa", "/common"}));
	assert((set.required_paths(2) == std::vector<std::string>{"/rare", "/middle"}));      // a small budget goes to the best findings
	assert(set.required_paths(1) == std::vector<std::string>{"/rare"});
	set.set_enabled("s1", false);
	set.set_enabled("s5", false);
	set.set_enabled("s6", false);
	assert((set.required_paths() == std::vector<std::string>{"/aaa", "/common"}));         // disabled signatures ask for nothing

	// paths in an exclude or a version rule count too
	SignatureSet s2;
	assert(!load(s2, wrap(sig("v", leaf("title", "contains", "\"abc\""), "\"exclude\":" + leaf("path:/ex:status", "equals", "200") + ",\"version\":{\"field\":\"path:/ver:body\",\"regex\":\"v([0-9.]+)\"},"))).has_errors());
	assert((s2.required_paths() == std::vector<std::string>{"/ex", "/ver"}));
}

static void test_evidence_json() {
	Evidence ev;
	std::vector<EvidenceProblem> problems;
	const nlohmann::json j = nlohmann::json::parse(R"J({"status":200,"title":"Hi","tls":true,"header:server":"nginx","cookie":["a","b"],"favicon_hash":-5})J");
	assert(evidence_from_json(j, ev, problems) && problems.empty() && ev.size() == 6);
	assert(std::get<std::vector<std::string>>(*ev.find("header:server")) == std::vector<std::string>{"nginx"});   // a lone string becomes a list
	const auto out = evidence_to_json(ev);
	assert(out["status"] == 200 && out["cookie"].size() == 2 && out["tls"] == true && out["favicon_hash"] == -5 && out["header:server"][0] == "nginx");

	// every problem is reported, valid fields are still read
	Evidence partial;
	problems.clear();
	assert(!evidence_from_json(nlohmann::json::parse(R"J({"status":"200","nosuch":1,"title":"ok","tls":"yes","cookie":[1]})J"), partial, problems));
	assert(problems.size() == 4 && partial.size() == 1 && partial.has("title"));
	problems.clear();
	assert(!evidence_from_json(nlohmann::json::parse("[1]"), partial, problems) && problems.size() == 1);
}

// ----------------------------------------------------------------- evaluation

static void test_string_operators() {
	Evidence ev;
	ev.set("title", "Welcome to NGINX!");
	ev.set("server", "nginx/1.24.0 (Ubuntu)");
	const auto has = [&](const std::string& field, const std::string& op, const std::string& value, const std::string& extra = "") {
		return detects(sig("t", "{\"field\":\"" + field + "\",\"op\":\"" + op + "\",\"value\":" + value + extra + "}"), ev);
	};
	// case-insensitive by default
	assert(has("title", "contains", "\"welcome\"") && has("title", "equals", "\"WELCOME TO NGINX!\"") && has("title", "prefix", "\"welcome\"") && has("title", "suffix", "\"nginx!\""));
	assert(!has("title", "contains", "\"apache\"") && !has("title", "equals", "\"Welcome\"") && !has("title", "prefix", "\"nginx\"") && !has("title", "suffix", "\"welcome\""));
	// ... unless asked otherwise
	assert(!has("title", "contains", "\"welcome\"", ",\"case_sensitive\":true") && has("title", "contains", "\"Welcome\"", ",\"case_sensitive\":true") &&
		!has("title", "equals", "\"welcome to nginx!\"", ",\"case_sensitive\":true") && has("title", "equals", "\"Welcome to NGINX!\"", ",\"case_sensitive\":true"));
	// alternatives: any of them
	assert(has("title", "contains", "[\"apache\",\"nginx\"]") && !has("title", "contains", "[\"apache\",\"iis\"]"));
	// regex
	assert(has("server", "regex", "\"^nginx/[0-9]+\\\\.\"") && !has("server", "regex", "\"^apache\"") && has("server", "regex", "[\"zzz\",\"UBUNTU\\\\)$\"]"));
	assert(!has("server", "regex", "\"NGINX\"", ",\"case_sensitive\":true") && has("server", "regex", "\"nginx\"", ",\"case_sensitive\":true"));
	// missing field: nothing matches; exists=false does
	assert(!has("body", "contains", "\"x\"") && !has("body", "exists", "true"));
	assert(detects(sig("t", leaf("body", "exists", "false")), ev) && detects(sig("t", leaf("title", "exists", "true")), ev) && detects(sig("t", "{\"field\":\"title\",\"op\":\"exists\"}"), ev));
	Evidence empty;
	empty.set("title", "");
	assert(!detects(sig("t", "{\"field\":\"title\",\"op\":\"exists\"}"), empty));          // present but empty is not "exists"
	assert(detects(sig("t", leaf("title", "exists", "false")), empty));
	// a field holding the wrong type of value never matches
	Evidence wrong;
	wrong.set("title", 5);
	assert(!detects(sig("t", leaf("title", "contains", "\"5\"")), wrong));
}

static void test_other_types() {
	Evidence ev;
	ev.set("status", 200);
	ev.set("favicon_hash", -1234567);
	ev.set("tls", true);
	ev.set("tls.expired", false);
	ev.set_list("cookie", {"PHPSESSID", "csrftoken"});
	ev.set_list("header:set-cookie", {"a=1", "b=2; HttpOnly"});
	ev.set_list("tls.san", {"intranet.acme.example", "*.acme.example"});
	auto d = [&](const std::string& match) { return detects(sig("t", match), ev); };

	// numbers
	assert(d(leaf("status", "equals", "200")) && d(leaf("status", "equals", "[301, 200]")) && !d(leaf("status", "equals", "404")));
	assert(d(leaf("status", "ge", "200")) && d(leaf("status", "gt", "199")) && !d(leaf("status", "gt", "200")) && d(leaf("status", "le", "200")) && d(leaf("status", "lt", "300")) && !d(leaf("status", "lt", "200")));
	assert(d(leaf("favicon_hash", "equals", "-1234567")) && d(leaf("favicon_hash", "equals", "[1, -1234567]")) && d(leaf("favicon_hash", "lt", "0")));
	// bool
	assert(d(leaf("tls", "equals", "true")) && !d(leaf("tls", "equals", "false")) && d(leaf("tls.expired", "equals", "false")) && !d(leaf("tls.self_signed", "equals", "true")));
	assert(!d(leaf("tls.self_signed", "equals", "false")));                                   // unknown is neither true nor false
	// lists: any element
	assert(d(leaf("cookie", "equals", "\"phpsessid\"")) && d(leaf("cookie", "prefix", "\"csrf\"")) && !d(leaf("cookie", "equals", "\"sessionid\"")));
	assert(d(leaf("cookie", "regex", "\"^(JSESSIONID|PHPSESSID)$\"")) && d(leaf("cookie", "exists", "true")) && !d(leaf("cookie_insecure", "exists", "true")));
	assert(d(leaf("header:set-cookie", "contains", "\"httponly\"")) && d(leaf("tls.san", "suffix", "\".acme.example\"")) && d(leaf("tls.san", "contains", "\"intranet\"")));
	Evidence none;
	none.set_list("cookie", {});
	assert(!detects(sig("t", leaf("cookie", "exists", "true")), none) && detects(sig("t", leaf("cookie", "exists", "false")), none));
}

static void test_boolean_structure() {
	Evidence ev;
	ev.set("title", "Login");
	ev.set("status", 200);
	auto d = [&](const std::string& match) { return detects(sig("t", match), ev); };
	const std::string yes = leaf("title", "contains", "\"login\""), no = leaf("title", "contains", "\"admin\""), ok = leaf("status", "equals", "200");

	assert(d("{\"all\":[" + yes + "," + ok + "]}") && !d("{\"all\":[" + yes + "," + no + "]}"));
	assert(d("{\"any\":[" + no + "," + yes + "]}") && !d("{\"any\":[" + no + "," + leaf("status", "equals", "500") + "]}"));
	assert(d("{\"not\":" + no + "}") && !d("{\"not\":" + yes + "}"));
	assert(d("{\"all\":[" + ok + ",{\"any\":[" + no + "," + yes + "]},{\"not\":" + leaf("title", "contains", "\"error\"") + "}]}"));
	// "not" of a leaf on a missing field is true
	assert(d("{\"not\":" + leaf("body", "contains", "\"x\"") + "}"));
}

static void test_confidence_and_threshold() {
	SignatureSet set;
	assert(!load(set, R"J({"signatures":[{
	  "id":"multi","name":"Multi","category":"cms","threshold":0.8,
	  "signals":[
	    {"weight":0.5,"match":{"field":"title","op":"contains","value":"alpha"}},
	    {"weight":0.6,"match":{"field":"body","op":"contains","value":"beta"}},
	    {"weight":0.7,"match":{"field":"server","op":"contains","value":"gamma"}}]}]})J").has_errors());
	auto conf = [&](bool a, bool b, bool c) -> double {
		Evidence ev;
		if (a) ev.set("title", "alpha");
		if (b) ev.set("body", "beta");
		if (c) ev.set("server", "gamma");
		const auto r = evaluate(set, ev);
		return r.empty() ? -1 : r[0].confidence;
	};
	assert(conf(false, false, false) == -1);                                   // nothing matched
	assert(conf(true, false, false) == -1 && conf(false, true, false) == -1);  // 0.5 and 0.6 are below the 0.8 threshold
	assert(conf(false, false, true) == -1);                                    // 0.7 too
	assert(std::fabs(conf(true, true, false) - 0.8) < 1e-9);                   // 1 - 0.5*0.4 = 0.8: reaches it exactly
	assert(std::fabs(conf(false, true, true) - 0.88) < 1e-9);                  // 1 - 0.4*0.3
	assert(std::fabs(conf(true, true, true) - 0.94) < 1e-9);                   // 1 - 0.5*0.4*0.3: more evidence, more certainty
	assert(conf(true, true, true) > conf(false, true, true));

	// certainty is capped
	SignatureSet cap;
	load(cap, wrap("{\"id\":\"sure\",\"name\":\"S\",\"category\":\"cms\",\"signals\":[{\"weight\":1,\"match\":" + leaf("title", "contains", "\"abc\"") + "}]}"));
	Evidence e;
	e.set("title", "abc");
	assert(evaluate(cap, e)[0].confidence == 0.99);
}

static void test_required_exclude_version_and_evidence_lines() {
	SignatureSet set;
	assert(!load(set, R"J({"signatures":[{
	  "id":"app","name":"App","category":"framework","interest":3,"tags":["web"],
	  "signals":[
	    {"weight":0.4,"required":true,"label":"is HTTP","match":{"field":"status","op":"exists"}},
	    {"weight":0.9,"label":"banner","match":{"field":"header:x-powered-by","op":"regex","value":"App/([0-9.]+)"}}],
	  "exclude":{"field":"title","op":"contains","value":"honeypot"},
	  "version":{"field":"header:x-powered-by","regex":"App/([0-9.]+)"}}]})J").has_errors());

	Evidence ev;
	ev.set("status", 200);
	ev.set_list("header:x-powered-by", {"PHP/8.2", "App/3.1.4"});
	auto r = evaluate(set, ev);
	assert(r.size() == 1 && r[0].id == "app" && r[0].version == "3.1.4" && r[0].category == Category::Framework && r[0].interest == 3 && !r[0].builtin);
	assert(std::fabs(r[0].confidence - 0.94) < 1e-9 && r[0].tags == std::vector<std::string>{"web"});
	assert(r[0].evidence.size() == 2 && r[0].evidence[0].find("+0.4  is HTTP: status exists") == 0 && r[0].evidence[1].find("+0.9  banner: header:x-powered-by regex") == 0);
	assert(r[0].evidence[1].find("[App/3.1.4]") != std::string::npos);                   // shows what it actually saw

	Evidence no_status;
	no_status.set_list("header:x-powered-by", {"App/3.1.4"});
	assert(evaluate(set, no_status).empty());                                            // a required signal is missing
	Evidence trap = ev;
	trap.set("title", "Totally a HONEYPOT");
	assert(evaluate(set, trap).empty());                                                 // excluded
	Evidence odd = ev;
	odd.set_list("header:x-powered-by", {"App/1.0 <script>"});
	assert(evaluate(set, odd).size() == 1 && evaluate(set, odd)[0].version == "1.0");    // version capture is limited to its group
	SignatureSet strict;
	load(strict, wrap(R"J({"id":"v","name":"V","category":"other","signals":[{"weight":0.9,"match":{"field":"title","op":"exists"}}],"version":{"field":"title","regex":"(.*)"}})J"));
	Evidence junk;
	junk.set("title", "has spaces & <tags>");
	assert(evaluate(strict, junk)[0].version.empty());                                    // odd characters: no version rather than a dirty one
	Evidence longv;
	longv.set("title", std::string(100, '1'));
	assert(evaluate(strict, longv)[0].version.empty());                                   // and not an absurd one
	Evidence plain;
	plain.set("title", "7.4.33");
	assert(evaluate(strict, plain)[0].version == "7.4.33");
}

static void test_ordering_and_stats() {
	SignatureSet set;
	load(set, "{\"signatures\":[" +
		sig("zeta", leaf("title", "contains", "\"x\""), "\"interest\":1,") + "," + sig("alpha", leaf("title", "contains", "\"x\""), "\"interest\":1,") + "," +
		sig("keen", leaf("title", "contains", "\"x\""), "\"interest\":5,") + "," +
		"{\"id\":\"strong\",\"name\":\"s\",\"category\":\"other\",\"signals\":[{\"weight\":0.95,\"match\":" + leaf("title", "contains", "\"x\"") + "}]}," +
		sig("quiet", leaf("title", "contains", "\"nothing-matches-this\"")) + "]}");
	Evidence ev;
	ev.set("title", "x");
	EvalStats stats;
	const auto r = evaluate(set, ev, &stats);
	assert(stats.signatures_evaluated == 5 && stats.regex_limit_hits == 0);
	assert(r.size() == 4 && r[0].id == "strong");                                       // highest confidence first
	assert(r[1].id == "keen" && r[2].id == "alpha" && r[3].id == "zeta");                // then interest, then id
}

static void test_regex_limits_are_counted_not_fatal() {
	SignatureSet set;
	assert(!load(set, wrap("{\"id\":\"evil\",\"name\":\"E\",\"category\":\"other\",\"signals\":[{\"weight\":0.9,\"match\":" + leaf("body", "regex", "\"(a+)+$\"") + "}]}")).has_errors());
	load(set, wrap(sig("benign", leaf("title", "contains", "\"abc\""))));
	Evidence ev;
	ev.set("body", std::string(40, 'a') + "!");
	ev.set("title", "abc");
	EvalStats stats;
	const auto r = evaluate(set, ev, &stats);
	assert(stats.regex_limit_hits == 1 && r.size() == 1 && r[0].id == "benign");          // the runaway pattern gave up; the rest still ran
}

static void test_examples() {
	SignatureSet good;
	assert(!load(good, wrap(R"J({"id":"srv","name":"Srv","category":"server","signals":[{"weight":0.9,"match":{"field":"server","op":"regex","value":"srv/([0-9.]+)"}}],
	  "version":{"field":"server","regex":"srv/([0-9.]+)"},
	  "examples":[
	    {"name":"plain","evidence":{"server":"srv/1.2"},"expect":"match","version":"1.2"},
	    {"name":"other server","evidence":{"server":"apache"},"expect":"no-match"},
	    {"name":"default expect","evidence":{"server":"srv/9"}}]})J")).has_errors());
	assert(run_examples(good).empty());

	SignatureSet broken;
	load(broken, wrap(R"J({"id":"srv","name":"Srv","category":"server","signals":[{"weight":0.9,"match":{"field":"server","op":"contains","value":"srv"}}],
	  "examples":[
	    {"name":"should match","evidence":{"server":"apache"},"expect":"match"},
	    {"name":"should not","evidence":{"server":"srv 1"},"expect":"no-match"}]})J"));
	const auto failures = run_examples(broken);
	assert(failures.size() == 2 && failures[0].find("srv: example \"should match\": expected a detection") == 0 && failures[1].find("expected no detection") != std::string::npos);

	SignatureSet wrongver;
	load(wrongver, wrap(R"J({"id":"v","name":"V","category":"server","signals":[{"weight":0.9,"match":{"field":"server","op":"exists"}}],
	  "version":{"field":"server","regex":"v([0-9.]+)"},"examples":[{"name":"x","evidence":{"server":"v2.0"},"expect":"match","version":"3.0"}]})J"));
	assert(run_examples(wrongver).size() == 1 && run_examples(wrongver)[0].find("expected version \"3.0\", got \"2.0\"") != std::string::npos);

	// disabled signatures are not tested
	broken.set_enabled("srv", false);
	assert(run_examples(broken).empty());

	// examples are validated like everything else
	SignatureSet bad;
	LoadResult r = load(bad, wrap(R"J({"id":"b","name":"B","category":"other","signals":[{"weight":0.9,"match":{"field":"server","op":"exists"}}],
	  "examples":[{"name":"x","evidence":{"nosuchfield":"v"}},{"name":"y","evidence":{"status":"200"}},{"name":"z","evidence":{"server":"s"},"expect":"maybe"},{"name":"w"}]})J"));
	assert(has_error(r, "examples[0].evidence.nosuchfield") && has_error(r, "examples[1].evidence.status") && has_error(r, "must be \"match\" or \"no-match\"") && has_error(r, "examples[3].evidence"));
}

static void test_files_and_directories() {
	namespace fs = std::filesystem;
	const fs::path dir = fs::temp_directory_path() / ("proculus_sigs_" + std::to_string(::getpid()));
	fs::remove_all(dir);
	fs::create_directories(dir);
	auto write = [&](const std::string& name, const std::string& text) { std::ofstream(dir / name) << text; };
	write("b.json", wrap(sig("from-b", leaf("title", "contains", "\"abc\""))));
	write("a.json", wrap(sig("from-a", leaf("title", "contains", "\"abc\""))));
	write("broken.json", "{ not json");
	write("notes.txt", "ignored");
	fs::create_directories(dir / "sub.json");                                              // a directory named like a signature file

	SignatureSet set;
	const LoadResult r = set.add_directory(dir);
	assert(r.loaded == 2 && r.errors() == 1 && set.all()[0].id == "from-a" && set.all()[1].id == "from-b");   // name order, junk skipped
	assert(set.find("from-a")->source.find("a.json") != std::string::npos);

	SignatureSet missing;
	assert(has_error(missing.add_file(dir / "nope.json"), "cannot read the file") && has_error(missing.add_directory(dir / "nope"), "not a directory"));
	assert(has_error(missing.add_file(dir), "cannot read the file"));                       // a directory is not a file
	write("huge.json", std::string(5 << 20, ' '));
	assert(has_error(missing.add_file(dir / "huge.json"), "larger than 4 MiB"));
	fs::remove_all(dir);
}

int main() {
	test_field_catalog();
	test_evidence();
	test_loading_a_valid_signature();
	test_structure_errors();
	test_typos_are_caught_with_hints();
	test_signature_field_errors();
	test_leaf_errors();
	test_ids_overrides_and_disable();
	test_one_bad_signature_does_not_block_the_rest();
	test_probe_path_limits();
	test_required_paths_ordering();
	test_evidence_json();
	test_string_operators();
	test_other_types();
	test_boolean_structure();
	test_confidence_and_threshold();
	test_required_exclude_version_and_evidence_lines();
	test_ordering_and_stats();
	test_regex_limits_are_counted_not_fatal();
	test_examples();
	test_files_and_directories();
	return 0;
}
