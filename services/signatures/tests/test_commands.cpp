#undef NDEBUG
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "commands.hpp"

using namespace proculus;

struct Result {
	int rc;
	std::string out, err;
};

static Result run(std::vector<std::string> args, const std::string& input = "") {
	std::istringstream in(input);
	std::ostringstream out, err;
	const int rc = run_signatures_tool(args, in, out, err);
	return {rc, out.str(), err.str()};
}

static bool has(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }

static std::filesystem::path scratch() {
	auto d = std::filesystem::temp_directory_path() / ("proculus-sigcli-" + std::to_string(::getpid()));
	std::filesystem::create_directories(d);
	return d;
}

static std::string write(const std::filesystem::path& dir, const std::string& name, const std::string& text) {
	const auto p = dir / name;
	std::ofstream(p) << text;
	return p.string();
}

static const char* kGood = R"J({"signatures":[{"id":"my-app","name":"My App","category":"admin","interest":3,
 "signals":[{"weight":0.9,"match":{"field":"title","op":"contains","value":"My App Console"}}],
 "examples":[{"name":"hit","evidence":{"title":"My App Console"}},{"name":"miss","evidence":{"title":"Other"},"expect":"no-match"}]}]})J";

static void test_usage() {
	assert(run({}).rc == 2);
	assert(run({"frobnicate"}).rc == 2);
	assert(has(run({"frobnicate"}).err, "unknown command"));
	assert(run({"list", "--bogus"}).rc == 2);
	assert(run({"list", "--category"}).rc == 2);
	assert(run({"list", "--category", "nope"}).rc == 2);
	assert(run({"help"}).rc == 0);
}

static void test_list_show_fields_paths() {
	auto all = run({"list"});
	assert(all.rc == 0 && has(all.out, "wordpress") && has(all.out, "signatures\n"));
	auto cms = run({"list", "--category", "cms"});
	assert(has(cms.out, "wordpress") && !has(cms.out, "nginx"));
	auto js = run({"list", "--format", "json", "--category", "cms"});
	assert(js.rc == 0 && js.out.front() == '[' && has(js.out, "\"id\": \"wordpress\""));
	assert(run({"list", "--no-builtin"}).out == "0 of 0 signatures\n");

	auto show = run({"show", "wordpress"});
	assert(show.rc == 0 && has(show.out, "WordPress") && has(show.out, "built in"));
	assert(run({"show", "nope"}).rc == 2);
	assert(run({"show"}).rc == 2);

	auto fields = run({"fields"});
	assert(has(fields.out, "favicon_hash  number") && has(fields.out, "path:<p>:status"));

	auto paths = run({"paths", "--max", "3"});
	assert(paths.rc == 0 && std::count(paths.out.begin(), paths.out.end(), '\n') == 3);
	assert(run({"paths", "--max", "x"}).rc == 2);
}

static void test_lint() {
	const auto dir = scratch();
	const std::string good = write(dir, "good.json", kGood);
	auto r = run({"lint", good});
	assert(r.rc == 0 && has(r.out, "1 signature(s) loaded, 0 error(s)") && r.err.empty());

	// a failing example is an error
	std::string bad_example = kGood;
	bad_example.replace(bad_example.find("My App Console\"}}"), 14, "Something Else");
	r = run({"lint", write(dir, "badex.json", bad_example)});
	assert(r.rc == 1 && has(r.err, "my-app: example \"hit\"") && has(r.out, "1 failing example"));

	// no examples: only a warning
	const std::string noex = R"J({"signatures":[{"id":"x1","name":"X","category":"other","signals":[{"weight":0.9,"match":{"field":"title","op":"contains","value":"x"}}]}]})J";
	r = run({"lint", write(dir, "noex.json", noex)});
	assert(r.rc == 0 && has(r.err, "no examples"));

	// schema errors, with the location
	const std::string typo = R"J({"signatures":[{"id":"x2","name":"X","category":"other","signals":[{"weight":0.9,"match":{"field":"titel","op":"contains","value":"x"}}]}]})J";
	r = run({"lint", write(dir, "typo.json", typo)});
	assert(r.rc == 1 && has(r.err, "titel"));

	// clash with a built-in needs "override"
	std::string clash = kGood;
	clash.replace(clash.find("my-app"), 6, "wordpress");
	r = run({"lint", write(dir, "clash.json", clash)});
	assert(r.rc == 1 && has(r.err, "built-in"));

	r = run({"lint", write(dir, "junk.json", "{not json")});
	assert(r.rc == 1);
	r = run({"lint", (dir / "missing.json").string()});
	assert(r.rc == 1);
	assert(run({"lint"}).rc == 2);

	// a directory, with one good and one bad file
	const auto sub = dir / "set";
	std::filesystem::create_directories(sub);
	write(sub, "a.json", kGood);
	write(sub, "b.json", typo);
	assert(run({"lint", sub.string()}).rc == 1);
	std::filesystem::remove_all(dir);
}

static void test_test_and_match() {
	assert(run({"test"}).rc == 0);
	assert(has(run({"test"}).out, "0 failure(s)"));

	const auto dir = scratch();
	const std::string sigs = write(dir, "s.json", kGood);
	auto t = run({"test", "--signatures", sigs, "--no-builtin"});
	assert(t.rc == 0 && has(t.out, "1 signatures, 2 examples"));

	auto m = run({"match", "-", "--signatures", sigs}, R"({"title":"My App Console","header:server":"nginx/1.24.0"})");
	assert(m.rc == 0 && has(m.out, "My App") && has(m.out, "nginx"));
	auto mj = run({"match", "-", "--format", "json", "--no-builtin", "--signatures", sigs}, R"({"title":"My App Console"})");
	assert(mj.rc == 0 && has(mj.out, "\"my-app\""));
	assert(has(run({"match", "-", "--no-builtin"}, R"({"title":"x"})").out, "no detections"));
	assert(!has(run({"match", "-", "--no-builtin", "--signatures", sigs, "--min-confidence", "0.95"}, R"({"title":"My App Console"})").out, "My App"));

	// bad input is reported, not crashed on
	assert(run({"match", "-"}, "not json").rc == 2);
	assert(run({"match", "-"}, "[1,2]").rc == 2);
	auto unknown = run({"match", "-"}, R"({"nonsense":1})");
	assert(unknown.rc == 2 && has(unknown.err, "nonsense"));
	assert(run({"match", "-"}, R"({"status":"200"})").rc == 2); // wrong type
	assert(run({"match", (dir / "none.json").string()}).rc == 2);
	assert(run({"match"}).rc == 2);

	// custom signatures with errors stop the command instead of being half-used
	assert(run({"list", "--signatures", write(dir, "bad.json", "{")}).rc == 2);

	// control characters in names are refused by the loader, so they never reach the terminal
	std::string esc = kGood;
	esc.replace(esc.find("My App\""), 7, "Esc\\u001b[31m\"");
	auto l = run({"list", "--no-builtin", "--signatures", write(dir, "esc.json", esc)});
	assert(l.rc == 2 && has(l.err, "printable") && l.err.find('\x1b') == std::string::npos);
	std::filesystem::remove_all(dir);
}

int main() {
	test_usage();
	test_list_show_fields_paths();
	test_lint();
	test_test_and_match();
	return 0;
}
