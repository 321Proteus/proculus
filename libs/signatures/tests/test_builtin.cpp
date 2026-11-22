#undef NDEBUG
#include <cassert>
#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <set>

#include "proculus/sig/builtin.hpp"
#include "proculus/sig/engine.hpp"

using namespace proculus::sig;

static double seconds_of(const std::function<void()>& f) {
	const auto t0 = std::chrono::steady_clock::now();
	f();
	return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

static std::set<std::string> ids_of(const std::vector<Detection>& d) {
	std::set<std::string> out;
	for (const Detection& x : d) out.insert(x.id);
	return out;
}

// Compares the detections with the expected ids, printing both when they differ.
static bool exactly(const std::vector<Detection>& d, const std::set<std::string>& want, const char* what) {
	const auto got = ids_of(d);
	if (got == want) return true;
	std::cerr << what << ": expected {";
	for (const auto& w : want) std::cerr << " " << w;
	std::cerr << " } but got {";
	for (const Detection& x : d) {
		std::cerr << " " << x.id << "(" << x.confidence << ")";
		for (const auto& e : x.evidence) std::cerr << "\n      " << e;
	}
	std::cerr << " }\n";
	return false;
}

static int max_interest(const std::vector<Detection>& d) {
	int m = 0;
	for (const Detection& x : d) m = std::max(m, x.interest);
	return m;
}

static void test_the_set_itself() {
	const SignatureSet set = builtin_signatures(); // throws if any embedded file is invalid
	assert(set.size() >= 100 && set.enabled_count() == set.size());

	std::map<Category, int> per_category;
	std::set<std::string> ids;
	for (const Signature& s : set.all()) {
		assert(s.builtin && s.enabled && s.source.rfind("builtin:", 0) == 0);
		assert(ids.insert(s.id).second);
		assert(!s.name.empty() && !s.signals.empty());
		per_category[s.category]++;
		// every signature carries its own proof that it works, and that it does not match everything
		assert(!s.examples.empty());
		assert(std::any_of(s.examples.begin(), s.examples.end(), [](const Example& e) { return e.expect_match; }));
	}
	for (Category c : {Category::Cms, Category::Framework, Category::Server, Category::Iot, Category::Staging, Category::Admin, Category::Other})
		assert(per_category[c] >= 5);

	// the examples all pass
	const auto failures = run_examples(set);
	for (const std::string& f : failures) std::cerr << f << "\n";
	assert(failures.empty());

	// extra requests are bounded: a dozen distinct paths for the whole built-in set
	const auto paths = set.required_paths();
	assert(!paths.empty() && paths.size() <= 15);
	for (const std::string& p : paths) assert(valid_probe_path(p));
	std::cout << set.size() << " built-in signatures, " << paths.size() << " probe paths\n";
}

static void test_ordinary_sites_are_not_flagged() {
	const SignatureSet set = builtin_signatures();

	// a plain static site mentioning the words that signatures look for
	Evidence blog;
	blog.set("status", 200);
	blog.set("port", 443);
	blog.set("host", "www.example.org");
	blog.set("tls", true);
	blog.set("tls.version", "TLSv1.3");
	blog.set("tls.self_signed", false);
	blog.set("tls.expired", false);
	blog.set("tls.key_type", "EC");
	blog.set("tls.key_bits", 256);
	blog.set("tls.signature_algorithm", "ecdsa-with-SHA256");
	blog.set("title", "Engineering blog - how we run staging and the admin console");
	blog.set("body", "<html><body><h1>Our staging process</h1><p>The admin team reviews every test environment. Log in to the wiki to read more.</p><a href='/login'>Login</a></body></html>");
	blog.set_list("header:server", {"nginx"});
	blog.set_list("header_names", {"server", "content-type", "date"});
	auto d = evaluate(set, blog);
	assert(exactly(d, {"nginx"}, "static blog"));                                           // and nothing else

	// an Express app with a session cookie
	Evidence app;
	app.set("status", 200);
	app.set("title", "Todo list");
	app.set("body", "<div id=root></div><script src=/static/app.js></script>");
	app.set_list("header:x-powered-by", {"Express"});
	app.set_list("header_names", {"x-powered-by", "content-type"});
	app.set_list("cookie", {"connect.sid"});
	d = evaluate(set, app);
	assert(exactly(d, {"express", "tech-disclosing-headers"}, "express app"));
	assert(max_interest(d) <= 1);

	// Apache + PHP site
	Evidence php;
	php.set("status", 200);
	php.set("title", "Acme Corp");
	php.set("body", "<html><body>Welcome to Acme</body></html>");
	php.set_list("header:server", {"Apache/2.4.58 (Ubuntu)"});
	php.set_list("header:x-powered-by", {"PHP/8.2.12"});
	php.set_list("header_names", {"server", "x-powered-by"});
	php.set_list("cookie", {"PHPSESSID"});
	d = evaluate(set, php);
	assert(exactly(d, {"apache-httpd", "php", "server-version-disclosure", "tech-disclosing-headers"}, "apache+php"));
	assert(max_interest(d) <= 1);
	for (const Detection& x : d)
		if (x.id == "php") assert(x.version == "8.2.12");

	// a single-page app that answers every path with 200 and the same page: no "protected /admin", no exposures
	Evidence spa = app;
	spa.set("path:/admin:status", 200);
	spa.set("path:/admin:body", "<div id=root></div>");
	spa.set("path:/.git/HEAD:status", 200);
	spa.set("path:/.git/HEAD:body", "<div id=root></div>");
	spa.set("path:/phpinfo.php:status", 200);
	spa.set("path:/phpinfo.php:body", "<div id=root></div>");
	spa.set("path:/server-status:status", 200);
	spa.set("path:/server-status:body", "<div id=root></div>");
	spa.set("path:/actuator:status", 200);
	spa.set("path:/actuator:body", "<div id=root></div>");
	spa.set("path:/phpmyadmin/:status", 200);
	spa.set("path:/phpmyadmin/:title", "Todo list");
	d = evaluate(set, spa);
	assert(exactly(d, {"express", "tech-disclosing-headers"}, "single page app"));  // the soft-404 paths did not create findings
	assert(max_interest(d) <= 1);

	// a normal HTTPS site: nothing about its certificate or cookies is remarkable
	Evidence tls = blog;
	tls.set_list("cookie", {"lang", "_ga"});
	tls.set_list("cookie_insecure", {"lang"});
	tls.set_list("cookie_no_httponly", {"lang", "_ga"});
	assert(exactly(evaluate(set, tls), {"nginx"}, "https site"));
}

static void test_things_that_should_stand_out() {
	const SignatureSet set = builtin_signatures();

	// an exposed development setup: dev name, debug page, old TLS, self-signed
	Evidence ev;
	ev.set("status", 500);
	ev.set("host", "staging-api.example.org");
	ev.set("title", "DisallowedHost at /");
	ev.set("body", "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>");
	ev.set("tls", true);
	ev.set("tls.version", "TLSv1");
	ev.set("tls.self_signed", true);
	ev.set_list("header:server", {"gunicorn/21.2.0"});
	ev.set_list("cookie", {"csrftoken"});
	const auto d = evaluate(set, ev);
	const auto ids = ids_of(d);
	for (const char* want : {"staging-host-name", "debug-django", "tls-old-protocol", "tls-self-signed", "gunicorn", "django"}) assert(ids.count(want));
	assert(max_interest(d) == 5 && d[0].confidence >= d.back().confidence);

	// corroboration: three independent WordPress signals give more certainty than one
	Evidence one;
	one.set("body", "<link href=\"/wp-content/themes/x/style.css\">");
	Evidence three = one;
	three.set("body", "<meta name=\"generator\" content=\"WordPress 6.4.2\"><link href=\"/wp-content/themes/x/style.css\">");
	three.set_list("cookie", {"wordpress_test_cookie"});
	three.set("path:/wp-login.php:status", 200);
	three.set("path:/wp-login.php:body", "<input id=\"wp-submit\">");
	double c1 = 0, c3 = 0;
	std::string v3;
	for (const Detection& x : evaluate(set, one)) if (x.id == "wordpress") c1 = x.confidence;
	for (const Detection& x : evaluate(set, three)) if (x.id == "wordpress") { c3 = x.confidence; v3 = x.version; }
	assert(c1 > 0.5 && c1 < 0.8 && c3 > 0.98 && v3 == "6.4.2");
}

static void test_cost_is_bounded() {
	const SignatureSet set = builtin_signatures();

	// a realistic big page: every signature, 120 KB of HTML
	std::string page = "<html><head><title>Big page</title></head><body>";
	while (page.size() < 120000) page += "<div class=\"row\"><a href=\"/item/12345\">Item name and description text</a><input type=\"text\" name=\"q\"></div>\n";
	Evidence big;
	big.set("status", 200);
	big.set("title", "Big page");
	big.set("body", page);
	big.set_list("header:server", {"nginx/1.24.0"});
	const double normal = seconds_of([&] {
		for (int i = 0; i < 10; i++) evaluate(set, big);
	}) / 10;
	std::cout << "one page against " << set.size() << " signatures: " << normal * 1000 << " ms\n";
	assert(normal < 0.25);                                          // thousands of pages per minute per core

	// hostile bodies designed to hurt: each must finish quickly
	const std::vector<std::pair<const char*, std::string>> hostile = {
		{"one long run", std::string(1000000, 'a')},
		{"unclosed inputs", [] { std::string s; for (int i = 0; i < 20000; i++) s += "<input type="; return s; }()},
		{"unclosed meta tags", [] { std::string s; for (int i = 0; i < 20000; i++) s += "<meta name=\"generator\" content=\""; return s; }()},
		{"error-message lookalikes", [] { std::string s; for (int i = 0; i < 20000; i++) s += "Warning: "; return s; }()},
		{"repeated stack frames", [] { std::string s; for (int i = 0; i < 20000; i++) s += "at com.a.B.c("; return s; }()},
	};
	for (const auto& [name, body] : hostile) {
		Evidence ev;
		ev.set("status", 200);
		ev.set("title", std::string(5000, 'x'));
		ev.set("body", body);
		EvalStats stats;
		const double t = seconds_of([&] { evaluate(set, ev, &stats); });
		std::cout << "hostile body '" << name << "': " << t * 1000 << " ms, regex limit hits " << stats.regex_limit_hits << "\n";
		assert(t < 2.0);
	}
}

int main() {
	test_the_set_itself();
	test_ordinary_sites_are_not_flagged();
	test_things_that_should_stand_out();
	test_cost_is_bounded();
	return 0;
}
