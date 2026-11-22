// Checks every EditStore must pass, whatever it keeps edits in.
#ifndef PROCULUS_EDIT_STORE_SUITE_HPP
#define PROCULUS_EDIT_STORE_SUITE_HPP
#undef NDEBUG
#include <cassert>
#include <thread>

#include "proculus/edits/edits.hpp"

using namespace proculus;
using nlohmann::json;

template <class F>
inline bool edit_refused(F f, const char* needle = "") {
	try {
		f();
	} catch (const EditError& e) {
		return e.status == 400 && std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

inline void run_edit_store_suite(EditStore& s) {
	const EditKey host{"10.0.0.5", 0, ""};
	const EditKey svc{"10.0.0.5", 443, "tcp"};
	assert(s.all().empty() && !s.get(host));
	assert(!s.clear(host));

	// a host edit, with every field
	auto r = s.apply(host, json::parse(R"({"hostname":"db-1.corp","environment":"staging","status":"confirmed","note":"owned by Team A\nsee ticket 42","priority":80,"tags":["Finance","db"]})"), "ann");
	assert(r.before.empty() && !r.after.empty() && r.after.edited_by == "ann" && r.after.edited_at.size() == 20);
	auto got = *s.get(host);
	assert(*got.hostname == "db-1.corp" && *got.environment == "staging" && *got.status == "confirmed" && *got.priority == 80);
	assert(*got.note == "owned by Team A\nsee ticket 42" && (got.tags == std::vector<std::string>{"finance", "db"}));

	// changes merge: only the named fields change, null removes a field
	r = s.apply(host, json::parse(R"({"note":"owned by Team B","priority":null})"), "bob");
	assert(*r.before.note == "owned by Team A\nsee ticket 42" && *r.after.note == "owned by Team B" && !r.after.priority && *r.after.hostname == "db-1.corp" && r.after.edited_by == "bob");
	assert(!s.get(host)->priority && *s.get(host)->hostname == "db-1.corp");

	// a service edit is separate from its host's
	s.apply(svc, json::parse(R"({"status":"false_positive","tags":["noisy"]})"), "ann");
	assert(*s.get(svc)->status == "false_positive" && *s.get(host)->status == "confirmed" && s.all().size() == 2);

	// removing every field removes the edit
	r = s.apply(svc, json::parse(R"({"status":"","tags":[]})"), "ann");
	assert(r.after.empty() && !s.get(svc) && s.all().size() == 1);
	assert(s.clear(host) && s.all().empty() && !s.clear(host));

	// bad edits are refused whole, and change nothing
	s.apply(host, json::parse(R"({"note":"keep me"})"), "ann");
	for (const char* bad : {R"([])", R"("x")", R"({"nope":1})", R"({"environment":"production"})", R"({"status":"maybe"})", R"({"priority":101})", R"({"priority":-1})", R"({"priority":"high"})",
	                         R"({"priority":1.5})", R"({"hostname":5})", R"({"note":5})", R"({"tags":"a"})", R"({"tags":["has space"]})", R"({"tags":[1]})", R"({"hostname":"a\u0007b"})"})
		assert(edit_refused([&] { s.apply(host, json::parse(bad), "ann"); }));
	assert(edit_refused([&] { s.apply(host, json::parse(R"({"note":"changed","status":"nope"})"), "ann"); })); // the valid note is not applied either
	assert(*s.get(host)->note == "keep me");
	assert(edit_refused([&] { s.apply(svc, json::parse(R"({"hostname":"x"})"), "ann"); }, "applies to a host"));
	assert(edit_refused([&] { s.apply(svc, json::parse(R"({"environment":"prod"})"), "ann"); }, "applies to a host"));
	assert(edit_refused([&] { s.apply(EditKey{"not.an.ip", 0, ""}, json::parse(R"({"note":"x"})"), "ann"); }, "not an IPv4"));
	assert(edit_refused([&] { s.apply(EditKey{"10.0.0.999", 0, ""}, json::parse(R"({"note":"x"})"), "ann"); }, "not an IPv4"));
	assert(edit_refused([&] { s.apply(EditKey{"10.0.0.5", 80, ""}, json::parse(R"({"note":"x"})"), "ann"); }, "protocol"));
	assert(edit_refused([&] { s.apply(host, json::parse(std::string("{\"note\":\"") + std::string(2001, 'x') + "\"}"), "ann"); }, "2000"));
	std::string many = R"({"tags":[)";
	for (int i = 0; i < 11; i++) many += (i ? ",\"t" : "\"t") + std::to_string(i) + "\"";
	assert(edit_refused([&] { s.apply(host, json::parse(many + "]}"), "ann"); }, "at most 10"));
	assert(s.all().size() == 1);

	// text that looks like markup or SQL is just text
	s.apply(host, json::parse(R"({"note":"<script>alert(1)</script> '; DROP TABLE edits;--","hostname":"a<b>.example"})"), "ann");
	assert(*s.get(host)->note == "<script>alert(1)</script> '; DROP TABLE edits;--" && s.all().size() == 1);

	// concurrent edits of different fields do not lose each other
	s.clear(host);
	std::vector<std::thread> threads;
	for (int i = 0; i < 8; i++)
		threads.emplace_back([&, i] {
			EditKey k{"10.0.1." + std::to_string(i + 1), 0, ""};
			for (int n = 0; n < 5; n++) s.apply(k, json{{"note", "n" + std::to_string(n)}}, "t");
		});
	for (auto& t : threads) t.join();
	assert(s.all().size() == 8);
	for (int i = 0; i < 8; i++) assert(*s.get(EditKey{"10.0.1." + std::to_string(i + 1), 0, ""})->note == "n4");
}

#endif
