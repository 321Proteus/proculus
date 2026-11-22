#undef NDEBUG
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "signature_store.hpp"

using namespace proculus;
namespace fs = std::filesystem;

static const char* kGood = R"({"format":1,"disable":["server-version-disclosure"],"signatures":[{"id":"my-portal","name":"My portal","category":"admin","interest":3,"threshold":0.5,
 "signals":[{"weight":0.8,"match":{"field":"title","op":"contains","value":"Portal"}}],
 "examples":[{"name":"match","evidence":{"title":"Portal login"}},{"name":"no match","evidence":{"title":"Blog"},"expect":"no-match"}]}]})";

static bool refused(SignatureStore& s, const std::string& text, const char* needle) {
	try {
		s.save(text);
	} catch (const ApiError& e) {
		return e.status == 400 && std::string(e.what()).find(needle) != std::string::npos;
	}
	return false;
}

static const Json* find(const Json& list, const std::string& id) {
	for (const Json& s : list["signatures"])
		if (s["id"] == id) return &s;
	return nullptr;
}

int main() {
	const fs::path dir = fs::temp_directory_path() / ("proculus_sigs_" + std::to_string(getpid()));
	fs::remove_all(dir);
	const fs::path file = dir / "custom-signatures.json";
	SignatureStore store(file);

	// the built-in signatures are listed, with their category, interest and source
	Json list = store.list();
	assert(list["signatures"].size() > 100 && list["text"] == "" && list["persistent"] == true);
	const Json* wp = find(list, "wordpress");
	assert(wp && (*wp)["builtin"] == true && (*wp)["category"] == "cms" && (*wp)["enabled"] == true && (*wp)["signals"].get<int>() > 1);
	assert(find(list, "my-portal") == nullptr);

	// checking does not save; a good document passes, a broken one says what is wrong
	assert(store.check(kGood)["ok"] == true && store.check(kGood)["loaded"] == 1 && !fs::exists(file));
	assert(store.check("")["ok"] == true && store.check("   \n")["loaded"] == 0);
	const Json bad = store.check("{ not json");
	assert(bad["ok"] == false && !bad["errors"].empty());
	assert(store.check(R"({"format":1,"signatures":[{"id":"BAD ID","name":"x","category":"cms","signals":[]}]})")["ok"] == false);
	// an example that does not hold is an error too: the signature does not do what its author says
	const Json ex = store.check(R"({"format":1,"signatures":[{"id":"liar","name":"Liar","category":"other","threshold":0.5,
	  "signals":[{"weight":0.8,"match":{"field":"title","op":"equals","value":"A"}}],"examples":[{"name":"wrong","evidence":{"title":"B"}}]}]})");
	assert(ex["ok"] == false && !ex["examples"].empty());

	// nothing broken is ever saved
	assert(refused(store, "{ not json", "not saved"));
	assert(!fs::exists(file));
	bool too_long = false;
	try { store.check(std::string(60 * 1024, ' ')); } catch (const ApiError& e) { too_long = e.status == 400; }
	assert(too_long);

	// saving: the file is written, the list shows the custom signature next to the built-in ones, "disable" switches a built-in off
	store.save(kGood);
	assert(fs::exists(file) && store.text() == kGood);
	assert((fs::status(file).permissions() & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none);
	list = store.list();
	const Json* mine = find(list, "my-portal");
	assert(mine && (*mine)["builtin"] == false && (*mine)["source"] == "custom" && (*mine)["category"] == "admin" && (*mine)["interest"] == 3);
	const Json* off = find(list, "server-version-disclosure");
	assert(off && (*off)["enabled"] == false && (*off)["builtin"] == true);
	assert(list["text"] == kGood && list["problems"].empty());

	// a broken file on disk (edited by hand) does not break the list: the problems are reported
	{ std::ofstream(file) << R"({"format":1,"signatures":[{"id":"BAD ID","name":"x","category":"cms","signals":[]}]})"; }
	list = store.list();
	assert(!list["problems"].empty() && list["signatures"].size() > 100);

	// empty text removes the custom signatures
	store.save("");
	assert(!fs::exists(file) && store.list()["text"] == "" && find(store.list(), "my-portal") == nullptr);

	// without a file nothing is kept, but checking works
	SignatureStore memory;
	assert(memory.check(kGood)["ok"] == true && memory.list()["persistent"] == false);
	fs::remove_all(dir);
	return 0;
}
