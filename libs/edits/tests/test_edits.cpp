#undef NDEBUG
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <sstream>

#include "edit_store_suite.hpp"

namespace fs = std::filesystem;

static fs::path scratch(const char* name) {
	fs::path d = fs::temp_directory_path() / ("proculus_edits_" + std::string(name) + "_" + std::to_string(getpid()));
	fs::remove_all(d);
	return d;
}

static std::string slurp(const fs::path& p) {
	std::ifstream f(p, std::ios::binary);
	std::stringstream s;
	s << f.rdbuf();
	return s.str();
}

int main() {
	assert(valid_ip("10.0.0.1") && valid_ip("255.255.255.255") && valid_ip("0.0.0.0"));
	for (const char* bad : {"", "10.0.0", "10.0.0.1.1", "10.0.0.256", "10.0.0.", ".10.0.0", "a.b.c.d", "10.0.0.1/8", "1000.0.0.1", "10..0.1", " 10.0.0.1"}) assert(!valid_ip(bad));
	assert((EditKey{"10.0.0.1", 0, ""}).text() == "10.0.0.1" && (EditKey{"10.0.0.1", 80, "tcp"}).text() == "10.0.0.1:80/tcp");

	const fs::path dir = scratch("suite");
	{
		auto store = make_file_edit_store(dir);
		run_edit_store_suite(*store);
	}
	fs::remove_all(dir);

	// the file survives a restart, is private, and another instance sees changes at once
	const fs::path d2 = scratch("files");
	{
		auto a = make_file_edit_store(d2);
		a->apply(EditKey{"10.0.0.5", 0, ""}, json{{"note", "kept"}, {"tags", {"x"}}}, "ann");
	}
	auto b = make_file_edit_store(d2), c = make_file_edit_store(d2);
	assert(*b->get(EditKey{"10.0.0.5", 0, ""})->note == "kept");
	c->apply(EditKey{"10.0.0.5", 0, ""}, json{{"status", "ignored"}}, "bob");
	assert(*b->get(EditKey{"10.0.0.5", 0, ""})->status == "ignored" && *b->get(EditKey{"10.0.0.5", 0, ""})->note == "kept");
	struct stat st{};
	assert(::stat((d2 / "edits.json").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
	for (const auto& e : fs::directory_iterator(d2)) assert(e.path().filename().string().find(".tmp.") == std::string::npos);

	// a damaged file is reported, never overwritten
	{
		std::ofstream(d2 / "edits.json") << "{ not json";
	}
	bool threw = false;
	try {
		b->apply(EditKey{"10.0.0.6", 0, ""}, json{{"note", "x"}}, "ann");
	} catch (const std::runtime_error& e) {
		threw = std::string(e.what()).find("damaged") != std::string::npos;
	}
	assert(threw && slurp(d2 / "edits.json") == "{ not json");
	fs::remove_all(d2);
	return 0;
}
