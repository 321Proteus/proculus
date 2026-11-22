#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <fstream>

#include "reset_cli.hpp"

namespace fs = std::filesystem;
using namespace proculus;

int main() {
	const fs::path dir = fs::temp_directory_path() / ("proculus-reset-" + std::to_string(getpid()));
	fs::remove_all(dir);
	fs::create_directories(dir / "accounts");
	fs::create_directories(dir / "edits");
	fs::create_directories(dir / "other");
	for (const char* f : {"accounts/users.json", "edits/e.json", "scan-config.json", "run-000001.json", "run-000002.json", "notes.txt", "run-1.json", "other/run-000003.json"}) std::ofstream(dir / f) << "x";

	// without --runs the runs stay; unknown files are never touched
	assert(reset_targets(dir, false).size() == 3);
	assert(reset_store(dir, false) == 3);
	assert(!fs::exists(dir / "accounts") && !fs::exists(dir / "edits") && !fs::exists(dir / "scan-config.json"));
	assert(fs::exists(dir / "run-000001.json") && fs::exists(dir / "notes.txt"));
	assert(reset_store(dir, false) == 0);

	// with --runs only well-formed run files at the top level go
	assert(reset_store(dir, true) == 2);
	assert(!fs::exists(dir / "run-000001.json") && fs::exists(dir / "run-1.json") && fs::exists(dir / "notes.txt") && fs::exists(dir / "other/run-000003.json"));

	// a symbolic link is not followed
	fs::create_directories(dir / "elsewhere");
	std::ofstream(dir / "elsewhere/keep") << "x";
	fs::create_directory_symlink(dir / "elsewhere", dir / "accounts");
	assert(reset_targets(dir, false).empty() && fs::exists(dir / "elsewhere/keep"));

	// not a directory
	bool threw = false;
	try { reset_targets(dir / "missing", false); } catch (const std::invalid_argument&) { threw = true; }
	assert(threw);
	fs::remove_all(dir);
	return 0;
}
