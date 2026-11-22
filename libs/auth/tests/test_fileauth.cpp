#undef NDEBUG
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include "backend_suite.hpp"
#include "proculus/auth/fileauth.hpp"

namespace fs = std::filesystem;

static fs::path scratch(const char* name) {
	fs::path d = fs::temp_directory_path() / ("proculus_fileauth_" + std::string(name) + "_" + std::to_string(getpid()));
	fs::remove_all(d);
	return d;
}

static std::string slurp(const fs::path& p) {
	std::ifstream f(p, std::ios::binary);
	std::stringstream s;
	s << f.rdbuf();
	return s.str();
}

static void test_files() {
	const fs::path dir = scratch("files");
	{
		FileAuthBackend a(dir);
		const auto admin = a.create_first_admin("root.admin", "correct horse battery");
		a.create_user("vera.viewer", "viewer password 1", "viewer");
		a.create_role("auditor", "Reads and exports", {"data.read", "export"});
		a.record(nullptr, "something", "entity", "detail", "10.0.0.7");
		(void)admin;
	}
	// the files are private, and hold no plain passwords
	struct stat st{};
	assert(::stat((dir / "users.json").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
	assert(::stat((dir / "audit.jsonl").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);
	assert(::stat(dir.c_str(), &st) == 0 && (st.st_mode & 0777) == 0700);
	const std::string text = slurp(dir / "users.json");
	assert(text.find("correct horse") == std::string::npos && text.find("viewer password") == std::string::npos && text.find("$argon2id$") != std::string::npos);

	// a new instance (a restart, or the command line) sees the same accounts and roles
	FileAuthBackend again(dir);
	assert(again.has_users() && again.users().size() == 2 && again.verify("vera.viewer", "viewer password 1"));
	bool custom = false;
	for (const auto& r : again.roles()) custom |= r.name == "auditor" && !r.builtin;
	assert(custom);
	assert(again.audit(10).size() == 1 && again.audit(10)[0].source_ip == "10.0.0.7");

	// and a change made through one instance shows up in the other at once
	FileAuthBackend other(dir);
	other.create_user("added.later", "added later password", "editor");
	assert(again.verify("added.later", "added later password"));
	assert(again.users().size() == 3);

	// no temporary files are left behind
	for (const auto& e : fs::directory_iterator(dir)) assert(e.path().filename().string().find(".tmp.") == std::string::npos);
	fs::remove_all(dir);
}

static void test_damage() {
	const fs::path dir = scratch("damage");
	{
		FileAuthBackend a(dir);
		a.create_first_admin("root.admin", "correct horse battery");
	}
	{
		std::ofstream(dir / "users.json") << "{ this is not json";
	}
	FileAuthBackend a(dir);
	bool threw = false;
	try {
		a.has_users();
	} catch (const std::runtime_error& e) {
		threw = std::string(e.what()).find("damaged") != std::string::npos;
	}
	assert(threw);
	// a damaged file is never overwritten with an "empty" one, whatever is asked
	threw = false;
	try {
		a.create_first_admin("attacker", "attacker password!");
	} catch (const std::runtime_error&) {
		threw = true;
	}
	assert(threw && slurp(dir / "users.json") == "{ this is not json");
	fs::remove_all(dir);
}

int main() {
	test_rules();
	{
		const fs::path dir = scratch("suite");
		FileAuthBackend a(dir);
		run_backend_suite(a);
		fs::remove_all(dir);
	}
	{
		const fs::path dir = scratch("setup");
		FileAuthBackend a(dir);
		run_setup_suite(a);
		fs::remove_all(dir);
	}
	{
		const fs::path dir = scratch("race");
		FileAuthBackend a(dir);
		run_setup_race(a);
		fs::remove_all(dir);
	}
	{ // the race also across separate instances (like server and command line)
		const fs::path dir = scratch("race2");
		std::atomic<int> won{0};
		std::vector<std::thread> threads;
		for (int i = 0; i < 6; i++)
			threads.emplace_back([&, i] {
				FileAuthBackend a(dir);
				try {
					a.create_first_admin("racer" + std::to_string(i), "racer password " + std::to_string(i));
					won++;
				} catch (const web::AuthError&) {
				}
			});
		for (auto& t : threads) t.join();
		assert(won == 1 && FileAuthBackend(dir).users().size() == 1);
		fs::remove_all(dir);
	}
	test_files();
	test_damage();
	return 0;
}
