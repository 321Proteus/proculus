#include "proculus/auth/fileauth.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>

#include "proculus/auth/pgauth.hpp" // check_username / check_password
#include "proculus/db/crypto.hpp"

namespace proculus::auth {

namespace {

using web::AuthError;
using Json = nlohmann::ordered_json;

struct Role {
	std::string name, description;
	std::vector<std::string> permissions;
	bool builtin = false;
};

struct Account {
	int64_t id = 0;
	std::string username, hash, role;
	bool disabled = false;
	std::string last_login;
};

struct State {
	int64_t next_id = 1;
	std::vector<Account> users;
	std::vector<Role> custom_roles;
};

// The same four roles as db/migrations/0001_init.sql.
std::vector<Role> builtin_roles() {
	return {{"admin", "Administration: everything, including users and configuration", web::all_permissions(), true},
		{"manager", "Add, delete and modify data; run scans", {"data.read", "data.edit", "data.create", "data.delete", "export", "scan.run"}, true},
		{"editor", "Modify and read existing data", {"data.read", "data.edit", "export"}, true},
		{"viewer", "Read only", {"data.read", "export"}, true}};
}

std::string now_text() {
	const std::time_t t = std::time(nullptr);
	std::tm tm{};
	gmtime_r(&t, &tm);
	char buf[32];
	std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
	return buf;
}

std::string lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

std::string clean_text(const std::string& s, size_t max) {
	std::string out;
	for (unsigned char c : s) {
		if (out.size() >= max) break;
		if (c >= 0x20 && c != 0x7f) out.push_back(static_cast<char>(c));
	}
	return out;
}

bool valid_role_name(const std::string& n) {
	if (n.size() < 2 || n.size() > 32) return false;
	return std::all_of(n.begin(), n.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '_' || c == '.'; });
}

bool ip_chars(const std::string& s) {
	return !s.empty() && s.size() <= 45 && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) || c == '.' || c == ':'; });
}

// Holds an exclusive lock on the directory's lock file (other processes included).
class FileLock {
public:
	explicit FileLock(const std::filesystem::path& dir) {
		fd_ = ::open((dir / ".lock").c_str(), O_CREAT | O_RDWR, 0600);
		if (fd_ < 0 || ::flock(fd_, LOCK_EX) != 0) {
			if (fd_ >= 0) ::close(fd_);
			throw std::runtime_error("cannot lock the accounts directory");
		}
	}
	~FileLock() {
		::flock(fd_, LOCK_UN);
		::close(fd_);
	}
	FileLock(const FileLock&) = delete;
	FileLock& operator=(const FileLock&) = delete;

private:
	int fd_;
};

State read_state(const std::filesystem::path& dir) {
	State s;
	std::ifstream f(dir / "users.json");
	if (!f) return s; // no file yet: no accounts
	std::stringstream text;
	text << f.rdbuf();
	const Json j = Json::parse(text.str(), nullptr, false);
	if (j.is_discarded() || !j.is_object()) throw std::runtime_error("users.json is damaged; fix or remove it (it is never overwritten automatically)");
	try {
		s.next_id = j.value("next_id", int64_t{1});
		for (const Json& u : j.value("users", Json::array())) {
			Account a;
			a.id = u.at("id").get<int64_t>();
			a.username = u.at("username").get<std::string>();
			a.hash = u.at("password_hash").get<std::string>();
			a.role = u.at("role").get<std::string>();
			a.disabled = u.value("disabled", false);
			a.last_login = u.value("last_login", std::string());
			s.users.push_back(std::move(a));
		}
		for (const Json& r : j.value("roles", Json::array())) {
			Role role;
			role.name = r.at("name").get<std::string>();
			role.description = r.value("description", std::string());
			role.permissions = r.at("permissions").get<std::vector<std::string>>();
			s.custom_roles.push_back(std::move(role));
		}
	} catch (const Json::exception&) {
		throw std::runtime_error("users.json is damaged; fix or remove it (it is never overwritten automatically)");
	}
	return s;
}

void write_state(const std::filesystem::path& dir, const State& s) {
	Json j = {{"format", 1}, {"next_id", s.next_id}, {"users", Json::array()}, {"roles", Json::array()}};
	for (const Account& a : s.users)
		j["users"].push_back({{"id", a.id}, {"username", a.username}, {"password_hash", a.hash}, {"role", a.role}, {"disabled", a.disabled}, {"last_login", a.last_login}});
	for (const Role& r : s.custom_roles) j["roles"].push_back({{"name", r.name}, {"description", r.description}, {"permissions", r.permissions}});
	const std::string text = j.dump(2) + "\n";

	const auto tmp = dir / ("users.json.tmp." + std::to_string(::getpid()));
	const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) throw std::runtime_error("cannot write the accounts file");
	size_t done = 0;
	while (done < text.size()) {
		const ssize_t n = ::write(fd, text.data() + done, text.size() - done);
		if (n <= 0) {
			::close(fd);
			::unlink(tmp.c_str());
			throw std::runtime_error("cannot write the accounts file");
		}
		done += static_cast<size_t>(n);
	}
	::fsync(fd);
	::close(fd);
	std::error_code ec;
	std::filesystem::rename(tmp, dir / "users.json", ec);
	if (ec) {
		::unlink(tmp.c_str());
		throw std::runtime_error("cannot replace the accounts file");
	}
}

std::vector<Role> all_roles(const State& s) {
	std::vector<Role> r = builtin_roles();
	r.insert(r.end(), s.custom_roles.begin(), s.custom_roles.end());
	return r;
}

const Role* find_role(const std::vector<Role>& roles, const std::string& name) {
	for (const Role& r : roles)
		if (r.name == name) return &r;
	return nullptr;
}

Account* find_user(State& s, const std::string& username) {
	const std::string key = lower(username);
	for (Account& a : s.users)
		if (lower(a.username) == key) return &a;
	return nullptr;
}

size_t administrators(const State& s) {
	const auto roles = all_roles(s);
	size_t n = 0;
	for (const Account& a : s.users) {
		const Role* r = find_role(roles, a.role);
		if (!a.disabled && r && std::find(r->permissions.begin(), r->permissions.end(), "users.manage") != r->permissions.end()) n++;
	}
	return n;
}

web::UserInfo info_of(const Account& a) { return {a.id, a.username, a.role, a.disabled, a.last_login}; }

} // namespace

FileAuthBackend::FileAuthBackend(std::filesystem::path dir) : dir_(std::move(dir)), dummy_hash_(db::hash_password("a password nobody has, for timing")) {
	std::error_code ec;
	std::filesystem::create_directories(dir_, ec);
	if (ec || !std::filesystem::is_directory(dir_)) throw std::runtime_error("cannot use the accounts directory " + dir_.string());
	::chmod(dir_.c_str(), 0700);
}

std::optional<web::AuthUser> FileAuthBackend::verify(const std::string& username, const std::string& password) {
	State s;
	{
		std::lock_guard<std::mutex> l(m_);
		s = read_state(dir_); // reads are safe without the file lock: writes replace the file atomically
	}
	Account* a = find_user(s, clean_text(username, 64));
	const bool ok = db::verify_password(a ? a->hash : dummy_hash_, password) && a && !a->disabled;
	if (!ok) return std::nullopt;

	const auto roles = all_roles(s);
	const Role* role = find_role(roles, a->role);
	web::AuthUser u;
	u.id = a->id;
	u.username = a->username;
	u.role = a->role;
	if (role) u.permissions = role->permissions;
	try { // remember the login; a failure here must not stop the login
		std::lock_guard<std::mutex> l(m_);
		FileLock lock(dir_);
		State fresh = read_state(dir_);
		for (Account& x : fresh.users)
			if (x.id == u.id) x.last_login = now_text();
		write_state(dir_, fresh);
	} catch (const std::exception&) {
	}
	return u;
}

bool FileAuthBackend::has_users() {
	std::lock_guard<std::mutex> l(m_);
	return !read_state(dir_).users.empty();
}

web::UserInfo FileAuthBackend::create_first_admin(const std::string& username, const std::string& password) {
	if (auto why = check_username(username); !why.empty()) throw AuthError(400, why);
	if (auto why = check_password(username, password); !why.empty()) throw AuthError(400, why);
	std::lock_guard<std::mutex> l(m_);
	FileLock lock(dir_);
	State s = read_state(dir_);
	if (!s.users.empty()) throw AuthError(409, "the system is already set up");
	Account a{s.next_id++, username, db::hash_password(password), "admin", false, ""};
	s.users.push_back(a);
	write_state(dir_, s);
	return info_of(a);
}

std::vector<web::UserInfo> FileAuthBackend::users() {
	std::lock_guard<std::mutex> l(m_);
	State s = read_state(dir_);
	std::sort(s.users.begin(), s.users.end(), [](const Account& a, const Account& b) { return lower(a.username) < lower(b.username); });
	std::vector<web::UserInfo> out;
	for (const Account& a : s.users) out.push_back(info_of(a));
	return out;
}

std::vector<web::RoleInfo> FileAuthBackend::roles() {
	std::lock_guard<std::mutex> l(m_);
	const State s = read_state(dir_);
	std::vector<web::RoleInfo> out;
	for (const Role& r : all_roles(s)) {
		size_t n = static_cast<size_t>(std::count_if(s.users.begin(), s.users.end(), [&](const Account& a) { return a.role == r.name; }));
		out.push_back({r.name, r.description, r.permissions, r.builtin, n});
	}
	return out;
}

web::UserInfo FileAuthBackend::create_user(const std::string& username, const std::string& password, const std::string& role) {
	if (auto why = check_username(username); !why.empty()) throw AuthError(400, why);
	if (auto why = check_password(username, password); !why.empty()) throw AuthError(400, why);
	std::lock_guard<std::mutex> l(m_);
	FileLock lock(dir_);
	State s = read_state(dir_);
	if (!find_role(all_roles(s), role)) throw AuthError(400, "no such role: " + clean_text(role, 40));
	if (find_user(s, username)) throw AuthError(409, "a user with that name already exists");
	Account a{s.next_id++, username, db::hash_password(password), role, false, ""};
	s.users.push_back(a);
	write_state(dir_, s);
	return info_of(a);
}

void FileAuthBackend::update_user(int64_t id, const std::optional<std::string>& role, const std::optional<bool>& disabled, const std::optional<std::string>& password) {
	std::lock_guard<std::mutex> l(m_);
	FileLock lock(dir_);
	State s = read_state(dir_);
	auto it = std::find_if(s.users.begin(), s.users.end(), [&](const Account& a) { return a.id == id; });
	if (it == s.users.end()) throw AuthError(404, "no such user");
	if (password) {
		if (auto why = check_password(it->username, *password); !why.empty()) throw AuthError(400, why);
		it->hash = db::hash_password(*password);
	}
	if (role) {
		if (!find_role(all_roles(s), *role)) throw AuthError(400, "no such role: " + clean_text(*role, 40));
		it->role = *role;
	}
	if (disabled) it->disabled = *disabled;
	if (administrators(s) == 0) throw AuthError(409, "that would leave no administrator"); // nothing is written
	write_state(dir_, s);
}

web::RoleInfo FileAuthBackend::create_role(const std::string& name, const std::string& description, const std::vector<std::string>& permissions) {
	if (!valid_role_name(name)) throw AuthError(400, "a role name has 2 to 32 characters: lowercase letters, digits, '.', '_' and '-'");
	if (permissions.empty()) throw AuthError(400, "a role needs at least one permission");
	for (const std::string& p : permissions)
		if (!web::is_permission(p)) throw AuthError(400, "unknown permission: " + clean_text(p, 40));
	std::vector<std::string> unique = permissions;
	std::sort(unique.begin(), unique.end());
	unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
	std::lock_guard<std::mutex> l(m_);
	FileLock lock(dir_);
	State s = read_state(dir_);
	if (find_role(all_roles(s), name)) throw AuthError(409, "a role with that name already exists");
	s.custom_roles.push_back({name, clean_text(description, 200), unique, false});
	write_state(dir_, s);
	return {name, clean_text(description, 200), unique, false, 0};
}

void FileAuthBackend::delete_role(const std::string& name) {
	std::lock_guard<std::mutex> l(m_);
	FileLock lock(dir_);
	State s = read_state(dir_);
	const auto roles = all_roles(s); // (find_role returns a pointer into it)
	const Role* role = find_role(roles, name);
	if (!role) throw AuthError(404, "no such role");
	if (role->builtin) throw AuthError(409, "built-in roles cannot be deleted");
	if (std::any_of(s.users.begin(), s.users.end(), [&](const Account& a) { return a.role == name; })) throw AuthError(409, "the role is in use: move its users to another role first");
	s.custom_roles.erase(std::remove_if(s.custom_roles.begin(), s.custom_roles.end(), [&](const Role& r) { return r.name == name; }), s.custom_roles.end());
	write_state(dir_, s);
}

std::vector<web::AuditEntry> FileAuthBackend::audit(size_t limit) {
	std::lock_guard<std::mutex> l(m_);
	std::ifstream f(dir_ / "audit.jsonl", std::ios::binary | std::ios::ate);
	std::vector<web::AuditEntry> all;
	if (!f) return all;
	const std::streamoff size = f.tellg(), cap = 4 << 20; // the last 4 MiB are enough for a recent-events view
	f.seekg(size > cap ? size - cap : 0);
	std::string line;
	if (size > cap) std::getline(f, line); // the first line may be cut
	int64_t n = 0;
	while (std::getline(f, line)) {
		const Json j = Json::parse(line, nullptr, false);
		if (j.is_discarded() || !j.is_object()) continue;
		web::AuditEntry e;
		e.id = ++n; // numbered as read: files carry no ids, so nothing can clash between processes
		e.at = j.value("at", std::string());
		e.user = j.value("user", std::string());
		e.action = j.value("action", std::string());
		e.entity = j.value("entity", std::string());
		e.detail = j.value("detail", std::string());
		e.source_ip = j.value("source_ip", std::string());
		all.push_back(std::move(e));
	}
	std::reverse(all.begin(), all.end()); // newest first
	if (all.size() > std::min<size_t>(limit, 1000)) all.resize(std::min<size_t>(limit, 1000));
	return all;
}

void FileAuthBackend::record(const web::AuthUser* user, const std::string& action, const std::string& entity, const std::string& detail, const std::string& source_ip) {
	try {
		const Json j = {{"at", now_text()}, {"user", user ? user->username : ""}, {"action", clean_text(action, 80)}, {"entity", clean_text(entity, 120)},
			{"detail", clean_text(detail, 500)}, {"source_ip", ip_chars(source_ip) ? source_ip : ""}};
		const std::string line = j.dump() + "\n";
		std::lock_guard<std::mutex> l(m_);
		FileLock lock(dir_);
		const int fd = ::open((dir_ / "audit.jsonl").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (fd < 0) return;
		const ssize_t ignored = ::write(fd, line.data(), line.size());
		(void)ignored;
		::close(fd);
	} catch (...) {
		// an audit failure must not break the action being recorded
	}
}

} // namespace proculus::auth
