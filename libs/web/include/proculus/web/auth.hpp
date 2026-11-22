#ifndef PROCULUS_WEB_AUTH_HPP
#define PROCULUS_WEB_AUTH_HPP

// What the gateway needs from "who may do what", without saying where users are
// kept: the users and roles themselves live behind AuthBackend (Postgres, see
// libs/auth), while sessions and the login throttle are plain in-memory
// objects here.
//
// Roles carry permissions (data.read, data.edit, data.create, data.delete,
// export, scan.run, config.manage, users.manage); a role is just a named set of
// them, so new roles need no code. The gateway checks a permission per route
// and denies by default.

#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace proculus::web {

const std::vector<std::string>& all_permissions();
bool is_permission(const std::string& name);

struct AuthUser {
	int64_t id = 0;
	std::string username, role;
	std::vector<std::string> permissions;
	bool has(const std::string& permission) const;
};

struct UserInfo {
	int64_t id = 0;
	std::string username, role;
	bool disabled = false;
	std::string last_login; // UTC ISO, "" if never
};

struct RoleInfo {
	std::string name, description;
	std::vector<std::string> permissions;
	bool builtin = false;
	size_t users = 0;
};

struct AuditEntry {
	int64_t id = 0;
	std::string at, user, action, entity, detail, source_ip;
};

// A refused operation: `status` is the HTTP status to answer with.
struct AuthError : std::runtime_error {
	AuthError(int status, const std::string& message) : std::runtime_error(message), status(status) {}
	int status;
};

class AuthBackend {
public:
	virtual ~AuthBackend() = default;

	// The user if the password is right and the account is enabled. A wrong
	// user and a wrong password must be indistinguishable, in answer and in time.
	virtual std::optional<AuthUser> verify(const std::string& username, const std::string& password) = 0;
	virtual bool has_users() = 0;

	virtual std::vector<UserInfo> users() = 0;
	virtual std::vector<RoleInfo> roles() = 0;
	// Throw AuthError (400 invalid, 404 unknown, 409 exists or would leave no administrator).
	virtual UserInfo create_user(const std::string& username, const std::string& password, const std::string& role) = 0;
	virtual void update_user(int64_t id, const std::optional<std::string>& role, const std::optional<bool>& disabled, const std::optional<std::string>& password) = 0;
	virtual RoleInfo create_role(const std::string& name, const std::string& description, const std::vector<std::string>& permissions) = 0;
	virtual void delete_role(const std::string& name) = 0;

	virtual std::vector<AuditEntry> audit(size_t limit) = 0;
	// Writes an audit entry; must not throw (a failing log must not break the action).
	virtual void record(const AuthUser* user, const std::string& action, const std::string& entity, const std::string& detail, const std::string& source_ip) = 0;
};

using Clock = std::function<std::chrono::steady_clock::time_point()>;

// Server-side sessions: an unguessable token maps to the user. They end after
// being idle too long or after a maximum age, on logout, and when the user is
// changed (so a demoted or disabled user loses access at once).
class SessionManager {
public:
	explicit SessionManager(Clock now = [] { return std::chrono::steady_clock::now(); }, std::chrono::seconds idle = std::chrono::hours(2),
		std::chrono::seconds max_age = std::chrono::hours(12), size_t max_sessions = 1000);

	std::string create(const AuthUser& user); // a new random token (64 hex characters)
	std::optional<AuthUser> find(const std::string& token); // also renews the idle timer
	void revoke(const std::string& token);
	void revoke_user(int64_t user_id);

private:
	struct Session {
		AuthUser user;
		std::chrono::steady_clock::time_point created, last_used;
	};
	void sweep(std::chrono::steady_clock::time_point now);
	Clock now_;
	std::chrono::seconds idle_, max_age_;
	size_t max_sessions_;
	std::mutex m_;
	std::map<std::string, Session> sessions_;
};

// Limits password guessing: too many failures for one user name (or too many
// failures overall) lock logins for a while. Locked answers are the same
// whether the name exists or not.
class LoginThrottle {
public:
	explicit LoginThrottle(Clock now = [] { return std::chrono::steady_clock::now(); }, int per_user = 5, int overall = 60, std::chrono::seconds window = std::chrono::seconds(300),
		std::chrono::seconds lockout = std::chrono::seconds(300));
	bool allowed(const std::string& username);
	void failed(const std::string& username);
	void succeeded(const std::string& username);

private:
	struct Count {
		int failures = 0;
		std::chrono::steady_clock::time_point first, locked_until;
	};
	bool locked(Count& c, int limit, std::chrono::steady_clock::time_point now);
	void add(Count& c, int limit, std::chrono::steady_clock::time_point now);
	Clock now_;
	int per_user_, overall_;
	std::chrono::seconds window_, lockout_;
	std::mutex m_;
	std::map<std::string, Count> users_;
	Count all_;
};

// A random token of `bytes` bytes as hex, from the system's random source.
std::string random_hex(size_t bytes);

} // namespace proculus::web

#endif // PROCULUS_WEB_AUTH_HPP
