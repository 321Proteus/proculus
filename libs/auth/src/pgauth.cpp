#include "proculus/auth/pgauth.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>

#include "proculus/db/connection.hpp"
#include "proculus/db/crypto.hpp"
#include "proculus/db/migrate.hpp"

namespace proculus::auth {

namespace {

using web::AuthError;

constexpr const char* kTs = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

// "{a,b,c}" -> {"a","b","c"} (permission names never need quoting)
std::vector<std::string> parse_array(const std::string& text) {
	std::vector<std::string> out;
	if (text.size() < 2) return out;
	std::string inner = text.substr(1, text.size() - 2), cur;
	for (char ch : inner) {
		if (ch == ',') {
			if (!cur.empty()) out.push_back(cur);
			cur.clear();
		} else if (ch != '"') {
			cur.push_back(ch);
		}
	}
	if (!cur.empty()) out.push_back(cur);
	return out;
}

std::string array_text(const std::vector<std::string>& v) {
	std::string out = "{";
	for (size_t i = 0; i < v.size(); i++) out += (i ? "," : "") + v[i];
	return out + "}";
}

bool valid_role_name(const std::string& n) {
	if (n.size() < 2 || n.size() > 32) return false;
	return std::all_of(n.begin(), n.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '_' || c == '.'; });
}

std::string clean_text(const std::string& s, size_t max) {
	std::string out;
	for (unsigned char c : s) {
		if (out.size() >= max) break;
		if (c >= 0x20 && c != 0x7f) out.push_back(static_cast<char>(c)); // no control characters, NUL included
	}
	return out;
}

// Enabled users whose role has users.manage: there must always be at least one.
int64_t administrators(db::Connection& c) {
	return c.exec("SELECT count(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE NOT u.disabled AND 'users.manage' = ANY (r.permissions)").integer(0, 0);
}

} // namespace

std::string check_username(const std::string& u) {
	if (u.size() < 3 || u.size() > 64) return "the user name must have 3 to 64 characters";
	if (!std::all_of(u.begin(), u.end(), [](unsigned char c) { return std::isalnum(c) || c == '.' || c == '_' || c == '-'; })) return "the user name may only have letters, digits, '.', '_' and '-'";
	return "";
}

std::string check_password(const std::string& username, const std::string& p) {
	if (p.size() < 10) return "the password must have at least 10 characters";
	if (p.size() > 200) return "the password is too long";
	std::string a = p, b = username;
	std::transform(a.begin(), a.end(), a.begin(), ::tolower);
	std::transform(b.begin(), b.end(), b.begin(), ::tolower);
	if (a == b) return "the password must not be the user name";
	if (p.find('\0') != std::string::npos) return "the password has an invalid character";
	return "";
}

PgAuthBackend::PgAuthBackend(std::string conninfo) : conninfo_(std::move(conninfo)), dummy_hash_(db::hash_password("a password nobody has, for timing")) {}

std::optional<web::AuthUser> PgAuthBackend::verify(const std::string& username, const std::string& password) {
	db::Connection c(conninfo_);
	db::Result r = c.exec("SELECT u.id, u.username, u.password_hash, u.disabled, r.name, r.permissions FROM users u JOIN roles r ON r.id = u.role_id WHERE lower(u.username) = lower($1)",
		{clean_text(username, 64)});
	const bool found = r.rows() == 1;
	// always do the (slow) hash check, so an unknown name takes as long as a wrong password
	const bool ok = db::verify_password(found ? r.str(0, 2) : dummy_hash_, password) && found && r.str(0, 3) != "t";
	if (!ok) return std::nullopt;
	web::AuthUser u;
	u.id = r.integer(0, 0);
	u.username = r.str(0, 1);
	u.role = r.str(0, 4);
	u.permissions = parse_array(r.str(0, 5));
	c.exec("UPDATE users SET last_login_at = now() WHERE id = $1", {u.id});
	return u;
}

bool PgAuthBackend::has_users() {
	db::Connection c(conninfo_);
	return c.exec("SELECT count(*) FROM users").integer(0, 0) > 0;
}

web::UserInfo PgAuthBackend::create_first_admin(const std::string& username, const std::string& password) {
	if (auto why = check_username(username); !why.empty()) throw AuthError(400, why);
	if (auto why = check_password(username, password); !why.empty()) throw AuthError(400, why);
	db::Connection c(conninfo_);
	db::Transaction tx(c);
	c.exec("SELECT pg_advisory_xact_lock(726600101)"); // one first-run setup at a time
	if (c.exec("SELECT count(*) FROM users").integer(0, 0) > 0) throw AuthError(409, "the system is already set up");
	db::Result r = c.exec("INSERT INTO users (username, password_hash, role_id) SELECT $1, $2, id FROM roles WHERE name = 'admin' RETURNING id", {username, db::hash_password(password)});
	if (r.rows() == 0) throw AuthError(500, "the admin role is missing");
	tx.commit();
	return {r.integer(0, 0), username, "admin", false, ""};
}

std::vector<web::UserInfo> PgAuthBackend::users() {
	db::Connection c(conninfo_);
	db::Result r = c.exec(std::string("SELECT u.id, u.username, r.name, u.disabled, coalesce(to_char(u.last_login_at AT TIME ZONE 'UTC', '") + kTs +
		"'), '') FROM users u JOIN roles r ON r.id = u.role_id ORDER BY lower(u.username)");
	std::vector<web::UserInfo> out;
	for (int i = 0; i < r.rows(); i++) out.push_back({r.integer(i, 0), r.str(i, 1), r.str(i, 2), r.str(i, 3) == "t", r.str(i, 4)});
	return out;
}

std::vector<web::RoleInfo> PgAuthBackend::roles() {
	db::Connection c(conninfo_);
	db::Result r = c.exec("SELECT r.name, r.description, r.permissions, r.builtin, (SELECT count(*) FROM users u WHERE u.role_id = r.id) FROM roles r ORDER BY r.builtin DESC, r.id");
	std::vector<web::RoleInfo> out;
	for (int i = 0; i < r.rows(); i++) out.push_back({r.str(i, 0), r.str(i, 1), parse_array(r.str(i, 2)), r.str(i, 3) == "t", static_cast<size_t>(r.integer(i, 4))});
	return out;
}

web::UserInfo PgAuthBackend::create_user(const std::string& username, const std::string& password, const std::string& role) {
	if (auto why = check_username(username); !why.empty()) throw AuthError(400, why);
	if (auto why = check_password(username, password); !why.empty()) throw AuthError(400, why);
	db::Connection c(conninfo_);
	try {
		db::Result r = c.exec("INSERT INTO users (username, password_hash, role_id) SELECT $1, $2, id FROM roles WHERE name = $3 RETURNING id", {username, db::hash_password(password), role});
		if (r.rows() == 0) throw AuthError(400, "no such role: " + clean_text(role, 40));
		return {r.integer(0, 0), username, role, false, ""};
	} catch (const db::DbError& e) {
		if (e.sqlstate == "23505") throw AuthError(409, "a user with that name already exists");
		throw;
	}
}

void PgAuthBackend::update_user(int64_t id, const std::optional<std::string>& role, const std::optional<bool>& disabled, const std::optional<std::string>& password) {
	db::Connection c(conninfo_);
	db::Transaction tx(c);
	db::Result user = c.exec("SELECT username FROM users WHERE id = $1 FOR UPDATE", {id});
	if (user.rows() == 0) throw AuthError(404, "no such user");
	if (password) {
		if (auto why = check_password(user.str(0, 0), *password); !why.empty()) throw AuthError(400, why);
		c.exec("UPDATE users SET password_hash = $1 WHERE id = $2", {db::hash_password(*password), id});
	}
	if (role) {
		if (c.exec("UPDATE users SET role_id = r.id FROM roles r WHERE r.name = $1 AND users.id = $2", {*role, id}).affected() == 0) throw AuthError(400, "no such role: " + clean_text(*role, 40));
	}
	if (disabled) c.exec("UPDATE users SET disabled = $1 WHERE id = $2", {*disabled, id});
	if (administrators(c) == 0) throw AuthError(409, "that would leave no administrator"); // rolls back
	tx.commit();
}

web::RoleInfo PgAuthBackend::create_role(const std::string& name, const std::string& description, const std::vector<std::string>& permissions) {
	if (!valid_role_name(name)) throw AuthError(400, "a role name has 2 to 32 characters: lowercase letters, digits, '.', '_' and '-'");
	if (permissions.empty()) throw AuthError(400, "a role needs at least one permission");
	for (const std::string& p : permissions)
		if (!web::is_permission(p)) throw AuthError(400, "unknown permission: " + clean_text(p, 40));
	std::vector<std::string> unique = permissions;
	std::sort(unique.begin(), unique.end());
	unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
	db::Connection c(conninfo_);
	try {
		c.exec("INSERT INTO roles (name, description, permissions, builtin) VALUES ($1, $2, $3::text[], false)", {name, clean_text(description, 200), array_text(unique)});
	} catch (const db::DbError& e) {
		if (e.sqlstate == "23505") throw AuthError(409, "a role with that name already exists");
		throw;
	}
	return {name, clean_text(description, 200), unique, false, 0};
}

void PgAuthBackend::delete_role(const std::string& name) {
	db::Connection c(conninfo_);
	db::Transaction tx(c);
	db::Result r = c.exec("SELECT id, builtin, (SELECT count(*) FROM users u WHERE u.role_id = roles.id) FROM roles WHERE name = $1 FOR UPDATE", {name});
	if (r.rows() == 0) throw AuthError(404, "no such role");
	if (r.str(0, 1) == "t") throw AuthError(409, "built-in roles cannot be deleted");
	if (r.integer(0, 2) > 0) throw AuthError(409, "the role is in use: move its users to another role first");
	c.exec("DELETE FROM roles WHERE id = $1", {r.integer(0, 0)});
	tx.commit();
}

std::vector<web::AuditEntry> PgAuthBackend::audit(size_t limit) {
	db::Connection c(conninfo_);
	db::Result r = c.exec(std::string("SELECT a.id, to_char(a.at AT TIME ZONE 'UTC', '") + kTs + "'), coalesce(u.username, ''), a.action, coalesce(a.entity, ''), coalesce(a.detail->>'detail', a.detail::text, ''), coalesce(host(a.source_ip), '') "
		"FROM audit_log a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT $1", {static_cast<int64_t>(std::min<size_t>(limit, 1000))});
	std::vector<web::AuditEntry> out;
	for (int i = 0; i < r.rows(); i++) out.push_back({r.integer(i, 0), r.str(i, 1), r.str(i, 2), r.str(i, 3), r.str(i, 4), r.str(i, 5), r.str(i, 6)});
	return out;
}

void PgAuthBackend::record(const web::AuthUser* user, const std::string& action, const std::string& entity, const std::string& detail, const std::string& source_ip) {
	const nlohmann::json d = {{"detail", clean_text(detail, 500)}};
	const std::string sql = "INSERT INTO audit_log (user_id, action, entity, detail, source_ip) VALUES ($1, $2, $3, $4::jsonb, CASE WHEN $5 = '' THEN NULL ELSE $5::inet END)";
	auto write = [&](const std::string& ip) {
		db::Connection c(conninfo_);
		c.exec(sql, {user ? db::Param(user->id) : db::Param(), clean_text(action, 80), clean_text(entity, 120), d.dump(), ip});
	};
	try {
		try {
			write(source_ip.size() < 46 && source_ip.find('/') == std::string::npos ? source_ip : std::string());
		} catch (const db::DbError&) {
			write(std::string()); // an address Postgres does not accept must not lose the entry
		}
	} catch (...) {
		// an audit failure must not break the action being recorded
	}
}

std::unique_ptr<PgAuthBackend> open_pg_auth(const std::string& conninfo, const std::filesystem::path& migrations_dir) {
	{
		db::Connection c(conninfo);
		db::migrate(c, migrations_dir);
	}
	return std::make_unique<PgAuthBackend>(conninfo);
}

} // namespace proculus::auth
