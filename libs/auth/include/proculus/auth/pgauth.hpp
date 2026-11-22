#ifndef PROCULUS_AUTH_PGAUTH_HPP
#define PROCULUS_AUTH_PGAUTH_HPP

// Users, roles and the audit log in Postgres (the users, roles and audit_log
// tables of db/migrations), behind the AuthBackend interface of libs/web.
// Passwords are stored as Argon2id hashes (libsodium). Every operation uses its
// own connection, so the backend may be used from several threads.

#include <filesystem>
#include <memory>
#include <string>

#include "proculus/web/auth.hpp"

namespace proculus::auth {

class PgAuthBackend : public web::AuthBackend {
public:
	explicit PgAuthBackend(std::string conninfo);

	std::optional<web::AuthUser> verify(const std::string& username, const std::string& password) override;
	bool has_users() override;
	std::vector<web::UserInfo> users() override;
	std::vector<web::RoleInfo> roles() override;
	web::UserInfo create_user(const std::string& username, const std::string& password, const std::string& role) override;
	void update_user(int64_t id, const std::optional<std::string>& role, const std::optional<bool>& disabled, const std::optional<std::string>& password) override;
	web::RoleInfo create_role(const std::string& name, const std::string& description, const std::vector<std::string>& permissions) override;
	void delete_role(const std::string& name) override;
	std::vector<web::AuditEntry> audit(size_t limit) override;
	void record(const web::AuthUser* user, const std::string& action, const std::string& entity, const std::string& detail, const std::string& source_ip) override;

private:
	std::string conninfo_;
	std::string dummy_hash_; // checked when the user does not exist, so timing does not tell
};

// The rules for new accounts, exposed for the UI and tests: 3-64 characters of
// letters, digits, '.', '_' and '-'; passwords of 10-200 characters that are not the user name.
// Return an empty string if fine, otherwise the reason.
std::string check_username(const std::string& username);
std::string check_password(const std::string& username, const std::string& password);

// Applies the migrations in `migrations_dir`, then returns the backend.
std::unique_ptr<PgAuthBackend> open_pg_auth(const std::string& conninfo, const std::filesystem::path& migrations_dir);

} // namespace proculus::auth

#endif // PROCULUS_AUTH_PGAUTH_HPP
