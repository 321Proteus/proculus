#ifndef PROCULUS_AUTH_FILEAUTH_HPP
#define PROCULUS_AUTH_FILEAUTH_HPP

// Users, roles and the audit log in files, for installations without a
// database: `users.json` (accounts with Argon2id hashes, and custom roles) and
// `audit.jsonl` in one directory. It behaves like the Postgres backend (same
// rules, same errors) so the rest of the system cannot tell them apart.
//
// Every change reads the file again, rewrites it atomically (temporary file,
// then rename, mode 0600) and holds an exclusive lock for that time, so the
// command line (`gateway user ...`) can change accounts while the server runs.
// Keep the directory private: it holds password hashes.

#include <filesystem>
#include <mutex>
#include <string>

#include "proculus/web/auth.hpp"

namespace proculus::auth {

class FileAuthBackend : public web::AuthBackend {
public:
	// Creates the directory if needed. Throws std::runtime_error if it cannot be used.
	explicit FileAuthBackend(std::filesystem::path dir);

	std::optional<web::AuthUser> verify(const std::string& username, const std::string& password) override;
	bool has_users() override;
	web::UserInfo create_first_admin(const std::string& username, const std::string& password) override;
	std::vector<web::UserInfo> users() override;
	std::vector<web::RoleInfo> roles() override;
	web::UserInfo create_user(const std::string& username, const std::string& password, const std::string& role) override;
	void update_user(int64_t id, const std::optional<std::string>& role, const std::optional<bool>& disabled, const std::optional<std::string>& password) override;
	web::RoleInfo create_role(const std::string& name, const std::string& description, const std::vector<std::string>& permissions) override;
	void delete_role(const std::string& name) override;
	std::vector<web::AuditEntry> audit(size_t limit) override;
	void record(const web::AuthUser* user, const std::string& action, const std::string& entity, const std::string& detail, const std::string& source_ip) override;

private:
	std::filesystem::path dir_;
	std::string dummy_hash_;
	std::mutex m_; // in-process; the file lock covers other processes
};

} // namespace proculus::auth

#endif // PROCULUS_AUTH_FILEAUTH_HPP
