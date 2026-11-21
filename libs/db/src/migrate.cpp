#include "proculus/db/migrate.hpp"

#include <sodium.h>

#include <algorithm>
#include <fstream>
#include <sstream>

namespace proculus::db {

namespace {

constexpr int64_t kLockKey = 0x70726F63; // "proc"

std::string sha256_hex(const std::string& data) {
	unsigned char digest[crypto_hash_sha256_BYTES];
	crypto_hash_sha256(digest,
		reinterpret_cast<const unsigned char*>(data.data()), data.size());
	char hex[crypto_hash_sha256_BYTES * 2 + 1];
	sodium_bin2hex(hex, sizeof hex, digest, sizeof digest);
	return hex;
}

struct AdvisoryLock {
	Connection& c;
	explicit AdvisoryLock(Connection& conn) : c(conn) {
		c.exec("SELECT pg_advisory_lock($1)", { kLockKey });
	}
	~AdvisoryLock() {
		try {
			c.exec("SELECT pg_advisory_unlock($1)", { kLockKey });
		} catch (...) {}
	}
};

} // namespace

std::vector<std::string> migrate(
	Connection& conn, const std::filesystem::path& dir) {
	if (sodium_init() < 0) throw DbError("libsodium initialisation failed");
	if (!std::filesystem::is_directory(dir))
		throw DbError("migrations directory not found: " + dir.string());

	std::vector<std::filesystem::path> files;
	for (const auto& e : std::filesystem::directory_iterator(dir))
		if (e.is_regular_file() && e.path().extension() == ".sql")
			files.push_back(e.path());
	std::sort(files.begin(), files.end());

	AdvisoryLock lock(conn);
	conn.exec("CREATE TABLE IF NOT EXISTS schema_migrations ("
			  "version text PRIMARY KEY, checksum text NOT NULL, applied_at "
			  "timestamptz NOT NULL DEFAULT now())");

	std::vector<std::string> applied;
	for (const auto& path : files) {
		std::ifstream f(path, std::ios::binary);
		if (!f) throw DbError("cannot read migration " + path.string());
		std::ostringstream ss;
		ss << f.rdbuf();
		const std::string sql = ss.str();
		const std::string version = path.stem().string();
		const std::string checksum = sha256_hex(sql);

		Result known = conn.exec(
			"SELECT checksum FROM schema_migrations WHERE version = $1",
			{ version });
		if (known.rows() > 0) {
			if (known.str(0, 0) != checksum)
				throw DbError("migration " + version +
					" was modified after it was applied");
			continue;
		}

		Transaction tx(conn);
		conn.exec_script(sql);
		conn.exec(
			"INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)",
			{ version, checksum });
		tx.commit();
		applied.push_back(version);
	}
	return applied;
}

} // namespace proculus::db
