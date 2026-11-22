#ifndef PROCULUS_PGSTORE_HPP
#define PROCULUS_PGSTORE_HPP

// A ResultStore kept in Postgres, behind the same interface as the file store.
//
// What goes where (see db/migrations): addresses, ports, timestamps, service
// names and versions stay in the clear, so runs can be indexed and queried by
// address; everything a scan reads from the network that may be sensitive
// (page titles, headers, cookies, TLS details, redirects, detections) is sealed
// with the field cipher (XChaCha20-Poly1305), each value bound to its own
// column, so a blob copied into another column or another key does not open.
//
// A run is saved in one transaction: all of it or none of it. Every operation
// uses its own connection, so the store may be used from several threads.
// Hosts come back ordered by address and services by port, which is how the
// runner writes them.

#include <filesystem>
#include <memory>
#include <string>

#include "proculus/db/crypto.hpp"
#include "proculus/results/results.hpp"

namespace proculus {

class PgResultStore : public ResultStore {
public:
	// `conninfo` is a libpq connection string or URL. The schema must exist
	// (see open_pg_store). Throws nothing until it is used.
	PgResultStore(std::string conninfo, db::FieldCipher cipher);

	// Throws FormatError for data Postgres cannot hold (bad address or timestamp,
	// a host or service listed twice) and db::DbError for database trouble.
	int64_t save(RunRecord run) override;
	std::vector<RunSummary> list() const override;
	// nullopt if there is no such run. Throws FormatError if stored data is
	// damaged or sealed under another key.
	std::optional<RunRecord> load(int64_t id) const override;

private:
	std::string conninfo_;
	db::FieldCipher cipher_;
};

// Where the migrations are: $PROCULUS_MIGRATIONS_DIR, or the directory of this
// source tree the program was built from.
std::filesystem::path default_migrations_dir();

// Connects, applies the migrations in `migrations_dir` that are missing, and
// returns a store using the keys from the environment (PROCULUS_KEY_FILE or
// PROCULUS_KEY, see db/crypto.hpp). Throws db::DbError, db::CryptoError.
std::unique_ptr<ResultStore> open_pg_store(const std::string& conninfo, const std::filesystem::path& migrations_dir);

} // namespace proculus

#endif // PROCULUS_PGSTORE_HPP
