#ifndef PROCULUS_DB_MIGRATE_HPP
#define PROCULUS_DB_MIGRATE_HPP

#include <filesystem>
#include <string>
#include <vector>

#include "connection.hpp"

namespace proculus::db {

// Applies every `*.sql` file in `dir` that has not been applied yet, in file
// name order, each inside its own transaction. Applied files are recorded in
// `schema_migrations` with a SHA-256 checksum; if an applied file has changed
// on disk, this throws instead of silently diverging.
//
// A database-wide advisory lock makes it safe for several services to call
// this at start-up at the same time. Returns the versions applied by this call.
std::vector<std::string> migrate(
	Connection& conn, const std::filesystem::path& dir);

} // namespace proculus::db

#endif // PROCULUS_DB_MIGRATE_HPP
