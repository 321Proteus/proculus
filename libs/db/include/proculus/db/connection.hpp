#ifndef PROCULUS_DB_CONNECTION_HPP
#define PROCULUS_DB_CONNECTION_HPP

// Small RAII layer over libpq. All values go through parameters (PQexecParams),
// never string concatenation.

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

struct pg_conn;
struct pg_result;

namespace proculus::db {

struct DbError : std::runtime_error {
	DbError(const std::string& msg, std::string sqlstate = "")
		: std::runtime_error(msg), sqlstate(std::move(sqlstate)) {}
	std::string sqlstate; // e.g. "23505" for a unique violation; empty for
						  // connection errors
};

// One query parameter: SQL NULL, text, or raw bytes (for bytea).
class Param {
public:
	enum class Kind { Null, Text, Bytes };

	Param() = default;
	Param(std::nullptr_t) {}
	Param(const char* s) : kind_(Kind::Text), data_(s) {}
	Param(std::string s) : kind_(Kind::Text), data_(std::move(s)) {}
	Param(bool b) : kind_(Kind::Text), data_(b ? "true" : "false") {}
	Param(const std::vector<uint8_t>& b)
		: kind_(Kind::Bytes),
		  data_(reinterpret_cast<const char*>(b.data()), b.size()) {}
	template <class T,
		std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>,
			int> = 0>
	Param(T v) : kind_(Kind::Text), data_(std::to_string(v)) {}

	Kind kind() const { return kind_; }
	const std::string& data() const { return data_; }

private:
	Kind kind_ = Kind::Null;
	std::string data_;
};

// Query result (text format)
// MOVE-ONLY!!!
class Result {
public:
	explicit Result(pg_result* r);
	Result(Result&&) noexcept;
	Result& operator=(Result&&) noexcept;
	~Result();
	Result(const Result&) = delete;
	Result& operator=(const Result&) = delete;

	int rows() const;
	int cols() const;
	bool is_null(int row, int col) const;
	std::string str(int row, int col) const; // "" for NULL
	int64_t integer(
		int row, int col) const; // throws DbError on NULL or non-numeric
	std::vector<uint8_t> bytes(int row, int col) const; // bytea column, decoded
	int64_t affected() const; // rows touched by INSERT/UPDATE/DELETE

private:
	pg_result* r_ = nullptr;
};

class Connection {
public:
	// conninfo is a libpq connection string or URL. Throws DbError.
	explicit Connection(const std::string& conninfo);
	~Connection();
	Connection(const Connection&) = delete;
	Connection& operator=(const Connection&) = delete;

	Result exec(const std::string& sql, const std::vector<Param>& params = {});
	// Runs a multi-statement script (migrations). No parameters.
	void exec_script(const std::string& sql);

private:
	pg_conn* conn_ = nullptr;
};

// BEGIN ... COMMIT; rolls back on destruction unless commit() was called.
class Transaction {
public:
	explicit Transaction(Connection& c);
	~Transaction();
	Transaction(const Transaction&) = delete;
	Transaction& operator=(const Transaction&) = delete;
	void commit();

private:
	Connection& c_;
	bool done_ = false;
};

} // namespace proculus::db

#endif // PROCULUS_DB_CONNECTION_HPP
