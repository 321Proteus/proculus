#include "proculus/db/connection.hpp"

#include <libpq-fe.h>

#include <cstdlib>
#include <cstring>

namespace proculus::db {

namespace {

std::string trim_newline(std::string s) {
	while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
	return s;
}

} // namespace

// ------------------------------------------------------------- Result

Result::Result(pg_result* r) : r_(r) {}
Result::Result(Result&& o) noexcept : r_(o.r_) { o.r_ = nullptr; }
Result& Result::operator=(Result&& o) noexcept {
	if (this != &o) {
		PQclear(r_);
		r_ = o.r_;
		o.r_ = nullptr;
	}
	return *this;
}
Result::~Result() { PQclear(r_); }

int Result::rows() const { return PQntuples(r_); }
int Result::cols() const { return PQnfields(r_); }
bool Result::is_null(int row, int col) const { return PQgetisnull(r_, row, col) != 0; }
std::string Result::str(int row, int col) const { return PQgetvalue(r_, row, col); }

int64_t Result::integer(int row, int col) const {
	if (is_null(row, col)) throw DbError("unexpected NULL where an integer was expected");
	const char* s = PQgetvalue(r_, row, col);
	char* end = nullptr;
	long long v = std::strtoll(s, &end, 10);
	if (end == s || *end != '\0') throw DbError(std::string("not an integer: ") + s);
	return v;
}

std::vector<uint8_t> Result::bytes(int row, int col) const {
	if (is_null(row, col)) return {};
	size_t len = 0;
	unsigned char* raw = PQunescapeBytea(reinterpret_cast<const unsigned char*>(PQgetvalue(r_, row, col)), &len);
	if (!raw) throw DbError("cannot decode bytea value");
	std::vector<uint8_t> out(raw, raw + len);
	PQfreemem(raw);
	return out;
}

int64_t Result::affected() const {
	const char* s = PQcmdTuples(r_);
	return (s && *s) ? std::strtoll(s, nullptr, 10) : 0;
}

// --------------------------------------------------------- Connection

Connection::Connection(const std::string& conninfo) {
	conn_ = PQconnectdb(conninfo.c_str());
	if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
		std::string msg = conn_ ? trim_newline(PQerrorMessage(conn_)) : "out of memory";
		PQfinish(conn_);
		conn_ = nullptr;
		throw DbError("cannot connect to database: " + msg);
	}
}

Connection::~Connection() { PQfinish(conn_); }

static Result check(pg_result* r, pg_conn* conn) {
	if (!r) throw DbError(trim_newline(PQerrorMessage(conn)));
	ExecStatusType st = PQresultStatus(r);
	if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK && st != PGRES_EMPTY_QUERY) {
		const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		std::string msg = trim_newline(PQresultErrorMessage(r));
		PQclear(r);
		throw DbError(msg, state ? state : "");
	}
	return Result(r);
}

Result Connection::exec(const std::string& sql, const std::vector<Param>& params) {
	const int n = static_cast<int>(params.size());
	std::vector<const char*> values(params.size());
	std::vector<int> lengths(params.size()), formats(params.size());
	for (size_t i = 0; i < params.size(); i++) {
		const Param& p = params[i];
		values[i] = p.kind() == Param::Kind::Null ? nullptr : p.data().data();
		lengths[i] = static_cast<int>(p.data().size());
		formats[i] = p.kind() == Param::Kind::Bytes ? 1 : 0;
	}
	return check(PQexecParams(conn_, sql.c_str(), n, nullptr, values.data(), lengths.data(), formats.data(), 0), conn_);
}

void Connection::exec_script(const std::string& sql) { check(PQexec(conn_, sql.c_str()), conn_); }

// -------------------------------------------------------- Transaction

Transaction::Transaction(Connection& c) : c_(c) { c_.exec("BEGIN"); }

Transaction::~Transaction() {
	if (done_) return;
	try {
		c_.exec("ROLLBACK");
	} catch (...) {
	}
}

void Transaction::commit() {
	c_.exec("COMMIT");
	done_ = true;
}

} // namespace proculus::db
