#include "proculus/pgstore/pgstore.hpp"

#include <algorithm>
#include <cstdlib>
#include <map>

#include "proculus/db/connection.hpp"
#include "proculus/db/migrate.hpp"

namespace proculus {

namespace {

using db::Param;

// Text for Postgres: no NUL bytes, valid UTF-8 (invalid sequences become U+FFFD).
std::string clean(const std::string& s) {
	std::string out;
	out.reserve(s.size());
	for (size_t i = 0; i < s.size();) {
		const unsigned char c = static_cast<unsigned char>(s[i]);
		size_t len = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
		bool ok = len != 0 && i + len <= s.size() && c != 0;
		for (size_t k = 1; ok && k < len; k++) ok = (static_cast<unsigned char>(s[i + k]) & 0xC0) == 0x80;
		if (ok && len == 2 && c < 0xC2) ok = false;                                   // overlong
		if (ok && len == 3 && c == 0xE0 && static_cast<unsigned char>(s[i + 1]) < 0xA0) ok = false;
		if (ok && len == 3 && c == 0xED && static_cast<unsigned char>(s[i + 1]) >= 0xA0) ok = false; // surrogates
		if (ok && len == 4 && (c > 0xF4 || (c == 0xF0 && static_cast<unsigned char>(s[i + 1]) < 0x90) || (c == 0xF4 && static_cast<unsigned char>(s[i + 1]) >= 0x90))) ok = false;
		if (ok) {
			out.append(s, i, len);
			i += len;
		} else if (c == 0) {
			i++; // drop NUL
		} else {
			out += "\xEF\xBF\xBD";
			i++;
		}
	}
	return out;
}

Param text(const std::string& s) { return Param(clean(s)); }
Param optional_text(const std::string& s) { return s.empty() ? Param() : Param(clean(s)); }

constexpr const char* kTsFormat = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

std::vector<uint8_t> seal(const db::FieldCipher& c, const std::string& plaintext, const char* column) {
	return c.seal(plaintext, std::string("http_observations.") + column);
}

std::string open_text(const db::FieldCipher& c, const db::Result& r, int row, int col, const char* column) {
	return c.open(r.bytes(row, col), std::string("http_observations.") + column);
}

Json parse_part(const std::string& text, const char* what) {
	Json j = Json::parse(text, nullptr, false);
	if (j.is_discarded()) throw FormatError(std::string("stored ") + what + " is not valid JSON");
	return j;
}

} // namespace

PgResultStore::PgResultStore(std::string conninfo, db::FieldCipher cipher) : conninfo_(std::move(conninfo)), cipher_(std::move(cipher)) {}

int64_t PgResultStore::save(RunRecord run) {
	try {
		db::Connection c(conninfo_);
		db::Transaction tx(c);
		const Param started = optional_text(run.started), finished = optional_text(run.finished);

		db::Result r = c.exec(
			"INSERT INTO scan_runs (status, source, started_at, finished_at, total_addresses, chunks, pauses, cancelled_chunks) "
			"VALUES ('completed', $1, $2::timestamptz, $3::timestamptz, $4, $5, $6, $7) RETURNING id",
			{text(run.source), started, finished, static_cast<int64_t>(run.addresses_scanned), run.chunks, run.pauses, run.cancelled_chunks});
		const int64_t id = r.integer(0, 0);

		for (const HostRecord& h : run.hosts) {
			if (h.ip.find('/') != std::string::npos) throw FormatError("bad address: " + clean(h.ip));
			c.exec("INSERT INTO observations (run_id, observed_at, ip, host_up, hostname) VALUES ($1, COALESCE($2::timestamptz, now()), $3::inet, true, $4)",
				{id, finished, text(h.ip), optional_text(h.hostname)});

			for (const ServiceRecord& s : h.services) {
				c.exec("INSERT INTO observations (run_id, observed_at, ip, host_up, port, protocol, port_state, service_name, product, version, extrainfo, confidence) "
				       "VALUES ($1, COALESCE($2::timestamptz, now()), $3::inet, true, $4, $5, $6, $7, $8, $9, $10, $11)",
					{id, finished, text(h.ip), static_cast<int>(s.port), text(s.protocol), text(s.state), optional_text(s.name), optional_text(s.product),
						optional_text(s.version), optional_text(s.extrainfo), s.confidence});
				if (!s.web) continue;

				const Json j = web_to_json(*s.web);
				const std::string scheme = s.web->url.compare(0, 8, "https://") == 0 ? "https" : "http";
				Json meta = {{"url", j["url"]}, {"server", j["server"]}, {"content_type", j["content_type"]}};
				const Param tls = j.contains("tls") ? Param(seal(cipher_, dump_json(j["tls"]), "tls_enc")) : Param();
				c.exec("INSERT INTO http_observations (run_id, observed_at, ip, port, scheme, status_code, favicon_hash, title_enc, headers_enc, cookies_enc, tls_enc, "
				       "redirects_enc, meta_enc, detections_enc) VALUES ($1, COALESCE($2::timestamptz, now()), $3::inet, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
					{id, finished, text(h.ip), static_cast<int>(s.port), scheme, s.web->status, s.web->favicon_hash ? Param(static_cast<int64_t>(*s.web->favicon_hash)) : Param(),
						seal(cipher_, clean(j["title"].get<std::string>()), "title_enc"), seal(cipher_, dump_json(j["headers"]), "headers_enc"),
						seal(cipher_, dump_json(j["cookies"]), "cookies_enc"), tls, seal(cipher_, dump_json(j["redirects"]), "redirects_enc"),
						seal(cipher_, dump_json(meta), "meta_enc"), seal(cipher_, dump_json(j["detections"]), "detections_enc")});
			}
		}
		tx.commit();
		return id;
	} catch (const db::DbError& e) {
		// data Postgres cannot hold is the caller's problem, not an outage
		if (e.sqlstate == "22007" || e.sqlstate == "22008" || e.sqlstate == "22P02" || e.sqlstate == "22021") throw FormatError(std::string("the run holds data that cannot be stored: ") + e.what());
		if (e.sqlstate == "23505") throw FormatError(std::string("the run lists a host or service twice: ") + e.what());
		throw;
	}
}

std::vector<RunSummary> PgResultStore::list() const {
	db::Connection c(conninfo_);
	db::Result r = c.exec(
		std::string("SELECT r.id, r.source, coalesce(to_char(r.started_at AT TIME ZONE 'UTC', '") + kTsFormat + "'), ''), coalesce(to_char(r.finished_at AT TIME ZONE 'UTC', '" + kTsFormat +
		"'), ''), "
		"(SELECT count(*) FROM observations o WHERE o.run_id = r.id AND o.port IS NULL), "
		"(SELECT count(*) FROM observations o WHERE o.run_id = r.id AND o.port IS NOT NULL) "
		"FROM scan_runs r WHERE r.status = 'completed' ORDER BY r.id");
	std::vector<RunSummary> out;
	for (int i = 0; i < r.rows(); i++) {
		RunSummary s;
		s.id = r.integer(i, 0);
		s.source = r.str(i, 1);
		s.started = r.str(i, 2);
		s.finished = r.str(i, 3);
		s.hosts = static_cast<size_t>(r.integer(i, 4));
		s.services = static_cast<size_t>(r.integer(i, 5));
		out.push_back(std::move(s));
	}
	return out;
}

std::optional<RunRecord> PgResultStore::load(int64_t id) const {
	db::Connection c(conninfo_);
	db::Result r = c.exec(
		std::string("SELECT r.id, r.source, coalesce(to_char(r.started_at AT TIME ZONE 'UTC', '") + kTsFormat + "'), ''), coalesce(to_char(r.finished_at AT TIME ZONE 'UTC', '" + kTsFormat +
		"'), ''), r.total_addresses, r.chunks, r.pauses, r.cancelled_chunks FROM scan_runs r WHERE r.id = $1 AND r.status = 'completed'",
		{id});
	if (r.rows() == 0) return std::nullopt;

	RunRecord run;
	run.id = r.integer(0, 0);
	run.source = r.str(0, 1);
	run.started = r.str(0, 2);
	run.finished = r.str(0, 3);
	run.addresses_scanned = static_cast<uint64_t>(r.integer(0, 4));
	run.chunks = static_cast<int>(r.integer(0, 5));
	run.pauses = static_cast<int>(r.integer(0, 6));
	run.cancelled_chunks = static_cast<int>(r.integer(0, 7));

	// hosts and services (the host-level row has no port)
	db::Result obs = c.exec(
		"SELECT host(ip), hostname, port, protocol, port_state, service_name, product, version, extrainfo, confidence FROM observations WHERE run_id = $1 "
		"ORDER BY ip, port NULLS FIRST, protocol",
		{id});
	std::map<std::string, size_t> index; // address -> position in run.hosts
	for (int i = 0; i < obs.rows(); i++) {
		const std::string ip = obs.str(i, 0);
		auto it = index.find(ip);
		if (it == index.end()) {
			it = index.emplace(ip, run.hosts.size()).first;
			HostRecord h;
			h.ip = ip;
			run.hosts.push_back(std::move(h));
		}
		HostRecord& h = run.hosts[it->second];
		if (obs.is_null(i, 2)) {
			h.hostname = obs.str(i, 1);
			continue;
		}
		ServiceRecord s;
		s.port = static_cast<uint16_t>(obs.integer(i, 2));
		s.protocol = obs.str(i, 3);
		s.state = obs.str(i, 4);
		s.name = obs.str(i, 5);
		s.product = obs.str(i, 6);
		s.version = obs.str(i, 7);
		s.extrainfo = obs.str(i, 8);
		s.confidence = obs.is_null(i, 9) ? 0 : static_cast<int>(obs.integer(i, 9));
		h.services.push_back(std::move(s));
	}

	// web results, sealed
	db::Result web = c.exec(
		"SELECT host(ip), port, status_code, favicon_hash, title_enc, headers_enc, cookies_enc, tls_enc, redirects_enc, meta_enc, detections_enc "
		"FROM http_observations WHERE run_id = $1",
		{id});
	try {
		for (int i = 0; i < web.rows(); i++) {
			auto host = index.find(web.str(i, 0));
			if (host == index.end()) throw FormatError("web data for a host that is not in the run");
			const int port = static_cast<int>(web.integer(i, 1));
			auto svc = std::find_if(run.hosts[host->second].services.begin(), run.hosts[host->second].services.end(), [&](const ServiceRecord& s) { return s.port == port; });
			if (svc == run.hosts[host->second].services.end()) throw FormatError("web data for a service that is not in the run");

			Json j = parse_part(open_text(cipher_, web, i, 9, "meta_enc"), "web metadata");
			j["status"] = web.is_null(i, 2) ? 0 : static_cast<int>(web.integer(i, 2));
			j["title"] = open_text(cipher_, web, i, 4, "title_enc");
			j["headers"] = parse_part(open_text(cipher_, web, i, 5, "headers_enc"), "headers");
			j["cookies"] = parse_part(open_text(cipher_, web, i, 6, "cookies_enc"), "cookies");
			if (!web.is_null(i, 7)) j["tls"] = parse_part(open_text(cipher_, web, i, 7, "tls_enc"), "TLS data");
			j["redirects"] = parse_part(open_text(cipher_, web, i, 8, "redirects_enc"), "redirects");
			j["detections"] = parse_part(open_text(cipher_, web, i, 10, "detections_enc"), "detections");
			if (!web.is_null(i, 3)) j["favicon_hash"] = web.integer(i, 3);
			svc->web = web_from_json(j);
		}
	} catch (const db::CryptoError& e) {
		throw FormatError(std::string("stored web data cannot be opened (wrong key, or damaged): ") + e.what());
	}
	return run;
}

std::filesystem::path default_migrations_dir() {
	if (const char* env = std::getenv("PROCULUS_MIGRATIONS_DIR"); env && *env) return env;
	return PROCULUS_DEFAULT_MIGRATIONS_DIR;
}

std::unique_ptr<ResultStore> open_pg_store(const std::string& conninfo, const std::filesystem::path& migrations_dir) {
	{
		db::Connection c(conninfo);
		db::migrate(c, migrations_dir);
	}
	return std::make_unique<PgResultStore>(conninfo, db::FieldCipher(db::KeyRing::from_env()));
}

} // namespace proculus
