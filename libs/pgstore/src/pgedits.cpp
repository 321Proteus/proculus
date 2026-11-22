#include "proculus/pgstore/pgedits.hpp"

#include "proculus/db/connection.hpp"

namespace proculus {

namespace {

using Json = nlohmann::ordered_json;

constexpr const char* kContext = "entity_edits.data_enc";
constexpr const char* kTs = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

class PgEditStore : public EditStore {
public:
	PgEditStore(std::string conninfo, db::FieldCipher cipher) : conninfo_(std::move(conninfo)), cipher_(std::move(cipher)) {}

	std::vector<std::pair<EditKey, EditRecord>> all() override {
		db::Connection c(conninfo_);
		db::Result r = c.exec(std::string("SELECT host(ip), port, protocol, data_enc, edited_by, to_char(edited_at AT TIME ZONE 'UTC', '") + kTs + "') FROM entity_edits ORDER BY ip, port, protocol");
		std::vector<std::pair<EditKey, EditRecord>> out;
		for (int i = 0; i < r.rows(); i++) out.emplace_back(EditKey{r.str(i, 0), static_cast<uint16_t>(r.integer(i, 1)), r.str(i, 2)}, record_of(r, i));
		return out;
	}

	std::optional<EditRecord> get(const EditKey& key) override {
		db::Connection c(conninfo_);
		db::Result r = c.exec(std::string("SELECT host(ip), port, protocol, data_enc, edited_by, to_char(edited_at AT TIME ZONE 'UTC', '") + kTs +
			"') FROM entity_edits WHERE ip = $1::inet AND port = $2 AND protocol = $3", {key.ip, static_cast<int>(key.port), key.protocol});
		if (r.rows() == 0) return std::nullopt;
		return record_of(r, 0);
	}

	EditResult apply(const EditKey& key, const nlohmann::json& changes, const std::string& user) override {
		if (!valid_ip(key.ip)) throw EditError(400, "not an IPv4 address: " + key.ip.substr(0, 40));
		db::Connection c(conninfo_);
		db::Transaction tx(c);
		c.exec("SELECT pg_advisory_xact_lock(hashtext($1))", {"entity_edits:" + key.text()}); // one edit of this key at a time
		db::Result r = c.exec(std::string("SELECT host(ip), port, protocol, data_enc, edited_by, to_char(edited_at AT TIME ZONE 'UTC', '") + kTs +
			"') FROM entity_edits WHERE ip = $1::inet AND port = $2 AND protocol = $3", {key.ip, static_cast<int>(key.port), key.protocol});
		EditResult result;
		EditRecord record;
		const bool exists = r.rows() == 1;
		if (exists) record = result.before = record_of(r, 0);
		apply_changes(key, changes, record);
		record.edited_by = user;
		if (record.empty()) {
			if (exists) c.exec("DELETE FROM entity_edits WHERE ip = $1::inet AND port = $2 AND protocol = $3", {key.ip, static_cast<int>(key.port), key.protocol});
		} else {
			c.exec("INSERT INTO entity_edits (ip, port, protocol, data_enc, edited_by) VALUES ($1::inet, $2, $3, $4, $5) "
			       "ON CONFLICT (ip, port, protocol) DO UPDATE SET data_enc = EXCLUDED.data_enc, edited_by = EXCLUDED.edited_by, edited_at = now()",
				{key.ip, static_cast<int>(key.port), key.protocol, cipher_.seal(payload(record), kContext), clip(user)});
			result.after = record;
			result.after.edited_at = c.exec(std::string("SELECT to_char(edited_at AT TIME ZONE 'UTC', '") + kTs + "') FROM entity_edits WHERE ip = $1::inet AND port = $2 AND protocol = $3",
				{key.ip, static_cast<int>(key.port), key.protocol}).str(0, 0);
		}
		tx.commit();
		return result;
	}

	bool clear(const EditKey& key) override {
		db::Connection c(conninfo_);
		return c.exec("DELETE FROM entity_edits WHERE ip = $1::inet AND port = $2 AND protocol = $3", {key.ip, static_cast<int>(key.port), key.protocol}).affected() > 0;
	}

private:
	static std::string clip(const std::string& s) { return s.substr(0, 64); }

	// The sealed part: the edited values (who and when are columns)
	static std::string payload(const EditRecord& r) {
		Json j = to_json(r);
		j.erase("edited_by");
		j.erase("edited_at");
		return j.dump();
	}

	EditRecord record_of(const db::Result& r, int row) const {
		Json j = Json::parse(cipher_.open(r.bytes(row, 3), kContext), nullptr, false);
		if (j.is_discarded() || !j.is_object()) throw std::runtime_error("a stored edit is damaged");
		EditRecord rec = record_from_json(j);
		rec.edited_by = r.str(row, 4);
		rec.edited_at = r.str(row, 5);
		return rec;
	}

	std::string conninfo_;
	db::FieldCipher cipher_;
};

} // namespace

std::unique_ptr<EditStore> make_pg_edit_store(const std::string& conninfo, db::FieldCipher cipher) { return std::make_unique<PgEditStore>(conninfo, std::move(cipher)); }

} // namespace proculus
