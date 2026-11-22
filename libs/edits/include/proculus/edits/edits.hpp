#ifndef PROCULUS_EDITS_HPP
#define PROCULUS_EDITS_HPP

// User edits of scanned data: a host name, tags, a note, an environment, a
// status ("ignored", "false positive", "confirmed") and a priority, for a host
// or for one of its services.
//
// Edits are kept apart from what scans found and are keyed by what they are
// about (address, and port and protocol for a service), not by any scan. No scan
// ever touches them, so they survive every later scan, and they stay when a host
// disappears and comes back. Readers apply them on top of the scan data.

#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace proculus {

struct EditKey {
	std::string ip;
	uint16_t port = 0;     // 0: the host itself
	std::string protocol;  // "tcp" / "udp"; empty for the host
	bool is_host() const { return port == 0; }
	bool operator==(const EditKey& o) const { return ip == o.ip && port == o.port && protocol == o.protocol; }
	std::string text() const; // "10.0.0.1" or "10.0.0.1:80/tcp"
};

struct EditRecord {
	std::optional<std::string> hostname;     // hosts only
	std::optional<std::string> environment;  // hosts only: prod, staging, test, dev
	std::optional<std::string> status;       // ignored, false_positive, confirmed
	std::optional<std::string> note;
	std::optional<int> priority;             // 0-100: replaces the computed priority score
	std::vector<std::string> tags;
	std::string edited_by, edited_at;        // who and when (UTC ISO)

	bool empty() const { return !hostname && !environment && !status && !note && !priority && tags.empty(); }
};

nlohmann::ordered_json to_json(const EditRecord& r);
EditRecord record_from_json(const nlohmann::json& j); // for stores reading their own data

// A refused edit; status is the HTTP status to answer with.
struct EditError : std::runtime_error {
	EditError(int status, const std::string& message) : std::runtime_error(message), status(status) {}
	int status;
};

// Validates and applies `changes` (a JSON object: field -> new value, or null to
// remove the field) to `record`. Throws EditError(400) for unknown fields, fields
// that do not apply to the key's level, or bad values. All or nothing.
void apply_changes(const EditKey& key, const nlohmann::json& changes, EditRecord& record);

// An IPv4 address, checked: 4 numbers 0-255.
bool valid_ip(const std::string& ip);

struct EditResult {
	EditRecord before, after; // `after` is empty if every field was removed (the edit is gone)
};

class EditStore {
public:
	virtual ~EditStore() = default;
	virtual std::vector<std::pair<EditKey, EditRecord>> all() = 0;
	virtual std::optional<EditRecord> get(const EditKey& key) = 0;
	// Applies the changes, stamping `user` and the time; removes the edit if nothing is left.
	virtual EditResult apply(const EditKey& key, const nlohmann::json& changes, const std::string& user) = 0;
	// Removes the edit; false if there was none.
	virtual bool clear(const EditKey& key) = 0;
};

// Edits in `edits.json` in a directory, written atomically under a file lock
// (so other processes may use the same directory). Creates the directory.
std::unique_ptr<EditStore> make_file_edit_store(const std::filesystem::path& dir);

} // namespace proculus

#endif // PROCULUS_EDITS_HPP
