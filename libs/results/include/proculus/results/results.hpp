#ifndef PROCULUS_RESULTS_HPP
#define PROCULUS_RESULTS_HPP

// What a scan run found, and where it is kept.
//
// RunRecord is the stored form of one complete scan round: which hosts
// answered and which services they expose. Stores keep runs and hand them back;
// the file-backed store is the simplest one, a Postgres-backed one can sit
// behind the same interface.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace proculus {

// What a signature recognised on a web service.
struct DetectionRecord {
	std::string id, name, category;
	double confidence = 0; // 0..0.99
	int interest = 0;      // 0..5
	std::string version;
	bool builtin = false;
	std::vector<std::string> tags;
	std::vector<std::string> evidence; // one line per matched signal, for people to check
};

// Cookie names and attributes only: values are never stored.
struct CookieRecord {
	std::string name;
	bool secure = false;
	bool http_only = false;
	std::string same_site;
};

struct TlsRecord {
	std::string version, cipher;
	std::string subject, issuer, not_before, not_after, sha256, key_type;
	int key_bits = 0;
	bool self_signed = false, expired = false, not_yet_valid = false;
	std::optional<bool> hostname_match;
	std::vector<std::string> san;
};

// What the web prober saw on a service, plus what the signatures made of it.
// The page body is not kept. Set-Cookie values are already redacted in `headers`.
struct WebRecord {
	std::string url;
	int status = 0;
	std::string title, server, content_type;
	std::vector<std::pair<std::string, std::string>> headers;
	std::vector<CookieRecord> cookies;
	std::vector<std::string> redirects; // Location values, as sent
	std::optional<TlsRecord> tls;
	std::optional<int32_t> favicon_hash;
	std::vector<DetectionRecord> detections;
};

struct ServiceRecord {
	uint16_t port = 0;
	std::string protocol = "tcp";
	std::string state = "open";
	std::string name, product, version, extrainfo;
	int confidence = 0; // nmap's 0-10 service match confidence
	std::optional<WebRecord> web; // set when the service was probed as a web service
};

struct HostRecord {
	std::string ip;
	std::string hostname;
	std::vector<ServiceRecord> services;
};

struct RunRecord {
	int64_t id = 0; // assigned by the store on save
	std::string source;   // "nmap", "sim", "import", ...
	std::string started;  // UTC, e.g. 2026-11-21T22:00:00Z
	std::string finished;
	uint64_t addresses_scanned = 0;
	int chunks = 0;
	int pauses = 0;
	int cancelled_chunks = 0;
	std::vector<HostRecord> hosts;
};

struct RunSummary {
	int64_t id = 0;
	std::string source, started, finished;
	size_t hosts = 0;
	size_t services = 0;
};

RunSummary summarize(const RunRecord& run);

// Bumped when the stored layout changes incompatibly.
constexpr int kFormatVersion = 1;

// A stored run that is missing fields, has the wrong types, or comes from a
// newer format version.
struct FormatError : std::runtime_error {
	using std::runtime_error::runtime_error;
};

// Insertion-ordered JSON, so stored files read id / source / started / ... in
// that order instead of alphabetically.
using Json = nlohmann::ordered_json;

// Serialises with the given indentation (< 0: compact). Invalid UTF-8 in
// scanned text (banners come from the network) is replaced with U+FFFD
// instead of making serialisation fail.
std::string dump_json(const Json& j, int indent = -1);

Json run_to_json(const RunRecord& run);
RunRecord run_from_json(const Json& v); // throws FormatError

// Persists runs. Implementations must be safe against partial writes: a run
// is either stored completely or not at all.
class ResultStore {
public:
	virtual ~ResultStore() = default;
	// Stores `run` under a new id (any id already set is ignored) and returns it.
	virtual int64_t save(RunRecord run) = 0;
	virtual std::vector<RunSummary> list() const = 0; // oldest first
	virtual std::optional<RunRecord> load(int64_t id) const = 0;
};

// One JSON file per run in a directory: run-000001.json, run-000002.json, ...
// The directory is created on first use. Files are written to a temporary name
// and moved into place without overwriting, so concurrent writers never lose a
// run and readers never see half a file.
//
// NOTE: files are plain text. Use a protected directory; encrypted storage is
// provided by the database-backed store.
class FileResultStore : public ResultStore {
public:
	explicit FileResultStore(std::filesystem::path dir);

	int64_t save(RunRecord run) override;
	std::vector<RunSummary> list() const override;
	std::optional<RunRecord> load(int64_t id) const override;

	std::filesystem::path path_for(int64_t id) const;

private:
	std::vector<int64_t> ids() const;
	std::filesystem::path dir_;
};

} // namespace proculus

#endif // PROCULUS_RESULTS_HPP
