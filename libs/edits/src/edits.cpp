#include "proculus/edits/edits.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>

namespace proculus {

using Json = nlohmann::ordered_json;

std::string EditKey::text() const { return is_host() ? ip : ip + ":" + std::to_string(port) + "/" + protocol; }

bool valid_ip(const std::string& ip) {
	int parts = 0;
	size_t i = 0;
	while (i < ip.size()) {
		size_t start = i;
		int value = 0;
		while (i < ip.size() && std::isdigit(static_cast<unsigned char>(ip[i]))) {
			value = value * 10 + (ip[i] - '0');
			if (++i - start > 3) return false;
		}
		if (i == start || value > 255) return false;
		parts++;
		if (i < ip.size()) {
			if (ip[i] != '.') return false;
			i++;
			if (i == ip.size()) return false;
		}
	}
	return parts == 4;
}

namespace {

[[noreturn]] void bad(const std::string& why) { throw EditError(400, why); }

bool clean_text(const std::string& s) {
	return std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= 0x20 && c != 0x7f; });
}

std::string now_text() {
	const std::time_t t = std::time(nullptr);
	std::tm tm{};
	gmtime_r(&t, &tm);
	char buf[32];
	std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
	return buf;
}

const std::set<std::string> kEnvironments = {"prod", "staging", "test", "dev"};
const std::set<std::string> kStatuses = {"ignored", "false_positive", "confirmed"};

} // namespace

Json to_json(const EditRecord& r) {
	Json j = Json::object();
	if (r.hostname) j["hostname"] = *r.hostname;
	if (r.environment) j["environment"] = *r.environment;
	if (r.status) j["status"] = *r.status;
	if (r.priority) j["priority"] = *r.priority;
	if (!r.tags.empty()) j["tags"] = r.tags;
	if (r.note) j["note"] = *r.note;
	j["edited_by"] = r.edited_by;
	j["edited_at"] = r.edited_at;
	return j;
}

EditRecord record_from_json(const nlohmann::json& j) {
	EditRecord r;
	if (j.contains("hostname") && j["hostname"].is_string()) r.hostname = j["hostname"].get<std::string>();
	if (j.contains("environment") && j["environment"].is_string()) r.environment = j["environment"].get<std::string>();
	if (j.contains("status") && j["status"].is_string()) r.status = j["status"].get<std::string>();
	if (j.contains("note") && j["note"].is_string()) r.note = j["note"].get<std::string>();
	if (j.contains("priority") && j["priority"].is_number_integer()) r.priority = j["priority"].get<int>();
	if (j.contains("tags") && j["tags"].is_array())
		for (const auto& t : j["tags"])
			if (t.is_string()) r.tags.push_back(t.get<std::string>());
	r.edited_by = j.value("edited_by", std::string());
	r.edited_at = j.value("edited_at", std::string());
	return r;
}

void apply_changes(const EditKey& key, const nlohmann::json& changes, EditRecord& record) {
	if (!changes.is_object()) bad("the changes must be an object: {\"note\": \"...\", \"status\": \"ignored\", ...}");
	if (!valid_ip(key.ip)) bad("not an IPv4 address: " + key.ip.substr(0, 40));
	if (!key.is_host() && (key.protocol != "tcp" && key.protocol != "udp")) bad("a service edit needs a protocol (tcp or udp)");
	EditRecord next = record; // all or nothing
	for (auto it = changes.begin(); it != changes.end(); ++it) {
		const std::string& f = it.key();
		const auto& v = it.value();
		const bool remove = v.is_null() || (v.is_string() && v.get<std::string>().empty()) || (v.is_array() && v.empty());
		if ((f == "hostname" || f == "environment") && !key.is_host()) bad("\"" + f + "\" applies to a host, not to a service");
		if (f == "hostname") {
			if (remove) next.hostname.reset();
			else {
				if (!v.is_string() || v.get<std::string>().size() > 100 || !clean_text(v.get<std::string>())) bad("\"hostname\" must be text of at most 100 characters");
				next.hostname = v.get<std::string>();
			}
		} else if (f == "environment") {
			if (remove) next.environment.reset();
			else {
				if (!v.is_string() || !kEnvironments.count(v.get<std::string>())) bad("\"environment\" must be one of prod, staging, test, dev");
				next.environment = v.get<std::string>();
			}
		} else if (f == "status") {
			if (remove) next.status.reset();
			else {
				if (!v.is_string() || !kStatuses.count(v.get<std::string>())) bad("\"status\" must be one of ignored, false_positive, confirmed");
				next.status = v.get<std::string>();
			}
		} else if (f == "note") {
			if (remove) next.note.reset();
			else {
				if (!v.is_string() || v.get<std::string>().size() > 2000) bad("\"note\" must be text of at most 2000 characters");
				const std::string& s = v.get<std::string>();
				if (!std::all_of(s.begin(), s.end(), [](unsigned char c) { return c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7f); })) bad("\"note\" has control characters");
				next.note = s;
			}
		} else if (f == "priority") {
			if (remove) next.priority.reset();
			else {
				if (!v.is_number_integer() || v.get<long long>() < 0 || v.get<long long>() > 100) bad("\"priority\" must be a whole number from 0 to 100");
				next.priority = v.get<int>();
			}
		} else if (f == "tags") {
			next.tags.clear();
			if (!remove) {
				if (!v.is_array() || v.size() > 10) bad("\"tags\" must be a list of at most 10 tags");
				for (const auto& t : v) {
					std::string s = t.is_string() ? t.get<std::string>() : "";
					std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
					if (s.empty() || s.size() > 32 || !std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::islower(c) || std::isdigit(c) || c == '-' || c == '_' || c == '.'; }))
						bad("a tag has 1 to 32 characters: letters, digits, '.', '_' and '-'");
					if (std::find(next.tags.begin(), next.tags.end(), s) == next.tags.end()) next.tags.push_back(s);
				}
			}
		} else {
			bad("unknown field \"" + f.substr(0, 40) + "\" (hostname, environment, status, note, priority, tags)");
		}
	}
	record = std::move(next);
}

// ------------------------------------------------------------------ file store

namespace {

class FileLock {
public:
	explicit FileLock(const std::filesystem::path& dir) {
		fd_ = ::open((dir / ".lock").c_str(), O_CREAT | O_RDWR, 0600);
		if (fd_ < 0 || ::flock(fd_, LOCK_EX) != 0) {
			if (fd_ >= 0) ::close(fd_);
			throw std::runtime_error("cannot lock the edits directory");
		}
	}
	~FileLock() {
		::flock(fd_, LOCK_UN);
		::close(fd_);
	}
	FileLock(const FileLock&) = delete;
	FileLock& operator=(const FileLock&) = delete;

private:
	int fd_;
};

using Entries = std::vector<std::pair<EditKey, EditRecord>>;

class FileEditStore : public EditStore {
public:
	explicit FileEditStore(std::filesystem::path dir) : dir_(std::move(dir)) {
		std::error_code ec;
		std::filesystem::create_directories(dir_, ec);
		if (ec || !std::filesystem::is_directory(dir_)) throw std::runtime_error("cannot use the edits directory " + dir_.string());
	}

	Entries all() override {
		std::lock_guard<std::mutex> l(m_);
		return read();
	}

	std::optional<EditRecord> get(const EditKey& key) override {
		std::lock_guard<std::mutex> l(m_);
		for (auto& [k, r] : read())
			if (k == key) return r;
		return std::nullopt;
	}

	EditResult apply(const EditKey& key, const nlohmann::json& changes, const std::string& user) override {
		std::lock_guard<std::mutex> l(m_);
		FileLock lock(dir_);
		Entries entries = read();
		auto it = std::find_if(entries.begin(), entries.end(), [&](const auto& e) { return e.first == key; });
		EditResult result;
		EditRecord record;
		if (it != entries.end()) record = result.before = it->second;
		apply_changes(key, changes, record);
		record.edited_by = user;
		record.edited_at = now_text();
		if (record.empty()) {
			if (it != entries.end()) entries.erase(it);
		} else {
			result.after = record;
			if (it != entries.end()) it->second = record;
			else entries.emplace_back(key, record);
		}
		write(entries);
		return result;
	}

	bool clear(const EditKey& key) override {
		std::lock_guard<std::mutex> l(m_);
		FileLock lock(dir_);
		Entries entries = read();
		auto it = std::find_if(entries.begin(), entries.end(), [&](const auto& e) { return e.first == key; });
		if (it == entries.end()) return false;
		entries.erase(it);
		write(entries);
		return true;
	}

private:
	Entries read() const {
		Entries out;
		std::ifstream f(dir_ / "edits.json");
		if (!f) return out;
		std::stringstream text;
		text << f.rdbuf();
		const Json j = Json::parse(text.str(), nullptr, false);
		if (j.is_discarded() || !j.is_object() || !j.contains("edits") || !j["edits"].is_array())
			throw std::runtime_error("edits.json is damaged; fix or remove it (it is never overwritten automatically)");
		for (const Json& e : j["edits"]) {
			EditKey k;
			k.ip = e.value("ip", std::string());
			k.port = static_cast<uint16_t>(e.value("port", 0));
			k.protocol = e.value("protocol", std::string());
			out.emplace_back(std::move(k), record_from_json(e));
		}
		return out;
	}

	void write(const Entries& entries) const {
		Json j = {{"format", 1}, {"edits", Json::array()}};
		for (const auto& [k, r] : entries) {
			Json e = to_json(r);
			e["ip"] = k.ip;
			e["port"] = k.port;
			e["protocol"] = k.protocol;
			j["edits"].push_back(std::move(e));
		}
		const std::string text = j.dump(2) + "\n";
		const auto tmp = dir_ / ("edits.json.tmp." + std::to_string(::getpid()));
		const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0) throw std::runtime_error("cannot write the edits file");
		size_t done = 0;
		while (done < text.size()) {
			const ssize_t n = ::write(fd, text.data() + done, text.size() - done);
			if (n <= 0) {
				::close(fd);
				::unlink(tmp.c_str());
				throw std::runtime_error("cannot write the edits file");
			}
			done += static_cast<size_t>(n);
		}
		::fsync(fd);
		::close(fd);
		std::error_code ec;
		std::filesystem::rename(tmp, dir_ / "edits.json", ec);
		if (ec) {
			::unlink(tmp.c_str());
			throw std::runtime_error("cannot replace the edits file");
		}
	}

	std::filesystem::path dir_;
	std::mutex m_;
};

} // namespace

std::unique_ptr<EditStore> make_file_edit_store(const std::filesystem::path& dir) { return std::make_unique<FileEditStore>(dir); }

} // namespace proculus
