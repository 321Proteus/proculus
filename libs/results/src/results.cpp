#include "proculus/results/results.hpp"

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace proculus {

namespace {

namespace fs = std::filesystem;

std::string file_name(int64_t id) {
	char buf[40];
	std::snprintf(buf, sizeof buf, "run-%06lld.json", static_cast<long long>(id));
	return buf;
}

// "run-000012.json" -> 12; -1 if the name is not one of ours.
int64_t id_from_name(const std::string& name) {
	if (name.size() < 15 || name.compare(0, 4, "run-") != 0 || name.compare(name.size() - 5, 5, ".json") != 0) return -1;
	const std::string digits = name.substr(4, name.size() - 9);
	if (digits.size() < 6 || digits.size() > 15 || digits.find_first_not_of("0123456789") != std::string::npos) return -1;
	return std::stoll(digits);
}

const Json& need(const Json& obj, const char* key) {
	auto it = obj.find(key);
	if (it == obj.end()) throw FormatError(std::string("missing field \"") + key + "\"");
	return *it;
}

std::string str(const Json& obj, const char* key, bool required) {
	auto it = obj.find(key);
	if (it == obj.end()) {
		if (required) throw FormatError(std::string("missing field \"") + key + "\"");
		return "";
	}
	if (!it->is_string()) throw FormatError(std::string("field \"") + key + "\" must be a string");
	return it->get<std::string>();
}

int64_t integer(const Json& obj, const char* key, int64_t lo, int64_t hi) {
	const Json& v = need(obj, key);
	if (!v.is_number_integer()) throw FormatError(std::string("field \"") + key + "\" must be a whole number");
	int64_t n;
	if (v.is_number_unsigned()) {
		const uint64_t u = v.get<uint64_t>();
		if (u > static_cast<uint64_t>(INT64_MAX)) throw FormatError(std::string("field \"") + key + "\" is out of range");
		n = static_cast<int64_t>(u);
	} else {
		n = v.get<int64_t>();
	}
	if (n < lo || n > hi) throw FormatError(std::string("field \"") + key + "\" is out of range");
	return n;
}

bool boolean(const Json& obj, const char* key) {
	auto it = obj.find(key);
	if (it == obj.end()) return false;
	if (!it->is_boolean()) throw FormatError(std::string("field \"") + key + "\" must be true or false");
	return it->get<bool>();
}

std::vector<std::string> strings(const Json& obj, const char* key) {
	std::vector<std::string> out;
	auto it = obj.find(key);
	if (it == obj.end()) return out;
	if (!it->is_array()) throw FormatError(std::string("field \"") + key + "\" must be an array");
	for (const Json& e : *it) {
		if (!e.is_string()) throw FormatError(std::string("\"") + key + "\" must hold strings");
		out.push_back(e.get<std::string>());
	}
	return out;
}

int optional_int(const Json& obj, const char* key, int lo, int hi) {
	if (!obj.contains(key)) return 0;
	return static_cast<int>(integer(obj, key, lo, hi));
}

double number(const Json& obj, const char* key, double lo, double hi) {
	auto it = obj.find(key);
	if (it == obj.end()) return 0;
	if (!it->is_number()) throw FormatError(std::string("field \"") + key + "\" must be a number");
	const double d = it->get<double>();
	if (!(d >= lo && d <= hi)) throw FormatError(std::string("field \"") + key + "\" is out of range");
	return d;
}

const Json& object_at(const Json& v, const char* what) {
	if (!v.is_object()) throw FormatError(std::string(what) + " must be a JSON object");
	return v;
}

} // namespace

Json web_to_json(const WebRecord& w) {
	Json j = Json::object();
	j["url"] = w.url;
	j["status"] = w.status;
	j["title"] = w.title;
	j["server"] = w.server;
	j["content_type"] = w.content_type;
	Json headers = Json::array();
	for (const auto& [n, v] : w.headers) headers.push_back({ { "name", n }, { "value", v } });
	j["headers"] = std::move(headers);
	Json cookies = Json::array();
	for (const CookieRecord& c : w.cookies)
		cookies.push_back({ { "name", c.name }, { "secure", c.secure }, { "http_only", c.http_only }, { "same_site", c.same_site } });
	j["cookies"] = std::move(cookies);
	j["redirects"] = w.redirects;
	if (w.tls) {
		const TlsRecord& t = *w.tls;
		Json tj = { { "version", t.version }, { "cipher", t.cipher }, { "subject", t.subject }, { "issuer", t.issuer }, { "not_before", t.not_before },
			{ "not_after", t.not_after }, { "sha256", t.sha256 }, { "key_type", t.key_type }, { "key_bits", t.key_bits }, { "self_signed", t.self_signed },
			{ "expired", t.expired }, { "not_yet_valid", t.not_yet_valid }, { "san", t.san } };
		if (t.hostname_match) tj["hostname_match"] = *t.hostname_match;
		j["tls"] = std::move(tj);
	}
	if (w.favicon_hash) j["favicon_hash"] = *w.favicon_hash;
	Json dets = Json::array();
	for (const DetectionRecord& d : w.detections) {
		Json dj = { { "id", d.id }, { "name", d.name }, { "category", d.category }, { "confidence", d.confidence }, { "interest", d.interest },
			{ "version", d.version }, { "builtin", d.builtin }, { "tags", d.tags }, { "evidence", d.evidence } };
		dets.push_back(std::move(dj));
	}
	j["detections"] = std::move(dets);
	return j;
}

WebRecord web_from_json(const Json& v) {
	object_at(v, "\"web\"");
	WebRecord w;
	w.url = str(v, "url", false);
	w.status = optional_int(v, "status", 0, 999);
	w.title = str(v, "title", false);
	w.server = str(v, "server", false);
	w.content_type = str(v, "content_type", false);
	if (auto it = v.find("headers"); it != v.end()) {
		if (!it->is_array()) throw FormatError("\"headers\" must be an array");
		for (const Json& h : *it) w.headers.emplace_back(str(object_at(h, "a header"), "name", true), str(h, "value", false));
	}
	if (auto it = v.find("cookies"); it != v.end()) {
		if (!it->is_array()) throw FormatError("\"cookies\" must be an array");
		for (const Json& cj : *it) {
			object_at(cj, "a cookie");
			CookieRecord c;
			c.name = str(cj, "name", true);
			c.secure = boolean(cj, "secure");
			c.http_only = boolean(cj, "http_only");
			c.same_site = str(cj, "same_site", false);
			w.cookies.push_back(std::move(c));
		}
	}
	w.redirects = strings(v, "redirects");
	if (auto it = v.find("tls"); it != v.end()) {
		object_at(*it, "\"tls\"");
		TlsRecord t;
		t.version = str(*it, "version", false);
		t.cipher = str(*it, "cipher", false);
		t.subject = str(*it, "subject", false);
		t.issuer = str(*it, "issuer", false);
		t.not_before = str(*it, "not_before", false);
		t.not_after = str(*it, "not_after", false);
		t.sha256 = str(*it, "sha256", false);
		t.key_type = str(*it, "key_type", false);
		t.key_bits = optional_int(*it, "key_bits", 0, 100000);
		t.self_signed = boolean(*it, "self_signed");
		t.expired = boolean(*it, "expired");
		t.not_yet_valid = boolean(*it, "not_yet_valid");
		if (it->contains("hostname_match")) t.hostname_match = boolean(*it, "hostname_match");
		t.san = strings(*it, "san");
		w.tls = std::move(t);
	}
	if (v.contains("favicon_hash")) w.favicon_hash = static_cast<int32_t>(integer(v, "favicon_hash", INT32_MIN, INT32_MAX));
	if (auto it = v.find("detections"); it != v.end()) {
		if (!it->is_array()) throw FormatError("\"detections\" must be an array");
		for (const Json& dj : *it) {
			object_at(dj, "a detection");
			DetectionRecord d;
			d.id = str(dj, "id", true);
			d.name = str(dj, "name", false);
			d.category = str(dj, "category", false);
			d.confidence = number(dj, "confidence", 0, 1);
			d.interest = optional_int(dj, "interest", 0, 5);
			d.version = str(dj, "version", false);
			d.builtin = boolean(dj, "builtin");
			d.tags = strings(dj, "tags");
			d.evidence = strings(dj, "evidence");
			w.detections.push_back(std::move(d));
		}
	}
	return w;
}

RunSummary summarize(const RunRecord& run) {
	RunSummary s;
	s.id = run.id;
	s.source = run.source;
	s.started = run.started;
	s.finished = run.finished;
	s.hosts = run.hosts.size();
	for (const HostRecord& h : run.hosts) s.services += h.services.size();
	return s;
}

std::string dump_json(const Json& j, int indent) {
	return j.dump(indent, ' ', false, Json::error_handler_t::replace);
}

Json run_to_json(const RunRecord& run) {
	Json v = Json::object();
	v["format"] = kFormatVersion;
	v["id"] = run.id;
	v["source"] = run.source;
	v["started"] = run.started;
	v["finished"] = run.finished;
	v["addresses_scanned"] = run.addresses_scanned;
	v["chunks"] = run.chunks;
	v["pauses"] = run.pauses;
	v["cancelled_chunks"] = run.cancelled_chunks;

	Json hosts = Json::array();
	for (const HostRecord& h : run.hosts) {
		Json hv = Json::object();
		hv["ip"] = h.ip;
		hv["hostname"] = h.hostname;
		Json services = Json::array();
		for (const ServiceRecord& s : h.services) {
			Json sv = Json::object();
			sv["port"] = static_cast<int>(s.port);
			sv["protocol"] = s.protocol;
			sv["state"] = s.state;
			sv["name"] = s.name;
			sv["product"] = s.product;
			sv["version"] = s.version;
			sv["extrainfo"] = s.extrainfo;
			sv["confidence"] = s.confidence;
			if (s.web) sv["web"] = web_to_json(*s.web);
			services.push_back(std::move(sv));
		}
		hv["services"] = std::move(services);
		hosts.push_back(std::move(hv));
	}
	v["hosts"] = std::move(hosts);
	return v;
}

RunRecord run_from_json(const Json& v) {
	if (!v.is_object()) throw FormatError("a run must be a JSON object");
	const int64_t format = integer(v, "format", 0, 1000000);
	if (format > kFormatVersion)
		throw FormatError("run uses format " + std::to_string(format) + ", this build understands up to " +
			std::to_string(kFormatVersion));

	RunRecord run;
	run.id = integer(v, "id", 0, INT64_MAX / 2);
	run.source = str(v, "source", true);
	run.started = str(v, "started", true);
	run.finished = str(v, "finished", true);
	run.addresses_scanned = static_cast<uint64_t>(integer(v, "addresses_scanned", 0, INT64_MAX / 2));
	run.chunks = static_cast<int>(integer(v, "chunks", 0, 1000000000));
	run.pauses = static_cast<int>(integer(v, "pauses", 0, 1000000000));
	run.cancelled_chunks = static_cast<int>(integer(v, "cancelled_chunks", 0, 1000000000));

	const Json& hosts = need(v, "hosts");
	if (!hosts.is_array()) throw FormatError("\"hosts\" must be an array");
	for (const Json& hv : hosts) {
		if (!hv.is_object()) throw FormatError("a host must be a JSON object");
		HostRecord h;
		h.ip = str(hv, "ip", true);
		h.hostname = str(hv, "hostname", false);
		const Json& services = need(hv, "services");
		if (!services.is_array()) throw FormatError("\"services\" must be an array");
		for (const Json& sv : services) {
			if (!sv.is_object()) throw FormatError("a service must be a JSON object");
			ServiceRecord s;
			s.port = static_cast<uint16_t>(integer(sv, "port", 1, 65535));
			s.protocol = str(sv, "protocol", true);
			s.state = str(sv, "state", true);
			s.name = str(sv, "name", false);
			s.product = str(sv, "product", false);
			s.version = str(sv, "version", false);
			s.extrainfo = str(sv, "extrainfo", false);
			s.confidence = static_cast<int>(integer(sv, "confidence", 0, 10));
			if (auto it = sv.find("web"); it != sv.end()) s.web = web_from_json(*it);
			h.services.push_back(std::move(s));
		}
		run.hosts.push_back(std::move(h));
	}
	return run;
}

// -------------------------------------------------------- FileResultStore

FileResultStore::FileResultStore(fs::path dir) : dir_(std::move(dir)) {}

fs::path FileResultStore::path_for(int64_t id) const { return dir_ / file_name(id); }

std::vector<int64_t> FileResultStore::ids() const {
	std::vector<int64_t> out;
	std::error_code ec;
	if (!fs::is_directory(dir_, ec)) return out;
	for (const auto& e : fs::directory_iterator(dir_, ec)) {
		if (!e.is_regular_file()) continue; // also skips symlinks to elsewhere
		const int64_t id = id_from_name(e.path().filename().string());
		if (id >= 0) out.push_back(id);
	}
	std::sort(out.begin(), out.end());
	return out;
}

int64_t FileResultStore::save(RunRecord run) {
	std::error_code ec;
	fs::create_directories(dir_, ec);
	if (!fs::is_directory(dir_)) throw std::runtime_error("cannot create results directory " + dir_.string());

	const auto existing = ids();
	int64_t id = existing.empty() ? 1 : existing.back() + 1;

	// Write the document once under a private temporary name...
	static std::atomic<uint64_t> counter{0}; // unique per call, so threads of one process do not share a file
	const fs::path tmp = dir_ / (".tmp-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
	// ...but the id is part of the content, so render it per attempt.
	for (int attempt = 0; attempt < 1000; attempt++, id++) {
		run.id = id;
		{
			std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
			if (!f) throw std::runtime_error("cannot write " + tmp.string());
			f << dump_json(run_to_json(run), 2) << "\n";
			f.flush();
			if (!f) {
				fs::remove(tmp, ec);
				throw std::runtime_error("failed writing " + tmp.string());
			}
		}
		// link() fails if the target exists, so a concurrent writer that picked the
		// same id makes us try the next one instead of overwriting its run.
		if (::link(tmp.c_str(), path_for(id).c_str()) == 0) {
			fs::remove(tmp, ec);
			return id;
		}
		if (errno != EEXIST) {
			fs::remove(tmp, ec);
			throw std::runtime_error("cannot store run " + std::to_string(id) + ": " + std::strerror(errno));
		}
	}
	fs::remove(tmp, ec);
	throw std::runtime_error("could not find a free run id");
}

std::optional<RunRecord> FileResultStore::load(int64_t id) const {
	if (id < 0) return std::nullopt;
	std::ifstream f(path_for(id), std::ios::binary);
	if (!f) return std::nullopt;
	std::ostringstream ss;
	ss << f.rdbuf();
	RunRecord run;
	try {
		run = run_from_json(Json::parse(ss.str()));
	} catch (const Json::exception& e) {
		throw FormatError(path_for(id).filename().string() + ": not valid JSON: " + e.what());
	} catch (const FormatError& e) {
		throw FormatError(path_for(id).filename().string() + ": " + e.what());
	}
	if (run.id != id) throw FormatError(path_for(id).filename().string() + ": id inside the file does not match its name");
	return run;
}

std::vector<RunSummary> FileResultStore::list() const {
	std::vector<RunSummary> out;
	for (int64_t id : ids()) {
		if (auto run = load(id)) out.push_back(summarize(*run));
	}
	return out;
}

} // namespace proculus
