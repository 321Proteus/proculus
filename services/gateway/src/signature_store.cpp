#include "signature_store.hpp"

#include <fstream>
#include <sstream>

#include <sys/stat.h>

#include "proculus/sig/builtin.hpp"
#include "proculus/sig/engine.hpp"

namespace proculus {

namespace {

constexpr size_t kMaxText = 48 * 1024;
constexpr size_t kMaxReported = 30;

Json signature_json(const sig::Signature& s) {
	return {{"id", s.id}, {"name", s.name}, {"category", sig::to_string(s.category)}, {"interest", s.interest}, {"tags", s.tags}, {"description", s.description},
		{"threshold", s.threshold}, {"signals", s.signals.size()}, {"enabled", s.enabled}, {"builtin", s.builtin}, {"source", s.source}};
}

Json clipped(const std::vector<std::string>& v) {
	Json a = Json::array();
	for (size_t i = 0; i < v.size() && i < kMaxReported; i++) a.push_back(v[i].substr(0, 400));
	if (v.size() > kMaxReported) a.push_back("... and " + std::to_string(v.size() - kMaxReported) + " more");
	return a;
}

bool blank(const std::string& s) { return s.find_first_not_of(" \t\r\n") == std::string::npos; }

} // namespace

SignatureStore::SignatureStore(std::filesystem::path file) : file_(std::move(file)), builtin_(sig::builtin_signatures()) {}

std::string SignatureStore::text() const {
	std::lock_guard<std::mutex> l(m_);
	if (file_.empty()) return "";
	std::ifstream in(file_, std::ios::binary);
	if (!in) return "";
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str();
}

Json SignatureStore::check(const std::string& text) const {
	if (text.size() > kMaxText) throw ApiError(400, "the signatures are too long (at most " + std::to_string(kMaxText / 1024) + " KiB)");
	sig::SignatureSet set;
	{
		std::lock_guard<std::mutex> l(m_);
		set = builtin_; // custom signatures are read on top of the built-in ones, as the runner does: they can override or disable them
	}
	std::vector<std::string> errors, warnings, example_failures;
	size_t loaded = 0;
	if (!blank(text)) {
		const sig::LoadResult r = set.add_json(text, "custom");
		loaded = r.loaded;
		for (const sig::Diagnostic& d : r.diagnostics) (d.level == sig::Diagnostic::Level::Error ? errors : warnings).push_back(sig::describe(d));
		for (const sig::Signature& s : set.all())
			if (s.source == "custom")
				for (const std::string& f : sig::run_examples(s)) example_failures.push_back(s.id + ": " + f);
	}
	return {{"ok", errors.empty() && example_failures.empty()}, {"loaded", loaded}, {"errors", clipped(errors)}, {"warnings", clipped(warnings)}, {"examples", clipped(example_failures)}};
}

Json SignatureStore::save(const std::string& text) {
	const Json c = check(text);
	if (!c["ok"].get<bool>()) {
		std::string why;
		for (const Json& e : c["errors"]) why += (why.empty() ? "" : "; ") + e.get<std::string>();
		for (const Json& e : c["examples"]) why += (why.empty() ? "" : "; ") + std::string("example failed: ") + e.get<std::string>();
		throw ApiError(400, "not saved: " + why.substr(0, 600));
	}
	std::lock_guard<std::mutex> l(m_);
	if (!file_.empty()) {
		try {
			if (blank(text)) {
				std::error_code ec;
				std::filesystem::remove(file_, ec);
			} else {
				std::filesystem::create_directories(file_.parent_path());
				const std::filesystem::path tmp = file_.string() + ".tmp";
				{
					std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
					if (!out) throw std::runtime_error("cannot write " + tmp.string());
					::chmod(tmp.c_str(), 0600);
					out << text;
					out.flush();
					if (!out) throw std::runtime_error("cannot write " + tmp.string());
				}
				std::filesystem::rename(tmp, file_);
			}
		} catch (const std::exception& e) {
			throw ApiError(500, std::string("the signatures could not be saved: ") + e.what());
		}
	}
	return c;
}

Json SignatureStore::list() const {
	sig::SignatureSet set;
	{
		std::lock_guard<std::mutex> l(m_);
		set = builtin_;
	}
	const std::string custom = text();
	Json problems = Json::array();
	if (!blank(custom)) {
		const sig::LoadResult r = set.add_json(custom, "custom");
		for (const sig::Diagnostic& d : r.diagnostics)
			if (d.level == sig::Diagnostic::Level::Error) problems.push_back(sig::describe(d).substr(0, 400));
	}
	Json a = Json::array();
	for (const sig::Signature& s : set.all()) a.push_back(signature_json(s));
	return {{"text", custom}, {"signatures", a}, {"problems", problems}, {"persistent", !file_.empty()}};
}

} // namespace proculus
