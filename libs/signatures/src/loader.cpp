#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

#include "proculus/sig/evidence_json.hpp"
#include "proculus/sig/signature.hpp"

namespace proculus::sig {

using Json = nlohmann::json;

const char* to_string(Category c) {
	switch (c) {
	case Category::Cms: return "cms";
	case Category::Framework: return "framework";
	case Category::Server: return "server";
	case Category::Iot: return "iot";
	case Category::Staging: return "staging";
	case Category::Admin: return "admin";
	case Category::Other: return "other";
	}
	return "other";
}

std::optional<Category> parse_category(const std::string& name) {
	for (Category c : {Category::Cms, Category::Framework, Category::Server, Category::Iot, Category::Staging, Category::Admin, Category::Other})
		if (name == to_string(c)) return c;
	return std::nullopt;
}

size_t LoadResult::errors() const {
	return static_cast<size_t>(std::count_if(diagnostics.begin(), diagnostics.end(), [](const Diagnostic& d) { return d.level == Diagnostic::Level::Error; }));
}
size_t LoadResult::warnings() const { return diagnostics.size() - errors(); }

std::string describe(const Diagnostic& d) {
	std::string out = d.level == Diagnostic::Level::Error ? "error: " : "warning: ";
	out += d.source;
	if (!d.signature.empty()) out += ": " + d.signature;
	if (!d.where.empty()) out += ": " + d.where;
	return out + ": " + d.message;
}

namespace {

constexpr size_t kMaxDepth = 6;
constexpr size_t kMaxLeaves = 40;
constexpr size_t kMaxSignals = 20;
constexpr size_t kMaxExamples = 20;
constexpr size_t kMaxAlternatives = 20;
constexpr size_t kMaxFileBytes = 4 << 20;

// ------------------------------------------------------------------ context

struct Ctx {
	LoadResult& result;
	const std::string& source;
	std::string signature;

	void error(const std::string& where, const std::string& message) {
		result.diagnostics.push_back({Diagnostic::Level::Error, source, signature, where, message});
		failed = true;
	}
	void warn(const std::string& where, const std::string& message) {
		result.diagnostics.push_back({Diagnostic::Level::Warning, source, signature, where, message});
	}
	bool failed = false; // an error was found in the signature being parsed
};

size_t edit_distance(const std::string& a, const std::string& b) {
	std::vector<size_t> prev(b.size() + 1), cur(b.size() + 1);
	for (size_t j = 0; j <= b.size(); j++) prev[j] = j;
	for (size_t i = 1; i <= a.size(); i++) {
		cur[0] = i;
		for (size_t j = 1; j <= b.size(); j++)
			cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1)});
		prev.swap(cur);
	}
	return prev[b.size()];
}

// Rejects keys that are not in `allowed`, with a hint for likely typos.
bool check_keys(Ctx& ctx, const Json& obj, const std::string& where, const std::vector<std::string>& allowed) {
	bool ok = true;
	for (auto it = obj.begin(); it != obj.end(); ++it) {
		if (std::find(allowed.begin(), allowed.end(), it.key()) != allowed.end()) continue;
		std::string hint;
		size_t best = 3;
		for (const std::string& a : allowed) {
			const size_t d = edit_distance(it.key(), a);
			if (d < best) {
				best = d;
				hint = " (did you mean \"" + a + "\"?)";
			}
		}
		ctx.error(where.empty() ? it.key() : where + "." + it.key(), "unknown key \"" + it.key() + "\"" + hint);
		ok = false;
	}
	return ok;
}

bool is_string(const Json& j) { return j.is_string(); }

std::string at(const std::string& base, size_t index) { return base + "[" + std::to_string(index) + "]"; }
std::string at(const std::string& base, const std::string& key) { return base.empty() ? key : base + "." + key; }

bool valid_id(const std::string& id) {
	if (id.empty() || id.size() > 64) return false;
	if (!(std::islower(static_cast<unsigned char>(id[0])) || std::isdigit(static_cast<unsigned char>(id[0])))) return false;
	for (unsigned char c : id)
		if (!(std::islower(c) || std::isdigit(c) || c == '.' || c == '_' || c == '-')) return false;
	return true;
}

bool printable_text(const std::string& s) {
	for (unsigned char c : s)
		if (c < 0x20 || c == 0x7f) return false;
	return true;
}

// ------------------------------------------------------------------- leaves

// Reads a string or a non-empty array of strings.
bool read_strings(Ctx& ctx, const Json& v, const std::string& where, std::vector<std::string>& out) {
	auto one = [&](const Json& e, const std::string& w) {
		if (!e.is_string()) {
			ctx.error(w, "expected a string");
			return false;
		}
		const std::string s = e.get<std::string>();
		if (s.empty()) {
			ctx.error(w, "empty string");
			return false;
		}
		if (s.size() > 300) {
			ctx.error(w, "longer than 300 characters");
			return false;
		}
		out.push_back(s);
		return true;
	};
	if (v.is_string()) return one(v, where);
	if (!v.is_array() || v.empty()) {
		ctx.error(where, "expected a string or a non-empty list of strings");
		return false;
	}
	if (v.size() > kMaxAlternatives) {
		ctx.error(where, "more than " + std::to_string(kMaxAlternatives) + " alternatives");
		return false;
	}
	bool ok = true;
	for (size_t i = 0; i < v.size(); i++) ok &= one(v[i], at(where, i));
	return ok;
}

bool read_numbers(Ctx& ctx, const Json& v, const std::string& where, std::vector<double>& out) {
	auto one = [&](const Json& e, const std::string& w) {
		if (!e.is_number()) {
			ctx.error(w, "expected a number");
			return false;
		}
		out.push_back(e.get<double>());
		return true;
	};
	if (v.is_number()) return one(v, where);
	if (!v.is_array() || v.empty()) {
		ctx.error(where, "expected a number or a non-empty list of numbers");
		return false;
	}
	if (v.size() > kMaxAlternatives) {
		ctx.error(where, "more than " + std::to_string(kMaxAlternatives) + " alternatives");
		return false;
	}
	bool ok = true;
	for (size_t i = 0; i < v.size(); i++) ok &= one(v[i], at(where, i));
	return ok;
}

bool parse_leaf(Ctx& ctx, const Json& j, const std::string& where, Condition& out) {
	if (!check_keys(ctx, j, where, {"field", "op", "value", "case_sensitive"})) return false;
	if (!j.contains("field") || !j["field"].is_string()) {
		ctx.error(at(where, "field"), "a matcher needs a \"field\" (a string)");
		return false;
	}
	out.kind = Condition::Kind::Leaf;
	Leaf& leaf = out.leaf;
	leaf.field = j["field"].get<std::string>();

	std::string field_error;
	const auto type = field_type(leaf.field, field_error);
	if (!type) {
		ctx.error(at(where, "field"), field_error);
		return false;
	}
	leaf.field_type = *type;

	if (!j.contains("op") || !j["op"].is_string()) {
		ctx.error(at(where, "op"), "a matcher needs an \"op\" (equals, contains, prefix, suffix, regex, exists, gt, ge, lt, le)");
		return false;
	}
	const auto op = parse_op(j["op"].get<std::string>());
	if (!op) {
		ctx.error(at(where, "op"), "unknown operator \"" + j["op"].get<std::string>() + "\"");
		return false;
	}
	leaf.op = *op;
	if (!op_allowed(leaf.field_type, leaf.op)) {
		ctx.error(at(where, "op"), std::string("operator \"") + to_string(leaf.op) + "\" does not apply to " + to_string(leaf.field_type) + " field \"" + leaf.field + "\"");
		return false;
	}
	if (j.contains("case_sensitive")) {
		if (!j["case_sensitive"].is_boolean()) {
			ctx.error(at(where, "case_sensitive"), "expected true or false");
			return false;
		}
		leaf.case_sensitive = j["case_sensitive"].get<bool>();
	}

	const std::string vw = at(where, "value");
	if (leaf.op == Op::Exists) {
		if (j.contains("value")) {
			if (!j["value"].is_boolean()) {
				ctx.error(vw, "for \"exists\" the value is true (must exist) or false (must be absent)");
				return false;
			}
			leaf.flag = j["value"].get<bool>();
		}
		return true;
	}
	if (!j.contains("value")) {
		ctx.error(vw, "a matcher needs a \"value\"");
		return false;
	}
	const Json& v = j["value"];

	switch (leaf.field_type) {
	case FieldType::Bool:
		if (!v.is_boolean()) {
			ctx.error(vw, "expected true or false");
			return false;
		}
		leaf.flag = v.get<bool>();
		return true;
	case FieldType::Number:
		if (!read_numbers(ctx, v, vw, leaf.numbers)) return false;
		if (leaf.op != Op::Equals && leaf.numbers.size() != 1) {
			ctx.error(vw, std::string("\"") + to_string(leaf.op) + "\" compares with a single number");
			return false;
		}
		return true;
	case FieldType::String:
	case FieldType::StringList: {
		if (!read_strings(ctx, v, vw, leaf.strings)) return false;
		if (leaf.op == Op::Regex) {
			bool ok = true;
			for (size_t i = 0; i < leaf.strings.size(); i++) {
				std::string error;
				auto re = Regex::compile(leaf.strings[i], !leaf.case_sensitive, error);
				if (!re) {
					ctx.error(v.is_array() ? at(vw, i) : vw, "bad regular expression: " + error);
					ok = false;
					continue;
				}
				leaf.regexes.push_back(std::move(re));
			}
			return ok;
		}
		for (const std::string& s : leaf.strings) {
			if (s.size() < 3 && (leaf.field == "body" || leaf.field == "title") && (leaf.op == Op::Contains))
				ctx.warn(vw, "\"" + s + "\" is very short and will match almost any " + leaf.field);
			std::string low = s;
			std::transform(low.begin(), low.end(), low.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			leaf.lowered_strings.push_back(std::move(low));
		}
		return true;
	}
	}
	return false;
}

bool parse_condition(Ctx& ctx, const Json& j, const std::string& where, size_t depth, size_t& leaves, Condition& out) {
	if (!j.is_object()) {
		ctx.error(where, "expected an object");
		return false;
	}
	if (depth > kMaxDepth) {
		ctx.error(where, "conditions are nested more than " + std::to_string(kMaxDepth) + " levels deep");
		return false;
	}
	const bool has_all = j.contains("all"), has_any = j.contains("any"), has_not = j.contains("not");
	const int groups = int(has_all) + int(has_any) + int(has_not);
	if (groups > 1) {
		ctx.error(where, "use only one of \"all\", \"any\" and \"not\" in one condition");
		return false;
	}
	if (groups == 0) {
		if (++leaves > kMaxLeaves) {
			ctx.error(where, "more than " + std::to_string(kMaxLeaves) + " matchers in one signature");
			return false;
		}
		return parse_leaf(ctx, j, where, out);
	}
	if (!check_keys(ctx, j, where, {"all", "any", "not"})) return false;

	if (has_not) {
		out.kind = Condition::Kind::Not;
		out.children.emplace_back();
		return parse_condition(ctx, j["not"], at(where, "not"), depth + 1, leaves, out.children[0]);
	}
	const char* key = has_all ? "all" : "any";
	const Json& list = j[key];
	if (!list.is_array() || list.empty()) {
		ctx.error(at(where, key), "expected a non-empty list of conditions");
		return false;
	}
	out.kind = has_all ? Condition::Kind::All : Condition::Kind::Any;
	bool ok = true;
	for (size_t i = 0; i < list.size(); i++) {
		out.children.emplace_back();
		ok &= parse_condition(ctx, list[i], at(at(where, key), i), depth + 1, leaves, out.children.back());
	}
	return ok;
}

void collect_paths(const Condition& c, std::set<std::string>& out) {
	if (c.kind == Condition::Kind::Leaf) {
		if (auto p = probe_path_of(c.leaf.field)) out.insert(*p);
		return;
	}
	for (const Condition& child : c.children) collect_paths(child, out);
}

std::set<std::string> signature_paths(const Signature& s) {
	std::set<std::string> paths;
	for (const Signal& sig : s.signals) collect_paths(sig.match, paths);
	if (s.exclude) collect_paths(*s.exclude, paths);
	if (s.version)
		if (auto p = probe_path_of(s.version->field)) paths.insert(*p);
	return paths;
}

// ----------------------------------------------------------------- evidence

bool parse_evidence(Ctx& ctx, const Json& j, const std::string& where, Evidence& out) {
	std::vector<EvidenceProblem> problems;
	if (evidence_from_json(j, out, problems)) return true;
	for (const auto& [field, message] : problems) ctx.error(field.empty() ? where : at(where, field), message);
	return false;
}

// --------------------------------------------------------------- signatures

bool read_text(Ctx& ctx, const Json& j, const std::string& key, const std::string& where, size_t min, size_t max, std::string& out) {
	if (!j.contains(key)) return true;
	if (!j[key].is_string()) {
		ctx.error(at(where, key), "expected a string");
		return false;
	}
	out = j[key].get<std::string>();
	if (out.size() < min || out.size() > max || !printable_text(out)) {
		ctx.error(at(where, key), "must be " + std::to_string(min) + " to " + std::to_string(max) + " printable characters");
		return false;
	}
	return true;
}

std::optional<Signature> parse_signature(Ctx& ctx, const Json& j, const std::string& where, bool builtin, const std::string& source, bool& override_builtin) {
	ctx.failed = false;
	override_builtin = false;
	if (!j.is_object()) {
		ctx.error(where, "a signature must be an object");
		return std::nullopt;
	}
	// the id first, so that every later message can name the signature
	if (j.contains("id") && j["id"].is_string()) ctx.signature = j["id"].get<std::string>();
	check_keys(ctx, j, where, {"id", "name", "category", "tags", "interest", "description", "references", "threshold", "signals", "exclude", "version",
				       "examples", "enabled", "override"});

	Signature s;
	s.builtin = builtin;
	s.source = source;
	if (!j.contains("id") || !j["id"].is_string() || !valid_id(ctx.signature)) {
		ctx.error(at(where, "id"), "needs an \"id\" of lowercase letters, digits, '.', '_' or '-' (at most 64 characters)");
	}
	s.id = ctx.signature;

	if (!j.contains("name")) ctx.error(at(where, "name"), "needs a \"name\"");
	else read_text(ctx, j, "name", where, 1, 100, s.name);

	if (!j.contains("category")) ctx.error(at(where, "category"), "needs a \"category\" (cms, framework, server, iot, staging, admin or other)");
	else if (!j["category"].is_string() || !parse_category(j["category"].get<std::string>()))
		ctx.error(at(where, "category"), "must be one of cms, framework, server, iot, staging, admin, other");
	else s.category = *parse_category(j["category"].get<std::string>());

	read_text(ctx, j, "description", where, 0, 500, s.description);

	if (j.contains("tags")) {
		const Json& t = j["tags"];
		if (!t.is_array() || t.size() > 10 || !std::all_of(t.begin(), t.end(), is_string)) ctx.error(at(where, "tags"), "expected a list of at most 10 strings");
		else
			for (size_t i = 0; i < t.size(); i++) {
				const std::string tag = t[i].get<std::string>();
				if (!valid_id(tag) || tag.size() > 32) ctx.error(at(at(where, "tags"), i), "tags are lowercase letters, digits, '.', '_' or '-' (at most 32 characters)");
				else s.tags.push_back(tag);
			}
	}
	if (j.contains("references")) {
		const Json& r = j["references"];
		if (!r.is_array() || r.size() > 10 || !std::all_of(r.begin(), r.end(), is_string)) ctx.error(at(where, "references"), "expected a list of at most 10 URLs");
		else
			for (size_t i = 0; i < r.size(); i++) {
				const std::string url = r[i].get<std::string>();
				if ((url.compare(0, 7, "http://") != 0 && url.compare(0, 8, "https://") != 0) || url.size() > 300 || !printable_text(url))
					ctx.error(at(at(where, "references"), i), "expected an http:// or https:// URL");
				else s.references.push_back(url);
			}
	}
	if (j.contains("interest")) {
		if (!j["interest"].is_number_integer() || j["interest"].get<int>() < 0 || j["interest"].get<int>() > 5) ctx.error(at(where, "interest"), "must be a whole number from 0 to 5");
		else s.interest = j["interest"].get<int>();
	}
	if (j.contains("threshold")) {
		if (!j["threshold"].is_number() || j["threshold"].get<double>() <= 0 || j["threshold"].get<double>() > 1) ctx.error(at(where, "threshold"), "must be a number above 0 and at most 1");
		else s.threshold = j["threshold"].get<double>();
	}
	if (j.contains("enabled")) {
		if (!j["enabled"].is_boolean()) ctx.error(at(where, "enabled"), "expected true or false");
		else s.enabled = j["enabled"].get<bool>();
	}
	if (j.contains("override")) {
		if (!j["override"].is_boolean()) ctx.error(at(where, "override"), "expected true or false");
		else override_builtin = j["override"].get<bool>();
	}

	// signals
	size_t leaves = 0;
	if (!j.contains("signals") || !j["signals"].is_array() || j["signals"].empty()) {
		ctx.error(at(where, "signals"), "needs a non-empty list of \"signals\"");
	} else if (j["signals"].size() > kMaxSignals) {
		ctx.error(at(where, "signals"), "more than " + std::to_string(kMaxSignals) + " signals");
	} else {
		const Json& list = j["signals"];
		for (size_t i = 0; i < list.size(); i++) {
			const std::string w = at(at(where, "signals"), i);
			if (!list[i].is_object()) {
				ctx.error(w, "a signal must be an object");
				continue;
			}
			check_keys(ctx, list[i], w, {"weight", "match", "required", "label"});
			Signal sg;
			if (!list[i].contains("weight") || !list[i]["weight"].is_number() || list[i]["weight"].get<double>() <= 0 || list[i]["weight"].get<double>() > 1)
				ctx.error(at(w, "weight"), "needs a \"weight\" above 0 and at most 1");
			else sg.weight = list[i]["weight"].get<double>();
			if (list[i].contains("required")) {
				if (!list[i]["required"].is_boolean()) ctx.error(at(w, "required"), "expected true or false");
				else sg.required = list[i]["required"].get<bool>();
			}
			read_text(ctx, list[i], "label", w, 0, 100, sg.label);
			if (!list[i].contains("match")) ctx.error(at(w, "match"), "a signal needs a \"match\" condition");
			else parse_condition(ctx, list[i]["match"], at(w, "match"), 0, leaves, sg.match);
			s.signals.push_back(std::move(sg));
		}
	}
	if (j.contains("exclude")) {
		Condition c;
		if (parse_condition(ctx, j["exclude"], at(where, "exclude"), 0, leaves, c)) s.exclude = std::move(c);
	}

	// version
	if (j.contains("version")) {
		const Json& v = j["version"];
		const std::string w = at(where, "version");
		if (!v.is_object()) ctx.error(w, "expected an object with \"field\" and \"regex\"");
		else {
			check_keys(ctx, v, w, {"field", "regex"});
			VersionRule rule;
			std::string field_error;
			if (!v.contains("field") || !v["field"].is_string()) ctx.error(at(w, "field"), "needs a \"field\"");
			else if (auto t = field_type(v["field"].get<std::string>(), field_error); !t) ctx.error(at(w, "field"), field_error);
			else if (*t != FieldType::String && *t != FieldType::StringList) ctx.error(at(w, "field"), "the version must be read from a text field");
			else {
				rule.field = v["field"].get<std::string>();
				rule.field_type = *t;
			}
			std::string error;
			if (!v.contains("regex") || !v["regex"].is_string()) ctx.error(at(w, "regex"), "needs a \"regex\" with one capture group");
			else if (auto re = Regex::compile(v["regex"].get<std::string>(), false, error); !re) ctx.error(at(w, "regex"), "bad regular expression: " + error);
			else if (re->group_count() < 1) ctx.error(at(w, "regex"), "needs a capture group, e.g. nginx/([0-9.]+)");
			else rule.regex = re;
			if (rule.regex && !rule.field.empty()) s.version = std::move(rule);
		}
	}

	// can it ever be reported?
	if (!ctx.failed) {
		double miss = 1.0;
		for (const Signal& sg : s.signals) miss *= 1.0 - sg.weight;
		if (1.0 - miss < s.threshold - 1e-9)
			ctx.error(at(where, "threshold"), "can never be reached: all signals together give only " + std::to_string(1.0 - miss).substr(0, 4) + " but the threshold is " + std::to_string(s.threshold).substr(0, 4));
	}

	// examples (parsed last: they need the field catalog only)
	if (j.contains("examples")) {
		const Json& ex = j["examples"];
		const std::string w = at(where, "examples");
		if (!ex.is_array() || ex.size() > kMaxExamples) ctx.error(w, "expected a list of at most " + std::to_string(kMaxExamples) + " examples");
		else
			for (size_t i = 0; i < ex.size(); i++) {
				const std::string ew = at(w, i);
				if (!ex[i].is_object()) {
					ctx.error(ew, "an example must be an object");
					continue;
				}
				check_keys(ctx, ex[i], ew, {"name", "evidence", "expect", "version"});
				Example e;
				read_text(ctx, ex[i], "name", ew, 0, 100, e.name);
				if (!ex[i].contains("evidence")) ctx.error(at(ew, "evidence"), "an example needs \"evidence\"");
				else parse_evidence(ctx, ex[i]["evidence"], at(ew, "evidence"), e.evidence);
				if (ex[i].contains("expect")) {
					const std::string x = ex[i]["expect"].is_string() ? ex[i]["expect"].get<std::string>() : "";
					if (x != "match" && x != "no-match") ctx.error(at(ew, "expect"), "must be \"match\" or \"no-match\"");
					e.expect_match = x != "no-match";
				}
				read_text(ctx, ex[i], "version", ew, 0, 64, e.expect_version);
				s.examples.push_back(std::move(e));
			}
	}

	if (ctx.failed) return std::nullopt;
	return s;
}

} // namespace

// ------------------------------------------------------------- SignatureSet

size_t SignatureSet::enabled_count() const {
	return static_cast<size_t>(std::count_if(signatures_.begin(), signatures_.end(), [](const Signature& s) { return s.enabled; }));
}

const Signature* SignatureSet::find(const std::string& id) const {
	for (const Signature& s : signatures_)
		if (s.id == id) return &s;
	return nullptr;
}

bool SignatureSet::set_enabled(const std::string& id, bool enabled) {
	for (Signature& s : signatures_)
		if (s.id == id) {
			s.enabled = enabled;
			return true;
		}
	return false;
}

std::vector<std::string> SignatureSet::required_paths(size_t limit) const {
	struct Use {
		int interest = 0; // the highest interest of any signature that wants the path
		size_t count = 0; // how many signatures want it
	};
	std::map<std::string, Use> uses;
	for (const Signature& s : signatures_) {
		if (!s.enabled) continue;
		for (const std::string& p : signature_paths(s)) {
			Use& u = uses[p];
			u.interest = std::max(u.interest, s.interest);
			u.count++;
		}
	}
	std::vector<std::pair<std::string, Use>> sorted(uses.begin(), uses.end()); // by name already
	std::stable_sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
		if (a.second.interest != b.second.interest) return a.second.interest > b.second.interest;
		return a.second.count > b.second.count;
	});
	std::vector<std::string> out;
	for (const auto& kv : sorted) {
		if (limit && out.size() >= limit) break;
		out.push_back(kv.first);
	}
	return out;
}

LoadResult SignatureSet::add_json(const std::string& text, const std::string& source, bool builtin, const LoadPolicy& policy) {
	LoadResult result;
	Ctx ctx{result, source, ""};

	Json doc;
	try {
		doc = Json::parse(text);
	} catch (const Json::exception& e) {
		ctx.error("", std::string("not valid JSON: ") + e.what());
		return result;
	}
	if (!doc.is_object()) {
		ctx.error("", "the top level must be an object with a \"signatures\" list");
		return result;
	}
	if (!check_keys(ctx, doc, "", {"format", "signatures", "disable"})) return result;
	if (doc.contains("format") && !(doc["format"].is_number_integer() && doc["format"].get<int>() == 1)) {
		ctx.error("format", "unsupported format (this version reads format 1)");
		return result;
	}
	if (!doc.contains("signatures") && !doc.contains("disable")) {
		ctx.error("signatures", "needs a \"signatures\" list (or a \"disable\" list)");
		return result;
	}

	std::vector<Signature> accepted;
	std::vector<bool> overrides;
	if (doc.contains("signatures")) {
		const Json& list = doc["signatures"];
		if (!list.is_array()) {
			ctx.error("signatures", "expected a list");
			return result;
		}
		if (list.size() > policy.max_signatures_per_source) {
			ctx.error("signatures", "more than " + std::to_string(policy.max_signatures_per_source) + " signatures in one file");
			return result;
		}
		std::set<std::string> seen;
		for (size_t i = 0; i < list.size(); i++) {
			ctx.signature.clear();
			bool override_builtin = false;
			auto sig = parse_signature(ctx, list[i], at("signatures", i), builtin, source, override_builtin);
			if (!sig) continue;
			if (!seen.insert(sig->id).second) {
				ctx.error(at("signatures", i) + ".id", "duplicate id in this file");
				continue;
			}
			if (const Signature* existing = find(sig->id)) {
				if (!(existing->builtin && !builtin && override_builtin)) {
					ctx.error(at("signatures", i) + ".id", existing->builtin
							? "id \"" + sig->id + "\" is a built-in signature; add \"override\": true to replace it, or use another id"
							: "id \"" + sig->id + "\" already defined in " + existing->source);
					continue;
				}
			}
			accepted.push_back(std::move(*sig));
			overrides.push_back(override_builtin);
		}
	}
	ctx.signature.clear();

	// A source may only ask the prober to look at so many extra paths.
	std::set<std::string> paths;
	for (const Signature& s : accepted)
		for (const std::string& p : signature_paths(s)) paths.insert(p);
	if (!builtin && paths.size() > policy.max_probe_paths) {
		ctx.error("", "asks the prober to fetch " + std::to_string(paths.size()) + " different paths; the limit for one file is " + std::to_string(policy.max_probe_paths) + " (nothing from this file was loaded)");
		return result;
	}

	for (size_t i = 0; i < accepted.size(); i++) {
		if (overrides[i]) {
			auto it = std::find_if(signatures_.begin(), signatures_.end(), [&](const Signature& s) { return s.id == accepted[i].id; });
			*it = std::move(accepted[i]);
		} else {
			signatures_.push_back(std::move(accepted[i]));
		}
		result.loaded++;
	}

	if (doc.contains("disable")) {
		const Json& d = doc["disable"];
		if (!d.is_array() || !std::all_of(d.begin(), d.end(), is_string)) {
			ctx.error("disable", "expected a list of signature ids");
		} else {
			for (size_t i = 0; i < d.size(); i++) {
				if (!set_enabled(d[i].get<std::string>(), false)) ctx.warn(at("disable", i), "no signature \"" + d[i].get<std::string>() + "\" to disable");
			}
		}
	}
	return result;
}

LoadResult SignatureSet::add_file(const std::filesystem::path& file, bool builtin, const LoadPolicy& policy) {
	std::error_code ec;
	const auto size = std::filesystem::file_size(file, ec);
	if (ec || !std::filesystem::is_regular_file(file)) {
		LoadResult r;
		r.diagnostics.push_back({Diagnostic::Level::Error, file.string(), "", "", "cannot read the file"});
		return r;
	}
	if (size > kMaxFileBytes) {
		LoadResult r;
		r.diagnostics.push_back({Diagnostic::Level::Error, file.string(), "", "", "file is larger than " + std::to_string(kMaxFileBytes >> 20) + " MiB"});
		return r;
	}
	std::ifstream in(file, std::ios::binary);
	std::ostringstream ss;
	ss << in.rdbuf();
	return add_json(ss.str(), file.string(), builtin, policy);
}

LoadResult SignatureSet::add_directory(const std::filesystem::path& dir, bool builtin, const LoadPolicy& policy) {
	LoadResult total;
	std::error_code ec;
	if (!std::filesystem::is_directory(dir, ec)) {
		total.diagnostics.push_back({Diagnostic::Level::Error, dir.string(), "", "", "not a directory"});
		return total;
	}
	std::vector<std::filesystem::path> files;
	for (const auto& e : std::filesystem::directory_iterator(dir, ec))
		if (e.is_regular_file() && !e.is_symlink() && e.path().extension() == ".json") files.push_back(e.path());
	std::sort(files.begin(), files.end());
	for (const auto& f : files) {
		LoadResult r = add_file(f, builtin, policy);
		total.loaded += r.loaded;
		total.diagnostics.insert(total.diagnostics.end(), r.diagnostics.begin(), r.diagnostics.end());
	}
	return total;
}

} // namespace proculus::sig
