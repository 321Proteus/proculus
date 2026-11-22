#include "commands.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>

#include "proculus/sig/builtin.hpp"
#include "proculus/sig/engine.hpp"
#include "proculus/sig/evidence_json.hpp"

namespace proculus {

namespace {

using Json = nlohmann::ordered_json;

struct UsageError : std::runtime_error {
	using std::runtime_error::runtime_error;
};

std::string printable(std::string s) {
	for (char& c : s)
		if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = '?';
	return s;
}

struct Options {
	std::vector<std::string> positional;
	std::vector<std::string> sig_paths;
	bool no_builtin = false;
	bool json = false;
	std::string category, tag;
	size_t max = 0;
	double min_confidence = 0;
};

Options parse_options(const std::vector<std::string>& args, size_t from) {
	Options o;
	auto value = [&](size_t& i) -> const std::string& {
		if (i + 1 >= args.size()) throw UsageError("missing value for " + args[i]);
		return args[++i];
	};
	for (size_t i = from; i < args.size(); i++) {
		const std::string& a = args[i];
		if (a == "--signatures") o.sig_paths.push_back(value(i));
		else if (a == "--no-builtin") o.no_builtin = true;
		else if (a == "--format") {
			const std::string& f = value(i);
			if (f != "text" && f != "json") throw UsageError("unknown format '" + f + "' (use text or json)");
			o.json = f == "json";
		} else if (a == "--category") o.category = value(i);
		else if (a == "--tag") o.tag = value(i);
		else if (a == "--max") {
			const std::string& v = value(i);
			if (v.empty() || v.size() > 6 || v.find_first_not_of("0123456789") != std::string::npos) throw UsageError("not a number: " + v);
			o.max = std::stoul(v);
		} else if (a == "--min-confidence") {
			try {
				size_t pos = 0;
				o.min_confidence = std::stod(value(i), &pos);
				if (pos != args[i].size() || o.min_confidence < 0 || o.min_confidence > 1) throw std::invalid_argument("");
			} catch (const std::exception&) {
				throw UsageError("--min-confidence must be a number between 0 and 1");
			}
		} else if (a == "-" || a.empty() || a[0] != '-') o.positional.push_back(a);
		else throw UsageError("unknown option " + a);
	}
	return o;
}

void print_diagnostic(std::ostream& err, const sig::Diagnostic& d) {
	err << (d.level == sig::Diagnostic::Level::Error ? "error: " : "warning: ") << printable(d.source);
	if (!d.signature.empty()) err << ": " << printable(d.signature);
	if (!d.where.empty()) err << ": " << printable(d.where);
	err << ": " << printable(d.message) << "\n";
}

// Built-ins (unless --no-builtin) plus --signatures. Diagnostics go to `err`;
// returns false if a custom source had errors.
bool load_set(const Options& o, sig::SignatureSet& set, std::ostream& err) {
	if (!o.no_builtin) set = sig::builtin_signatures();
	bool ok = true;
	for (const std::string& path : o.sig_paths) {
		std::error_code ec;
		const std::filesystem::path fp(path);
		sig::LoadResult r = std::filesystem::is_directory(fp, ec) ? set.add_directory(fp) : set.add_file(fp);
		for (const sig::Diagnostic& d : r.diagnostics) print_diagnostic(err, d);
		ok &= !r.has_errors();
	}
	return ok;
}

std::string read_all(std::istream& in) { return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()); }

Json signature_summary(const sig::Signature& s) {
	return { { "id", s.id }, { "name", s.name }, { "category", sig::to_string(s.category) }, { "interest", s.interest }, { "threshold", s.threshold },
		{ "tags", s.tags }, { "builtin", s.builtin }, { "enabled", s.enabled }, { "source", s.source }, { "signals", s.signals.size() },
		{ "examples", s.examples.size() } };
}

// ---------------------------------------------------------------- commands

int cmd_list(const Options& o, std::ostream& out, std::ostream& err) {
	sig::SignatureSet set;
	if (!load_set(o, set, err)) return 2;
	std::optional<sig::Category> cat;
	if (!o.category.empty()) {
		cat = sig::parse_category(o.category);
		if (!cat) throw UsageError("unknown category '" + o.category + "' (cms, framework, server, iot, staging, admin, other)");
	}
	std::vector<const sig::Signature*> shown;
	for (const sig::Signature& s : set.all()) {
		if (cat && s.category != *cat) continue;
		if (!o.tag.empty() && std::find(s.tags.begin(), s.tags.end(), o.tag) == s.tags.end()) continue;
		shown.push_back(&s);
	}
	if (o.json) {
		Json arr = Json::array();
		for (const auto* s : shown) arr.push_back(signature_summary(*s));
		out << arr.dump(2, ' ', false, Json::error_handler_t::replace) << "\n";
		return 0;
	}
	for (const auto* s : shown)
		out << s->id << "  " << sig::to_string(s->category) << "  interest " << s->interest << (s->builtin ? "" : "  [custom]") << (s->enabled ? "" : "  [disabled]")
		    << "  " << printable(s->name) << "\n";
	out << shown.size() << " of " << set.size() << " signatures\n";
	return 0;
}

int cmd_show(const Options& o, std::ostream& out, std::ostream& err) {
	if (o.positional.size() != 1) throw UsageError("show needs exactly one signature id");
	sig::SignatureSet set;
	if (!load_set(o, set, err)) return 2;
	const sig::Signature* s = set.find(o.positional[0]);
	if (!s) {
		err << "error: no signature \"" << printable(o.positional[0]) << "\"\n";
		return 2;
	}
	Json j = signature_summary(*s);
	j["description"] = s->description;
	j["references"] = s->references;
	j["version_extraction"] = s->version.has_value();
	j["has_exclusion"] = s->exclude.has_value();
	j["signal_weights"] = Json::array();
	for (const sig::Signal& sg : s->signals) j["signal_weights"].push_back({ { "weight", sg.weight }, { "required", sg.required }, { "label", sg.label } });
	if (o.json) {
		out << j.dump(2, ' ', false, Json::error_handler_t::replace) << "\n";
		return 0;
	}
	out << s->id << ": " << printable(s->name) << "\n  category " << sig::to_string(s->category) << ", interest " << s->interest << ", reported from confidence "
	    << s->threshold << "\n  source " << printable(s->source) << (s->builtin ? " (built in)" : "") << "\n";
	if (!s->description.empty()) out << "  " << printable(s->description) << "\n";
	for (const sig::Signal& sg : s->signals)
		out << "  signal weight " << sg.weight << (sg.required ? " (required)" : "") << (sg.label.empty() ? "" : ": " + printable(sg.label)) << "\n";
	if (s->version) out << "  extracts a version from " << s->version->field << "\n";
	if (s->exclude) out << "  has an exclusion condition\n";
	out << "  " << s->examples.size() << " example(s)\n";
	return 0;
}

int cmd_lint(const Options& o, std::ostream& out, std::ostream& err) {
	if (o.positional.empty()) throw UsageError("lint needs at least one file or directory");
	int problems = 0;
	for (const std::string& path : o.positional) {
		// Against the built-ins, so an id clash or a "disable" of an unknown id shows up.
		sig::SignatureSet set;
		if (!o.no_builtin) set = sig::builtin_signatures();
		const std::filesystem::path fp(path);
		std::error_code ec;
		sig::LoadResult r = std::filesystem::is_directory(fp, ec) ? set.add_directory(fp) : set.add_file(fp);
		for (const sig::Diagnostic& d : r.diagnostics) print_diagnostic(err, d);

		size_t checked = 0, example_failures = 0, untested = 0;
		for (const sig::Signature& s : set.all()) {
			if (s.builtin) continue;
			checked++;
			if (s.examples.empty()) {
				untested++;
				err << "warning: " << printable(s.source) << ": " << printable(s.id) << ": no examples; add some so the signature can be tested\n";
			}
			for (const std::string& f : sig::run_examples(s)) {
				example_failures++;
				err << "error: " << printable(s.source) << ": " << printable(f) << "\n";
			}
		}
		out << path << ": " << r.loaded << " signature(s) loaded, " << r.errors() << " error(s), " << r.warnings() + untested << " warning(s), " << example_failures
		    << " failing example(s)\n";
		if (r.has_errors() || example_failures) problems++;
		(void)checked;
	}
	return problems ? 1 : 0;
}

int cmd_test(const Options& o, std::ostream& out, std::ostream& err) {
	sig::SignatureSet set;
	if (!load_set(o, set, err)) return 2;
	size_t examples = 0;
	for (const sig::Signature& s : set.all())
		if (s.enabled) examples += s.examples.size();
	const auto failures = sig::run_examples(set);
	for (const std::string& f : failures) err << "FAIL " << printable(f) << "\n";
	out << set.enabled_count() << " signatures, " << examples << " examples, " << failures.size() << " failure(s)\n";
	return failures.empty() ? 0 : 1;
}

int cmd_match(const Options& o, std::istream& in, std::ostream& out, std::ostream& err) {
	if (o.positional.size() != 1) throw UsageError("match needs one evidence file (or - for stdin)");
	std::string text;
	if (o.positional[0] == "-") text = read_all(in);
	else {
		std::ifstream f(o.positional[0]);
		if (!f) {
			err << "error: cannot read " << printable(o.positional[0]) << "\n";
			return 2;
		}
		text = read_all(f);
	}
	nlohmann::json doc = nlohmann::json::parse(text, nullptr, false);
	if (doc.is_discarded() || !doc.is_object()) {
		err << "error: the evidence must be a JSON object, e.g. {\"server\": \"nginx/1.24.0\", \"status\": 200}\n";
		return 2;
	}
	sig::Evidence ev;
	std::vector<sig::EvidenceProblem> problems;
	if (!sig::evidence_from_json(doc, ev, problems)) {
		for (const auto& [field, why] : problems) err << "error: evidence: " << printable(field) << ": " << printable(why) << "\n";
		return 2;
	}
	sig::SignatureSet set;
	if (!load_set(o, set, err)) return 2;
	sig::EvalStats stats;
	auto found = sig::evaluate(set, ev, &stats);
	found.erase(std::remove_if(found.begin(), found.end(), [&](const sig::Detection& d) { return d.confidence < o.min_confidence; }), found.end());

	if (o.json) {
		Json arr = Json::array();
		for (const sig::Detection& d : found) {
			Json j = { { "id", d.id }, { "name", d.name }, { "category", sig::to_string(d.category) }, { "confidence", d.confidence }, { "interest", d.interest },
				{ "builtin", d.builtin }, { "tags", d.tags }, { "evidence", d.evidence } };
			if (!d.version.empty()) j["version"] = d.version;
			arr.push_back(std::move(j));
		}
		out << arr.dump(2, ' ', false, Json::error_handler_t::replace) << "\n";
		return 0;
	}
	for (const sig::Detection& d : found) {
		out << printable(d.name);
		if (!d.version.empty()) out << " " << printable(d.version);
		out << "  [" << sig::to_string(d.category) << ", confidence " << static_cast<int>(d.confidence * 100 + 0.5) << "%, interest " << d.interest << "]  (" << printable(d.id) << ")\n";
		for (const std::string& e : d.evidence) out << "    " << printable(e) << "\n";
	}
	if (found.empty()) out << "no detections\n";
	if (stats.regex_limit_hits) out << "note: " << stats.regex_limit_hits << " pattern search(es) hit the effort limit\n";
	return 0;
}

int cmd_fields(const Options&, std::ostream& out) {
	for (const auto& [name, type] : sig::known_fields()) out << name << "  " << sig::to_string(type) << "\n";
	out << "header:<name>                 list    values of a response header (name in lowercase)\n"
	       "path:<p>:status               number  an extra page the prober fetches (GET only), e.g. path:/wp-login.php:status\n"
	       "path:<p>:body|title|content_type|redirect   string\n"
	       "path:<p>:header:<name>        list\n";
	return 0;
}

int cmd_paths(const Options& o, std::ostream& out, std::ostream& err) {
	sig::SignatureSet set;
	if (!load_set(o, set, err)) return 2;
	for (const std::string& p : set.required_paths(o.max)) out << p << "\n";
	return 0;
}

} // namespace

void print_signatures_usage(std::ostream& out, const char* argv0) {
	out << "usage: " << argv0 << " COMMAND [options]\n"
	    << "  list [--category C] [--tag T]    list signatures\n"
	    << "  show ID                          describe one signature\n"
	    << "  lint FILE|DIR...                 check your own signature files and run their examples\n"
	    << "  test                             run the examples of all signatures\n"
	    << "  match EVIDENCE.json|-            what the signatures say about some evidence (a JSON object of fields;\n"
	    << "                                   http-prober --dump-evidence writes one)  [--min-confidence C]\n"
	    << "  fields                           the facts a signature can test\n"
	    << "  paths [--max N]                  extra paths the prober would fetch, most valuable first\n"
	    << "common options: --signatures FILE|DIR (repeatable)  --no-builtin  --format text|json\n"
	    << "exit status: 0 ok, 1 problems in signatures or examples, 2 usage error or unreadable input\n";
}

int run_signatures_tool(const std::vector<std::string>& args, std::istream& in, std::ostream& out, std::ostream& err) {
	try {
		if (args.empty()) {
			print_signatures_usage(err, "signatures");
			return 2;
		}
		const std::string& cmd = args[0];
		if (cmd == "help" || cmd == "--help") {
			print_signatures_usage(out, "signatures");
			return 0;
		}
		const Options o = parse_options(args, 1);
		if (cmd == "list") return cmd_list(o, out, err);
		if (cmd == "show") return cmd_show(o, out, err);
		if (cmd == "lint") return cmd_lint(o, out, err);
		if (cmd == "test") return cmd_test(o, out, err);
		if (cmd == "match") return cmd_match(o, in, out, err);
		if (cmd == "fields") return cmd_fields(o, out);
		if (cmd == "paths") return cmd_paths(o, out, err);
		throw UsageError("unknown command '" + cmd + "'");
	} catch (const UsageError& e) {
		err << "error: " << e.what() << "\n";
		return 2;
	}
}

} // namespace proculus
