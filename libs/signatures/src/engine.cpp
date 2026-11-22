#include "proculus/sig/engine.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>

namespace proculus::sig {

namespace {

std::string lower_copy(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

std::string shorten(const std::string& s, size_t max = 60) {
	std::string out;
	for (unsigned char c : s) {
		out += (c < 0x20 || c == 0x7f) ? ' ' : static_cast<char>(c);
		if (out.size() >= max) return out + "...";
	}
	return out;
}

std::string number_text(double d) {
	char buf[32];
	if (d == std::floor(d) && std::fabs(d) < 1e15) std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(d));
	else std::snprintf(buf, sizeof buf, "%g", d);
	return buf;
}

struct Match {
	bool matched = false;
	std::string seen; // the value that matched, for the evidence line
};

// Tests one piece of text against a string operator.
bool text_matches(const Leaf& leaf, const std::string& text, const std::string& low, EvalStats* stats) {
	switch (leaf.op) {
	case Op::Equals:
		if (leaf.case_sensitive) return std::find(leaf.strings.begin(), leaf.strings.end(), text) != leaf.strings.end();
		return std::find(leaf.lowered_strings.begin(), leaf.lowered_strings.end(), low) != leaf.lowered_strings.end();
	case Op::Contains:
		for (size_t i = 0; i < leaf.strings.size(); i++)
			if (leaf.case_sensitive ? text.find(leaf.strings[i]) != std::string::npos : low.find(leaf.lowered_strings[i]) != std::string::npos) return true;
		return false;
	case Op::Prefix:
		for (size_t i = 0; i < leaf.strings.size(); i++) {
			const std::string& needle = leaf.case_sensitive ? leaf.strings[i] : leaf.lowered_strings[i];
			const std::string& hay = leaf.case_sensitive ? text : low;
			if (hay.size() >= needle.size() && hay.compare(0, needle.size(), needle) == 0) return true;
		}
		return false;
	case Op::Suffix:
		for (size_t i = 0; i < leaf.strings.size(); i++) {
			const std::string& needle = leaf.case_sensitive ? leaf.strings[i] : leaf.lowered_strings[i];
			const std::string& hay = leaf.case_sensitive ? text : low;
			if (hay.size() >= needle.size() && hay.compare(hay.size() - needle.size(), needle.size(), needle) == 0) return true;
		}
		return false;
	case Op::Regex:
		for (const auto& re : leaf.regexes) {
			const auto r = re->search(text);
			if (r == Regex::Result::Match) return true;
			if (r == Regex::Result::LimitExceeded && stats) stats->regex_limit_hits++;
		}
		return false;
	default: return false;
	}
}

bool number_matches(const Leaf& leaf, double v) {
	switch (leaf.op) {
	case Op::Equals: return std::any_of(leaf.numbers.begin(), leaf.numbers.end(), [&](double n) { return std::fabs(n - v) < 1e-9; });
	case Op::Gt: return v > leaf.numbers[0];
	case Op::Ge: return v >= leaf.numbers[0];
	case Op::Lt: return v < leaf.numbers[0];
	case Op::Le: return v <= leaf.numbers[0];
	default: return false;
	}
}

Match eval_leaf(const Leaf& leaf, const Evidence& ev, EvalStats* stats) {
	const Evidence::Value* value = ev.find(leaf.field);

	if (leaf.op == Op::Exists) {
		bool present = false;
		if (value) {
			if (auto* s = std::get_if<std::string>(value)) present = !s->empty();
			else if (auto* l = std::get_if<std::vector<std::string>>(value)) present = !l->empty();
			else present = true;
		}
		return {present == leaf.flag, ""};
	}
	if (!value) return {};

	if (auto* text = std::get_if<std::string>(value)) {
		if (leaf.field_type != FieldType::String) return {};
		const std::string& low = leaf.case_sensitive ? *text : ev.lowered(leaf.field);
		if (text_matches(leaf, *text, low, stats)) return {true, leaf.field == "body" ? "" : shorten(*text)};
		return {};
	}
	if (auto* list = std::get_if<std::vector<std::string>>(value)) {
		if (leaf.field_type != FieldType::StringList) return {};
		for (const std::string& item : *list)
			if (text_matches(leaf, item, leaf.case_sensitive ? item : lower_copy(item), stats)) return {true, shorten(item)};
		return {};
	}
	if (auto* number = std::get_if<double>(value)) {
		if (leaf.field_type != FieldType::Number) return {};
		return {number_matches(leaf, *number), number_text(*number)};
	}
	if (auto* flag = std::get_if<bool>(value)) {
		if (leaf.field_type != FieldType::Bool) return {};
		return {*flag == leaf.flag, *flag ? "true" : "false"};
	}
	return {};
}

std::string describe_leaf(const Leaf& leaf, const std::string& seen) {
	std::string out = leaf.field + " " + to_string(leaf.op);
	if (leaf.op == Op::Exists) {
		out += leaf.flag ? "" : " (absent)";
	} else if (!leaf.strings.empty()) {
		out += " \"" + shorten(leaf.strings[0], 40) + "\"";
		if (leaf.strings.size() > 1) out += " (+" + std::to_string(leaf.strings.size() - 1) + " more)";
	} else if (!leaf.numbers.empty()) {
		out += " " + number_text(leaf.numbers[0]);
	} else if (leaf.field_type == FieldType::Bool) {
		out += leaf.flag ? " true" : " false";
	}
	if (!seen.empty()) out += "  [" + seen + "]";
	return out;
}

// Evaluates a condition; the descriptions of the leaves that made it true go to `notes`.
bool eval(const Condition& c, const Evidence& ev, EvalStats* stats, std::vector<std::string>* notes) {
	switch (c.kind) {
	case Condition::Kind::Leaf: {
		const Match m = eval_leaf(c.leaf, ev, stats);
		if (m.matched && notes) notes->push_back(describe_leaf(c.leaf, m.seen));
		return m.matched;
	}
	case Condition::Kind::All: {
		std::vector<std::string> local;
		for (const Condition& child : c.children)
			if (!eval(child, ev, stats, notes ? &local : nullptr)) return false;
		if (notes) notes->insert(notes->end(), local.begin(), local.end());
		return true;
	}
	case Condition::Kind::Any:
		for (const Condition& child : c.children)
			if (eval(child, ev, stats, notes)) return true;
		return false;
	case Condition::Kind::Not: return !eval(c.children[0], ev, stats, nullptr);
	}
	return false;
}

bool version_text_ok(const std::string& v) {
	if (v.empty() || v.size() > 64) return false;
	for (unsigned char c : v)
		if (!(std::isalnum(c) || c == '.' || c == '_' || c == '+' || c == '~' || c == ':' || c == '-')) return false;
	return true;
}

std::string extract_version(const VersionRule& rule, const Evidence& ev, EvalStats* stats) {
	const Evidence::Value* value = ev.find(rule.field);
	if (!value) return "";
	auto try_text = [&](const std::string& text) -> std::string {
		std::string captured;
		const auto r = rule.regex->search(text, &captured, 1);
		if (r == Regex::Result::LimitExceeded && stats) stats->regex_limit_hits++;
		return r == Regex::Result::Match && version_text_ok(captured) ? captured : "";
	};
	if (auto* s = std::get_if<std::string>(value)) return try_text(*s);
	if (auto* l = std::get_if<std::vector<std::string>>(value))
		for (const std::string& item : *l)
			if (std::string v = try_text(item); !v.empty()) return v;
	return "";
}

} // namespace

std::optional<Detection> evaluate_signature(const Signature& sig, const Evidence& ev, EvalStats* stats) {
	if (stats) stats->signatures_evaluated++;

	if (sig.exclude && eval(*sig.exclude, ev, stats, nullptr)) return std::nullopt;

	double miss = 1.0;
	bool any = false;
	std::vector<std::string> lines;
	for (const Signal& signal : sig.signals) {
		std::vector<std::string> notes;
		const bool matched = eval(signal.match, ev, stats, &notes);
		if (!matched) {
			if (signal.required) return std::nullopt;
			continue;
		}
		any = true;
		miss *= 1.0 - signal.weight;
		std::string line = "+" + number_text(std::round(signal.weight * 100) / 100) + "  ";
		if (!signal.label.empty()) line += signal.label + ": ";
		for (size_t i = 0; i < notes.size(); i++) line += (i ? "; " : "") + notes[i];
		lines.push_back(std::move(line));
	}
	if (!any) return std::nullopt;
	const double confidence = std::min(0.99, 1.0 - miss);
	if (confidence < sig.threshold - 1e-9) return std::nullopt;

	Detection d;
	d.id = sig.id;
	d.name = sig.name;
	d.category = sig.category;
	d.tags = sig.tags;
	d.confidence = confidence;
	d.interest = sig.interest;
	d.builtin = sig.builtin;
	d.evidence = std::move(lines);
	if (sig.version) d.version = extract_version(*sig.version, ev, stats);
	return d;
}

std::vector<Detection> evaluate(const SignatureSet& set, const Evidence& ev, EvalStats* stats) {
	std::vector<Detection> out;
	for (const Signature& s : set.all()) {
		if (!s.enabled) continue;
		if (auto d = evaluate_signature(s, ev, stats)) out.push_back(std::move(*d));
	}
	std::sort(out.begin(), out.end(), [](const Detection& a, const Detection& b) {
		if (a.confidence != b.confidence) return a.confidence > b.confidence;
		if (a.interest != b.interest) return a.interest > b.interest;
		return a.id < b.id;
	});
	return out;
}

std::vector<std::string> run_examples(const Signature& s) {
	std::vector<std::string> failures;
	for (const Example& e : s.examples) {
		const auto d = evaluate_signature(s, e.evidence);
		const std::string label = s.id + ": example \"" + e.name + "\"";
		if (e.expect_match && !d) failures.push_back(label + ": expected a detection, got none");
		else if (!e.expect_match && d) failures.push_back(label + ": expected no detection, got one (confidence " + number_text(std::round(d->confidence * 100) / 100) + ")");
		else if (e.expect_match && !e.expect_version.empty() && d->version != e.expect_version)
			failures.push_back(label + ": expected version \"" + e.expect_version + "\", got \"" + d->version + "\"");
	}
	return failures;
}

std::vector<std::string> run_examples(const SignatureSet& set) {
	std::vector<std::string> failures;
	for (const Signature& s : set.all()) {
		if (!s.enabled) continue;
		for (std::string& f : run_examples(s)) failures.push_back(std::move(f));
	}
	return failures;
}

} // namespace proculus::sig
