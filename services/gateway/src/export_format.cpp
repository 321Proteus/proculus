#include "export_format.hpp"

#include <algorithm>

#include "api.hpp"

namespace proculus {

namespace {

constexpr size_t kMaxTemplate = 500, kMaxParts = 80, kMaxModifiers = 6;

[[noreturn]] void bad(const std::string& what, const std::string& why) { throw ApiError(400, what + ": " + why); }

std::string csv_quote(const std::string& v) {
	std::string s = v;
	if (!s.empty() && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@')) s.insert(s.begin(), '\''); // not a formula in a spreadsheet
	if (s.find_first_of(",\"\n\r") == std::string::npos && (s.empty() || (s.front() != ' ' && s.back() != ' '))) return s;
	std::string out = "\"";
	for (char c : s) {
		if (c == '"') out += '"';
		out += c;
	}
	return out + "\"";
}

std::string json_string(const std::string& v) {
	std::string out = "\"";
	for (unsigned char c : v) {
		switch (c) {
		case '"': out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		default:
			if (c < 0x20) {
				out += ' ';
			} else {
				out += static_cast<char>(c); // UTF-8 bytes pass through as they are
			}
		}
	}
	return out + "\"";
}

// Cut to `n` characters without splitting a UTF-8 sequence.
std::string cut(const std::string& s, size_t n) {
	size_t chars = 0, i = 0;
	while (i < s.size()) {
		if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) {
			if (chars == n) break;
			chars++;
		}
		i++;
	}
	return s.substr(0, i);
}

std::string trim(const std::string& s) {
	const size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t");
	return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

std::string ascii_case(std::string s, bool upper) {
	for (char& c : s)
		if (upper ? (c >= 'a' && c <= 'z') : (c >= 'A' && c <= 'Z')) c = static_cast<char>(c ^ 0x20);
	return s;
}

} // namespace

std::string clean_value(const std::string& s) {
	std::string out = s;
	for (char& c : out)
		if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = ' ';
	return out;
}

RowTemplate RowTemplate::parse(const std::string& text, const std::set<std::string>& names, const std::string& what) {
	if (text.size() > kMaxTemplate) bad(what, "longer than " + std::to_string(kMaxTemplate) + " characters");
	RowTemplate t;
	std::string lit;
	auto flush = [&] {
		if (lit.empty()) return;
		Part p;
		p.text = std::move(lit);
		t.parts_.push_back(std::move(p));
		lit.clear();
	};
	for (size_t i = 0; i < text.size(); i++) {
		const char c = text[i];
		if (c == '\\') {
			if (++i >= text.size()) bad(what, "ends with a lone \\");
			switch (text[i]) {
			case 'n': lit += '\n'; break;
			case 't': lit += '\t'; break;
			case '\\': case '{': case '}': case '|': lit += text[i]; break;
			default: bad(what, std::string("unknown escape \\") + text[i] + " (use \\n \\t \\\\ \\{ \\} \\|)");
			}
		} else if (c == '}') {
			bad(what, "a lone } (write \\} for the character)");
		} else if (c == '{') {
			const size_t end = text.find('}', i);
			if (end == std::string::npos) bad(what, "a { is never closed (write \\{ for the character)");
			const std::string body = text.substr(i + 1, end - i - 1);
			i = end;
			Part p;
			p.is_field = true;
			size_t from = 0, k = 0;
			while (true) {
				const size_t bar = body.find('|', from);
				const std::string piece = body.substr(from, bar == std::string::npos ? std::string::npos : bar - from);
				if (k++ == 0) {
					p.text = trim(piece);
					if (!names.count(p.text)) {
						std::string known;
						for (const std::string& n : names) known += (known.empty() ? "" : ", ") + n;
						bad(what, "unknown placeholder {" + p.text.substr(0, 30) + "} (known: " + known + ")");
					}
				} else {
					Modifier m;
					const size_t colon = piece.find(':');
					m.name = trim(piece.substr(0, colon));
					if (colon != std::string::npos) m.arg = piece.substr(colon + 1);
					if (m.name == "upper" || m.name == "lower" || m.name == "trim" || m.name == "csv" || m.name == "json") {
						if (colon != std::string::npos) bad(what, "modifier " + m.name + " takes no value");
					} else if (m.name == "default") {
						if (colon == std::string::npos) bad(what, "default needs a value: default:TEXT");
					} else if (m.name == "max") {
						if (m.arg.empty() || m.arg.size() > 4 || m.arg.find_first_not_of("0123456789") != std::string::npos || std::stoul(m.arg) < 1) bad(what, "max needs a number: max:20");
					} else {
						bad(what, "unknown modifier \"" + m.name.substr(0, 30) + "\" (known: upper, lower, trim, csv, json, default:TEXT, max:N)");
					}
					if (p.modifiers.size() >= kMaxModifiers) bad(what, "too many modifiers on one placeholder");
					p.modifiers.push_back(std::move(m));
				}
				if (bar == std::string::npos) break;
				from = bar + 1;
			}
			flush();
			t.parts_.push_back(std::move(p));
		} else {
			lit += c;
		}
		if (t.parts_.size() > kMaxParts) bad(what, "too many parts");
	}
	flush();
	return t;
}

std::string RowTemplate::render(const std::function<std::string(const std::string&)>& value) const {
	std::string out;
	for (const Part& p : parts_) {
		if (!p.is_field) {
			out += p.text;
			continue;
		}
		std::string v = clean_value(value(p.text));
		for (const Modifier& m : p.modifiers) {
			if (m.name == "upper") v = ascii_case(v, true);
			else if (m.name == "lower") v = ascii_case(v, false);
			else if (m.name == "trim") v = trim(v);
			else if (m.name == "csv") v = csv_quote(v);
			else if (m.name == "json") v = json_string(v);
			else if (m.name == "default") { if (v.empty()) v = m.arg; }
			else if (m.name == "max") v = cut(v, std::stoul(m.arg));
		}
		out += v;
	}
	return out;
}

} // namespace proculus
