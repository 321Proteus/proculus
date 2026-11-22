#include "proculus/sig/fields.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <vector>

namespace proculus::sig {

const char* to_string(Op op) {
	switch (op) {
	case Op::Equals: return "equals";
	case Op::Contains: return "contains";
	case Op::Prefix: return "prefix";
	case Op::Suffix: return "suffix";
	case Op::Regex: return "regex";
	case Op::Exists: return "exists";
	case Op::Gt: return "gt";
	case Op::Ge: return "ge";
	case Op::Lt: return "lt";
	case Op::Le: return "le";
	}
	return "?";
}

std::optional<Op> parse_op(const std::string& name) {
	for (Op op : {Op::Equals, Op::Contains, Op::Prefix, Op::Suffix, Op::Regex, Op::Exists, Op::Gt, Op::Ge, Op::Lt, Op::Le})
		if (name == to_string(op)) return op;
	return std::nullopt;
}

const char* to_string(FieldType t) {
	switch (t) {
	case FieldType::Number: return "number";
	case FieldType::String: return "string";
	case FieldType::Bool: return "bool";
	case FieldType::StringList: return "list";
	}
	return "?";
}

namespace {

const std::map<std::string, FieldType>& static_fields() {
	static const std::map<std::string, FieldType> f = {
		{"status", FieldType::Number}, {"port", FieldType::Number}, {"favicon_hash", FieldType::Number},
		{"body_length", FieldType::Number}, {"tls.key_bits", FieldType::Number},
		{"url", FieldType::String}, {"title", FieldType::String}, {"body", FieldType::String}, {"server", FieldType::String},
		{"content_type", FieldType::String}, {"host", FieldType::String}, {"tls.version", FieldType::String},
		{"tls.cipher", FieldType::String}, {"tls.subject", FieldType::String}, {"tls.issuer", FieldType::String},
		{"tls.key_type", FieldType::String}, {"tls.signature_algorithm", FieldType::String},
		{"service.name", FieldType::String}, {"service.product", FieldType::String}, {"service.version", FieldType::String},
		{"tls", FieldType::Bool}, {"tls.self_signed", FieldType::Bool}, {"tls.expired", FieldType::Bool},
		{"tls.not_yet_valid", FieldType::Bool}, {"tls.hostname_match", FieldType::Bool},
		{"cookie", FieldType::StringList}, {"cookie_insecure", FieldType::StringList}, {"cookie_no_httponly", FieldType::StringList},
		{"redirect_location", FieldType::StringList}, {"tls.san", FieldType::StringList}, {"hostnames", FieldType::StringList},
		{"header_names", FieldType::StringList},
	};
	return f;
}

bool valid_header_name(const std::string& n) {
	if (n.empty() || n.size() > 64) return false;
	for (unsigned char c : n)
		if (!(std::isalnum(c) || c == '-' || c == '_')) return false;
	return true;
}

} // namespace

const std::map<std::string, FieldType>& known_fields() { return static_fields(); }

bool valid_probe_path(const std::string& path) {
	if (path.size() < 1 || path.size() > 200 || path[0] != '/') return false;
	for (unsigned char c : path)
		if (!(std::isalnum(c) || c == '/' || c == '.' || c == '_' || c == '-' || c == '~' || c == '%')) return false;
	if (path.find("..") != std::string::npos || path.find("//") != std::string::npos) return false;
	return true;
}

std::optional<FieldType> field_type(const std::string& field, std::string& error) {
	if (auto it = static_fields().find(field); it != static_fields().end()) return it->second;

	if (field.compare(0, 7, "header:") == 0) {
		if (!valid_header_name(field.substr(7))) {
			error = "bad header name in \"" + field + "\"";
			return std::nullopt;
		}
		return FieldType::StringList;
	}
	if (field.compare(0, 5, "path:") == 0) {
		// path:<p>:<attr>[:<header name>]  -- paths cannot contain ':' so splitting is unambiguous
		std::vector<std::string> parts;
		size_t start = 0;
		for (;;) {
			const size_t colon = field.find(':', start);
			parts.push_back(field.substr(start, colon == std::string::npos ? std::string::npos : colon - start));
			if (colon == std::string::npos) break;
			start = colon + 1;
		}
		if (parts.size() < 3 || parts.size() > 4) {
			error = "\"" + field + "\" should look like path:/some/path:status";
			return std::nullopt;
		}
		if (!valid_probe_path(parts[1])) {
			error = "\"" + parts[1] + "\" is not an allowed probe path (absolute, plain characters, no query string or \"..\")";
			return std::nullopt;
		}
		const std::string& attr = parts[2];
		if (parts.size() == 3) {
			if (attr == "status") return FieldType::Number;
			if (attr == "body" || attr == "title" || attr == "content_type" || attr == "redirect") return FieldType::String;
			error = "unknown path attribute \"" + attr + "\" (use status, body, title, content_type, redirect or header:<name>)";
			return std::nullopt;
		}
		if (attr != "header" || !valid_header_name(parts[3])) {
			error = "\"" + field + "\": only path:<p>:header:<name> has four parts";
			return std::nullopt;
		}
		return FieldType::StringList;
	}
	error = "unknown field \"" + field + "\"";
	return std::nullopt;
}

bool op_allowed(FieldType type, Op op) {
	switch (type) {
	case FieldType::Number: return op == Op::Equals || op == Op::Exists || op == Op::Gt || op == Op::Ge || op == Op::Lt || op == Op::Le;
	case FieldType::Bool: return op == Op::Equals || op == Op::Exists;
	case FieldType::String:
	case FieldType::StringList: return op == Op::Equals || op == Op::Contains || op == Op::Prefix || op == Op::Suffix || op == Op::Regex || op == Op::Exists;
	}
	return false;
}

std::optional<std::string> probe_path_of(const std::string& field) {
	if (field.compare(0, 5, "path:") != 0) return std::nullopt;
	const size_t end = field.find(':', 5);
	if (end == std::string::npos) return std::nullopt;
	return field.substr(5, end - 5);
}

} // namespace proculus::sig
