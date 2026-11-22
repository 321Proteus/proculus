#ifndef PROCULUS_GATEWAY_EXPORT_FORMAT_HPP
#define PROCULUS_GATEWAY_EXPORT_FORMAT_HPP

// User-defined text output: a template with {placeholders} that is filled in for every service.
//
//   {ip}:{port}                        10.0.0.5:22
//   {ip|csv},{port},{service|csv}      10.0.0.5,22,"OpenSSH 9.6, protocol 2.0"
//   {hostname|default:-|upper}         a missing host name shows as "-"
//
// Placeholders are {name} or {name|modifier|modifier...}. Modifiers: upper, lower, trim, csv (RFC 4180
// quoting, and a leading ' on values a spreadsheet would run as a formula), json (a JSON string),
// default:TEXT (when the value is empty), max:N (cut to N characters). Escapes: \n \t \\ \{ \} \|.
// Values come from scanned machines and are not trusted: control characters in them are turned into
// spaces before any modifier runs, so a value can never add lines or columns of its own.
// Anything that is not understood is an error (ApiError 400) saying what, never silently dropped.

#include <functional>
#include <set>
#include <string>
#include <vector>

namespace proculus {

class RowTemplate {
public:
	// `names` are the placeholders this template may use; `what` names it in error messages.
	static RowTemplate parse(const std::string& text, const std::set<std::string>& names, const std::string& what);
	// `value(name)` gives the (already sanitised) text of a placeholder.
	std::string render(const std::function<std::string(const std::string&)>& value) const;

private:
	struct Modifier {
		std::string name, arg;
	};
	struct Part {
		bool is_field = false;
		std::string text; // literal text, or the placeholder name
		std::vector<Modifier> modifiers;
	};
	std::vector<Part> parts_;
};

// Control characters (and DEL) to spaces.
std::string clean_value(const std::string& s);

} // namespace proculus

#endif // PROCULUS_GATEWAY_EXPORT_FORMAT_HPP
