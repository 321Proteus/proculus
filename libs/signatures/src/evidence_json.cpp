#include "proculus/sig/evidence_json.hpp"

#include <algorithm>

#include "proculus/sig/fields.hpp"

namespace proculus::sig {

bool evidence_from_json(const nlohmann::json& j, Evidence& out, std::vector<EvidenceProblem>& problems) {
	if (!j.is_object()) {
		problems.push_back({"", "expected an object of field: value"});
		return false;
	}
	bool ok = true;
	for (auto it = j.begin(); it != j.end(); ++it) {
		std::string error;
		const auto type = field_type(it.key(), error);
		if (!type) {
			problems.push_back({it.key(), error});
			ok = false;
			continue;
		}
		const nlohmann::json& v = it.value();
		auto bad = [&](const char* expected) {
			problems.push_back({it.key(), std::string("expected ") + expected});
			ok = false;
		};
		switch (*type) {
		case FieldType::Number:
			if (v.is_number()) out.set(it.key(), v.get<double>());
			else bad("a number");
			break;
		case FieldType::Bool:
			if (v.is_boolean()) out.set(it.key(), v.get<bool>());
			else bad("true or false");
			break;
		case FieldType::String:
			if (v.is_string()) out.set(it.key(), v.get<std::string>());
			else bad("a string");
			break;
		case FieldType::StringList:
			if (v.is_string()) out.set_list(it.key(), {v.get<std::string>()});
			else if (v.is_array() && std::all_of(v.begin(), v.end(), [](const nlohmann::json& e) { return e.is_string(); }))
				out.set_list(it.key(), v.get<std::vector<std::string>>());
			else bad("a string or a list of strings");
			break;
		}
	}
	return ok;
}

nlohmann::ordered_json evidence_to_json(const Evidence& evidence) {
	nlohmann::ordered_json j = nlohmann::ordered_json::object();
	for (const auto& [field, value] : evidence.all()) {
		if (auto* s = std::get_if<std::string>(&value)) j[field] = *s;
		else if (auto* n = std::get_if<double>(&value)) j[field] = *n;
		else if (auto* b = std::get_if<bool>(&value)) j[field] = *b;
		else if (auto* l = std::get_if<std::vector<std::string>>(&value)) j[field] = *l;
	}
	return j;
}

} // namespace proculus::sig
