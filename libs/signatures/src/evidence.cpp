#include "proculus/sig/evidence.hpp"

#include <algorithm>
#include <cctype>

namespace proculus::sig {

void Evidence::set(const std::string& field, std::string value) {
	lower_cache_.erase(field);
	values_[field] = std::move(value);
}
void Evidence::set(const std::string& field, double value) { values_[field] = value; }
void Evidence::set(const std::string& field, bool value) { values_[field] = value; }
void Evidence::set_list(const std::string& field, std::vector<std::string> values) { values_[field] = std::move(values); }

void Evidence::add(const std::string& field, std::string value) {
	auto it = values_.find(field);
	if (it == values_.end() || !std::holds_alternative<std::vector<std::string>>(it->second)) {
		values_[field] = std::vector<std::string>{std::move(value)};
		return;
	}
	std::get<std::vector<std::string>>(it->second).push_back(std::move(value));
}

const Evidence::Value* Evidence::find(const std::string& field) const {
	auto it = values_.find(field);
	return it == values_.end() ? nullptr : &it->second;
}

const std::string& Evidence::lowered(const std::string& field) const {
	static const std::string empty;
	auto cached = lower_cache_.find(field);
	if (cached != lower_cache_.end()) return cached->second;
	const Value* v = find(field);
	if (!v || !std::holds_alternative<std::string>(*v)) return empty;
	std::string lower = std::get<std::string>(*v);
	std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return lower_cache_.emplace(field, std::move(lower)).first->second;
}

} // namespace proculus::sig
