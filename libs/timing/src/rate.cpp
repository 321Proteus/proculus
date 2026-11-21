#include "proculus/timing/rate.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

namespace proculus {

RateEstimator::RateEstimator(double alpha, double prior) : alpha_(alpha), rate_(prior > 0 ? prior : 0) {
	if (!(alpha > 0 && alpha <= 1)) throw std::invalid_argument("alpha must be in (0, 1]");
	if (std::isnan(prior) || std::isinf(prior)) throw std::invalid_argument("prior must be finite");
}

void RateEstimator::record(uint64_t addresses, double seconds) {
	if (addresses == 0 || !(seconds > 0) || std::isinf(seconds)) return;
	const double sample = static_cast<double>(addresses) / seconds;
	// The first real measurement replaces any prior; later ones are blended in.
	rate_ = samples_ == 0 ? sample : alpha_ * sample + (1 - alpha_) * rate_;
	samples_++;
}

std::optional<double> RateEstimator::estimate_seconds(uint64_t addresses) const {
	if (!has_estimate()) return std::nullopt;
	return static_cast<double>(addresses) / rate_;
}

std::optional<uint64_t> RateEstimator::addresses_for(double seconds) const {
	if (!has_estimate() || !(seconds > 0)) return std::nullopt;
	const double n = std::floor(rate_ * seconds);
	if (n < 1) return 1;
	if (n >= 1.8e19) return UINT64_MAX;
	return static_cast<uint64_t>(n);
}

std::string RateEstimator::serialize() const {
	char buf[64];
	std::snprintf(buf, sizeof buf, "%.9g;%zu", rate_, samples_);
	return buf;
}

bool RateEstimator::restore(const std::string& s) {
	char* end = nullptr;
	const double rate = std::strtod(s.c_str(), &end);
	if (end == s.c_str() || *end != ';' || !(rate >= 0) || std::isinf(rate)) return false;
	const char* p = end + 1;
	char* end2 = nullptr;
	const unsigned long long n = std::strtoull(p, &end2, 10);
	if (end2 == p || *end2 != '\0' || *p == '-') return false;
	rate_ = rate;
	samples_ = static_cast<size_t>(n);
	return true;
}

RateEstimator& RateTable::stage(const std::string& name) {
	return stages_.try_emplace(name, alpha_).first->second;
}

const RateEstimator* RateTable::find(const std::string& name) const {
	auto it = stages_.find(name);
	return it == stages_.end() ? nullptr : &it->second;
}

std::optional<double> eta_seconds(const Progress& p, const RateEstimator& r) {
	return r.estimate_seconds(p.remaining());
}

} // namespace proculus
