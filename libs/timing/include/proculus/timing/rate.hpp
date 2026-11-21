#ifndef PROCULUS_TIMING_RATE_HPP
#define PROCULUS_TIMING_RATE_HPP

// Measuring how fast scanning really goes, so chunk sizes, duration estimates
// and "will this chunk finish before the window closes?" decisions rest on
// measurements instead of guesses.

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace proculus {

// Wall-clock stopwatch (monotonic).
class Stopwatch {
public:
	Stopwatch() : start_(std::chrono::steady_clock::now()) {}
	double elapsed_seconds() const {
		return std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();
	}
	void restart() { start_ = std::chrono::steady_clock::now(); }

private:
	std::chrono::steady_clock::time_point start_;
};

// Scan speed in addresses per second, as an exponentially weighted average of
// measured chunks: recent measurements count more, so the estimate follows the
// network when it slows down or speeds up.
class RateEstimator {
public:
	// `alpha` in (0, 1]: weight of each new sample. `prior` (addresses/s, 0 = none)
	// is used until the first real measurement arrives, e.g. from a config value.
	explicit RateEstimator(double alpha = 0.3, double prior = 0);

	// Records that `addresses` were scanned in `seconds`. Samples with no
	// addresses or non-positive duration carry no information and are ignored.
	void record(uint64_t addresses, double seconds);

	bool has_estimate() const { return rate_ > 0; }
	size_t samples() const { return samples_; }
	// Addresses per second; 0 if nothing is known yet.
	double rate() const { return rate_; }

	// Expected seconds to scan `addresses`; nullopt if there is no estimate.
	std::optional<double> estimate_seconds(uint64_t addresses) const;
	// How many addresses fit in `seconds` (at least 1); nullopt if no estimate.
	std::optional<uint64_t> addresses_for(double seconds) const;

	// Persistable form "rate;samples", e.g. for the settings table.
	std::string serialize() const;
	// Restores state saved by serialize(); returns false (state unchanged) on bad input.
	bool restore(const std::string& s);

private:
	double alpha_;
	double rate_;
	size_t samples_ = 0;
};

// One estimator per scan stage ("discovery", "services", "http"): the stages
// run at very different speeds.
class RateTable {
public:
	explicit RateTable(double alpha = 0.3) : alpha_(alpha) {}
	RateEstimator& stage(const std::string& name);
	const RateEstimator* find(const std::string& name) const;

private:
	double alpha_;
	std::map<std::string, RateEstimator> stages_;
};

// Progress of a run: remaining work divided by the measured rate.
struct Progress {
	uint64_t total = 0;
	uint64_t done = 0;

	uint64_t remaining() const { return done >= total ? 0 : total - done; }
	double fraction() const { return total ? static_cast<double>(done) / static_cast<double>(total) : 1.0; }
};

std::optional<double> eta_seconds(const Progress& p, const RateEstimator& r);

} // namespace proculus

#endif // PROCULUS_TIMING_RATE_HPP
