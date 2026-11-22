#include "token_guard.hpp"

#include <cstdio>
#include <stdexcept>

namespace proculus {

TokenGuard::TokenGuard(std::string token, Now now, int max_failures, std::chrono::seconds window, std::chrono::seconds lockout)
	: token_(std::move(token)), now_(std::move(now)), max_failures_(max_failures), window_(window), lockout_(lockout) {}

TokenGuard::Result TokenGuard::check(const std::string& presented) {
	if (token_.empty()) return Result::Disabled;
	std::lock_guard<std::mutex> l(m_);
	const auto now = now_();
	if (failures_ >= max_failures_ && now < locked_until_) return Result::Locked;
	if (failures_ >= max_failures_ || now - window_start_ > window_) failures_ = 0; // lockout over, or the window passed

	// compare in constant time over the longer of the two, so the length and the
	// position of a difference do not show in how long this takes
	unsigned diff = static_cast<unsigned>(presented.size() ^ token_.size());
	const size_t n = std::max(presented.size(), token_.size());
	for (size_t i = 0; i < n; i++) {
		const unsigned a = i < presented.size() ? static_cast<unsigned char>(presented[i]) : 0;
		const unsigned b = i < token_.size() ? static_cast<unsigned char>(token_[i]) : 0;
		diff |= a ^ b;
	}
	if (diff == 0) {
		failures_ = 0;
		return Result::Ok;
	}
	if (failures_ == 0) window_start_ = now;
	if (++failures_ >= max_failures_) locked_until_ = now + lockout_;
	return Result::Denied;
}

std::string TokenGuard::generate() {
	unsigned char bytes[16];
	FILE* f = std::fopen("/dev/urandom", "rb");
	if (!f || std::fread(bytes, 1, sizeof bytes, f) != sizeof bytes) {
		if (f) std::fclose(f);
		throw std::runtime_error("cannot read random bytes for the control token");
	}
	std::fclose(f);
	static const char* hex = "0123456789abcdef";
	std::string out;
	for (unsigned char b : bytes) {
		out.push_back(hex[b >> 4]);
		out.push_back(hex[b & 15]);
	}
	return out;
}

} // namespace proculus
