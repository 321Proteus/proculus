#ifndef PROCULUS_GATEWAY_TOKEN_GUARD_HPP
#define PROCULUS_GATEWAY_TOKEN_GUARD_HPP

// The control token that protects actions (starting and stopping scans) until
// there are real user accounts and roles. It is a long random secret given to
// the operator when the gateway starts. Wrong guesses are limited: too many in
// a short time lock the guard for a while (even for the right token), so the
// token cannot be guessed by trying.

#include <chrono>
#include <functional>
#include <mutex>
#include <string>

namespace proculus {

class TokenGuard {
public:
	using Now = std::function<std::chrono::steady_clock::time_point()>;
	enum class Result { Ok, Denied, Locked, Disabled };

	// An empty token disables the guard: nothing is ever accepted.
	explicit TokenGuard(std::string token, Now now = [] { return std::chrono::steady_clock::now(); }, int max_failures = 5,
		std::chrono::seconds window = std::chrono::seconds(60), std::chrono::seconds lockout = std::chrono::seconds(60));

	Result check(const std::string& presented);

	// A new random token: 32 hex characters from the system's random source.
	static std::string generate();

private:
	std::string token_;
	Now now_;
	int max_failures_;
	std::chrono::seconds window_, lockout_;
	std::mutex m_;
	int failures_ = 0;
	std::chrono::steady_clock::time_point window_start_, locked_until_;
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_TOKEN_GUARD_HPP
