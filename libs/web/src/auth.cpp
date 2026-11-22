#include "proculus/web/auth.hpp"

#include <algorithm>
#include <cstdio>

namespace proculus::web {

const std::vector<std::string>& all_permissions() {
	static const std::vector<std::string> p = {"data.read", "data.edit", "data.create", "data.delete", "export", "scan.run", "config.manage", "users.manage"};
	return p;
}

bool is_permission(const std::string& name) {
	const auto& p = all_permissions();
	return std::find(p.begin(), p.end(), name) != p.end();
}

bool AuthUser::has(const std::string& permission) const { return std::find(permissions.begin(), permissions.end(), permission) != permissions.end(); }

std::string random_hex(size_t bytes) {
	std::string raw(bytes, '\0');
	FILE* f = std::fopen("/dev/urandom", "rb");
	if (!f || std::fread(&raw[0], 1, bytes, f) != bytes) {
		if (f) std::fclose(f);
		throw std::runtime_error("cannot read random bytes");
	}
	std::fclose(f);
	static const char* hex = "0123456789abcdef";
	std::string out;
	for (unsigned char b : raw) {
		out.push_back(hex[b >> 4]);
		out.push_back(hex[b & 15]);
	}
	return out;
}

// ------------------------------------------------------------------ sessions

SessionManager::SessionManager(Clock now, std::chrono::seconds idle, std::chrono::seconds max_age, size_t max_sessions)
	: now_(std::move(now)), idle_(idle), max_age_(max_age), max_sessions_(max_sessions) {}

void SessionManager::sweep(std::chrono::steady_clock::time_point now) {
	for (auto it = sessions_.begin(); it != sessions_.end();) {
		if (now - it->second.last_used > idle_ || now - it->second.created > max_age_) it = sessions_.erase(it);
		else ++it;
	}
}

std::string SessionManager::create(const AuthUser& user) {
	std::lock_guard<std::mutex> l(m_);
	const auto now = now_();
	sweep(now);
	if (sessions_.size() >= max_sessions_) { // make room: drop the one idle the longest
		auto oldest = std::min_element(sessions_.begin(), sessions_.end(), [](const auto& a, const auto& b) { return a.second.last_used < b.second.last_used; });
		sessions_.erase(oldest);
	}
	const std::string token = random_hex(32);
	sessions_[token] = Session{user, now, now};
	return token;
}

std::optional<AuthUser> SessionManager::find(const std::string& token) {
	std::lock_guard<std::mutex> l(m_);
	auto it = sessions_.find(token);
	if (it == sessions_.end()) return std::nullopt;
	const auto now = now_();
	if (now - it->second.last_used > idle_ || now - it->second.created > max_age_) {
		sessions_.erase(it);
		return std::nullopt;
	}
	it->second.last_used = now;
	return it->second.user;
}

void SessionManager::revoke(const std::string& token) {
	std::lock_guard<std::mutex> l(m_);
	sessions_.erase(token);
}

void SessionManager::revoke_user(int64_t user_id) {
	std::lock_guard<std::mutex> l(m_);
	for (auto it = sessions_.begin(); it != sessions_.end();) {
		if (it->second.user.id == user_id) it = sessions_.erase(it);
		else ++it;
	}
}

// ------------------------------------------------------------------ throttle

LoginThrottle::LoginThrottle(Clock now, int per_user, int overall, std::chrono::seconds window, std::chrono::seconds lockout)
	: now_(std::move(now)), per_user_(per_user), overall_(overall), window_(window), lockout_(lockout) {}

bool LoginThrottle::locked(Count& c, int limit, std::chrono::steady_clock::time_point now) {
	if (c.failures >= limit && now < c.locked_until) return true;
	if (c.failures >= limit || now - c.first > window_) c.failures = 0; // lockout over, or the window passed
	return false;
}

void LoginThrottle::add(Count& c, int limit, std::chrono::steady_clock::time_point now) {
	if (c.failures > 0 && c.failures < limit && now - c.first > window_) c.failures = 0; // earlier failures are outside the window
	if (c.failures == 0) c.first = now;
	if (++c.failures >= limit) c.locked_until = now + lockout_;
}

bool LoginThrottle::allowed(const std::string& username) {
	std::lock_guard<std::mutex> l(m_);
	const auto now = now_();
	if (locked(all_, overall_, now)) return false;
	auto it = users_.find(username);
	return it == users_.end() || !locked(it->second, per_user_, now);
}

void LoginThrottle::failed(const std::string& username) {
	std::lock_guard<std::mutex> l(m_);
	const auto now = now_();
	add(all_, overall_, now);
	if (users_.size() > 10000) users_.clear(); // bounded memory against a flood of made-up names
	add(users_[username], per_user_, now);
}

void LoginThrottle::succeeded(const std::string& username) {
	std::lock_guard<std::mutex> l(m_);
	users_.erase(username);
}

} // namespace proculus::web
