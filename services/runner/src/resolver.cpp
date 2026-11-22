#include "resolver.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <algorithm>

namespace proculus {

std::vector<std::string> system_resolve(const std::string& domain) {
	std::vector<std::string> out;
	addrinfo hints{};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	addrinfo* res = nullptr;
	if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) != 0 || !res) return out;
	for (addrinfo* p = res; p && out.size() < 8; p = p->ai_next) {
		char buf[INET_ADDRSTRLEN];
		const auto* sin = reinterpret_cast<const sockaddr_in*>(p->ai_addr);
		if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf)) {
			const std::string ip = buf;
			if (std::find(out.begin(), out.end(), ip) == out.end()) out.push_back(ip);
		}
	}
	freeaddrinfo(res);
	return out;
}

} // namespace proculus
