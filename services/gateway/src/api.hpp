#ifndef PROCULUS_GATEWAY_API_HPP
#define PROCULUS_GATEWAY_API_HPP

// The data behind the web UI, as JSON. Pure functions of the stored runs: no
// sockets here, so everything can be tested directly. The HTTP layer (server.cpp)
// only routes requests to these and maps the exceptions to status codes.

#include <stdexcept>
#include <string>

#include "proculus/results/results.hpp"

namespace proculus {

struct ApiError : std::runtime_error {
	ApiError(int status, const std::string& message) : std::runtime_error(message), status(status) {}
	int status;
};

struct ServicesQuery {
	std::string text;     // case-insensitive substring of address, host name, service, title or detection
	int min_score = 0;
	size_t limit = 50;    // 1..500
	size_t offset = 0;
};

class Api {
public:
	explicit Api(const ResultStore& store) : store_(store) {}

	Json runs() const;
	// `which` is a run number or "latest".
	Json dashboard(const std::string& which) const;
	Json services(const std::string& which, const ServicesQuery& q) const;
	Json diff(const std::string& before, const std::string& after) const;
	// Host states over time (replays all runs): counts and the hosts that need attention.
	Json hosts() const;

private:
	RunRecord load(const std::string& which) const;
	const ResultStore& store_;
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_API_HPP
