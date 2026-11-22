#ifndef PROCULUS_RUNNER_RESOLVER_HPP
#define PROCULUS_RUNNER_RESOLVER_HPP

#include <functional>
#include <string>
#include <vector>

namespace proculus {

// Domain name -> IPv4 addresses (empty if it does not resolve). The runner
// checks every address against the scope before scanning it, so a name that
// points outside the allowed networks is refused, not followed.
using Resolver = std::function<std::vector<std::string>(const std::string& domain)>;

// The system resolver (getaddrinfo), IPv4 only, at most 8 addresses.
std::vector<std::string> system_resolve(const std::string& domain);

} // namespace proculus

#endif // PROCULUS_RUNNER_RESOLVER_HPP
