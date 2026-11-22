#ifndef PROCULUS_RUNNER_SOCKET_TRANSPORT_INCLUDE_HPP
#define PROCULUS_RUNNER_SOCKET_TRANSPORT_INCLUDE_HPP

#include <memory>

#include "transport.hpp"

namespace proculus {

inline std::unique_ptr<HttpTransport> make_socket_transport() { return std::make_unique<SocketTransport>(); }

} // namespace proculus

#endif
