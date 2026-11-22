#ifndef PROCULUS_GATEWAY_SERVE_HPP
#define PROCULUS_GATEWAY_SERVE_HPP

namespace proculus {

// `gateway serve [options]`: argv[0] is "serve". Returns the exit code.
int serve_command(int argc, char** argv);

} // namespace proculus

#endif // PROCULUS_GATEWAY_SERVE_HPP
