#ifndef PROCULUS_GATEWAY_USERS_CLI_HPP
#define PROCULUS_GATEWAY_USERS_CLI_HPP

namespace proculus {

// `gateway user ...`: manage accounts straight in the database. argv[0] is "user".
// This is how the first administrator is created: there are no default accounts.
int users_command(int argc, char** argv);

} // namespace proculus

#endif
