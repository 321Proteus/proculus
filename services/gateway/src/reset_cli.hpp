#ifndef PROCULUS_GATEWAY_RESET_CLI_HPP
#define PROCULUS_GATEWAY_RESET_CLI_HPP

// `gateway reset --store DIR [--runs] [--yes]`: gives a file store a fresh start.
// It removes only what Proculus itself keeps there besides the runs: accounts/ (so the
// next start asks for the setup token again), edits/ and scan-config.json; with --runs
// also the saved runs (run-NNNNNN.json). Nothing else in DIR is touched, and without
// --yes it only lists what it would remove. Stop the gateway first.

#include <filesystem>
#include <string>
#include <vector>

namespace proculus {

// What reset would remove from `dir` (existing entries only). Symbolic links are left alone.
std::vector<std::filesystem::path> reset_targets(const std::filesystem::path& dir, bool include_runs);
// Removes them; returns how many entries were removed.
size_t reset_store(const std::filesystem::path& dir, bool include_runs);

// argv[0] is "reset".
int reset_command(int argc, char** argv);

} // namespace proculus

#endif
