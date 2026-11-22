#ifndef PROCULUS_SIGNATURES_COMMANDS_HPP
#define PROCULUS_SIGNATURES_COMMANDS_HPP

// The `signatures` tool: look at the built-in detection signatures, check and
// test your own, and see what they would say about some evidence. The commands
// are plain functions over streams so tests can drive them.

#include <iosfwd>
#include <string>
#include <vector>

namespace proculus {

// args excludes the program name: {"lint", "mine.json"}. Returns the exit code:
// 0 ok, 1 problems found in signatures or examples (lint, test), 2 usage error
// or unreadable input.
int run_signatures_tool(const std::vector<std::string>& args, std::istream& in, std::ostream& out, std::ostream& err);

void print_signatures_usage(std::ostream& out, const char* argv0);

} // namespace proculus

#endif // PROCULUS_SIGNATURES_COMMANDS_HPP
