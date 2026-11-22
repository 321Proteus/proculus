#include <iostream>

#include "commands.hpp"

int main(int argc, char** argv) {
	std::vector<std::string> args(argv + 1, argv + argc);
	try {
		return proculus::run_signatures_tool(args, std::cin, std::cout, std::cerr);
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 2;
	}
}
