// exporter: lists stored scan runs and dumps them as text, JSON or CSV.
#include <getopt.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "proculus/results/results.hpp"
#include "dojo.hpp"
#include "render.hpp"

enum { OPT_STORE = 256, OPT_FORMAT, OPT_OUTPUT, OPT_FORCE, OPT_MIN_LEVEL, OPT_HELP };

static const option long_opts[] = {
	{ "store", required_argument, nullptr, OPT_STORE },
	{ "format", required_argument, nullptr, OPT_FORMAT },
	{ "output", required_argument, nullptr, OPT_OUTPUT },
	{ "force", no_argument, nullptr, OPT_FORCE },
	{ "min-level", required_argument, nullptr, OPT_MIN_LEVEL },
	{ "help", no_argument, nullptr, OPT_HELP },
	{ nullptr, 0, nullptr, 0 },
};

static void usage(const char* argv0) {
	std::cerr << "usage: " << argv0 << " --store DIR list [--format text|json|csv]\n"
		  << "       " << argv0 << " --store DIR show RUN [--format text|json|csv|defectdojo] [--min-level LEVEL] [--output FILE] [--force]\n"
		  << "  RUN may be a run number or 'latest'. Without --output the result goes to stdout.\n"
		  << "  defectdojo: a Generic Findings Import file for DefectDojo, one finding per service;\n"
		  << "  --min-level info|low|medium|high (default low) leaves out services below that priority.\n"
		  << "  An existing output file is only replaced with --force.\n";
}

int main(int argc, char** argv) {
	using namespace proculus;
	std::string store_dir, output;
	Format format = Format::Text;
	bool force = false;
	int min_level = 1;

	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_STORE: store_dir = optarg; break;
			case OPT_FORMAT: format = parse_format(optarg); break;
			case OPT_OUTPUT: output = optarg; break;
			case OPT_FORCE: force = true; break;
			case OPT_MIN_LEVEL: min_level = parse_dojo_min_level(optarg); break;
			case OPT_HELP: usage(argv[0]); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		if (store_dir.empty()) throw std::invalid_argument("--store DIR is required (see --help)");
		if (optind >= argc) throw std::invalid_argument("expected a command: list or show");
		const std::string command = argv[optind++];

		FileResultStore store(store_dir);
		std::string text;
		if (command == "list") {
			if (optind < argc) throw std::invalid_argument("list takes no arguments");
			text = render_list(store.list(), format);
		} else if (command == "show") {
			if (optind >= argc) throw std::invalid_argument("show needs a run number or 'latest'");
			const std::string which = argv[optind++];
			if (optind < argc) throw std::invalid_argument("unexpected argument: " + std::string(argv[optind]));

			int64_t id;
			if (which == "latest") {
				auto runs = store.list();
				if (runs.empty()) throw std::runtime_error("no runs stored in " + store_dir);
				id = runs.back().id;
			} else {
				if (which.empty() || which.size() > 15 || which.find_first_not_of("0123456789") != std::string::npos)
					throw std::invalid_argument("not a run number: " + which);
				id = std::stoll(which);
			}
			auto run = store.load(id);
			if (!run) throw std::runtime_error("no run " + std::to_string(id) + " in " + store_dir);
			text = render_run(*run, format, min_level);
		} else {
			throw std::invalid_argument("unknown command '" + command + "' (use list or show)");
		}

		if (output.empty()) {
			std::cout << text;
		} else {
			if (std::filesystem::exists(output) && !force)
				throw std::runtime_error(output + " already exists (use --force to replace it)");
			std::ofstream f(output, std::ios::binary | std::ios::trunc);
			f << text;
			f.flush();
			if (!f) throw std::runtime_error("cannot write " + output);
			std::cerr << "wrote " << output << "\n";
		}
		return 0;
	} catch (const FormatError& e) {
		std::cerr << "error: stored data is damaged: " << e.what() << "\n";
		return 3;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
