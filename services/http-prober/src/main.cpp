// http-prober: looks at web services and reports what they show. It checks
// each target against the configured scope and ports before sending anything.
#include <getopt.h>

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "proculus/netutil/cidr.h"
#include "proculus/results/results.hpp"
#include "evidence.hpp"
#include "proculus/sig/builtin.hpp"
#include "proculus/sig/evidence_json.hpp"
#include "prober.hpp"
#include "web_record.hpp"
#include "report.hpp"

enum { OPT_SCOPE = 256, OPT_PORTS, OPT_HOST, OPT_FORMAT, OPT_BODY, OPT_COOKIE_VALUES, OPT_NO_FAVICON, OPT_RATE, OPT_REDIRECTS,
	OPT_CONNECT_TIMEOUT, OPT_TIMEOUT, OPT_MAX_BODY, OPT_ALLOW_RESERVED, OPT_STORE, OPT_RUN, OPT_SIGNATURES, OPT_NO_BUILTIN_SIGS, OPT_NO_SIGS, OPT_NO_PATHS, OPT_MAX_PATHS,
	OPT_MIN_CONFIDENCE, OPT_DUMP_EVIDENCE, OPT_SAVE_RUN, OPT_HELP };

static const option long_opts[] = {
	{ "scope", required_argument, nullptr, OPT_SCOPE },
	{ "allowed-ports", required_argument, nullptr, OPT_PORTS },
	{ "host", required_argument, nullptr, OPT_HOST },
	{ "format", required_argument, nullptr, OPT_FORMAT },
	{ "include-body", no_argument, nullptr, OPT_BODY },
	{ "keep-cookie-values", no_argument, nullptr, OPT_COOKIE_VALUES },
	{ "no-favicon", no_argument, nullptr, OPT_NO_FAVICON },
	{ "rate", required_argument, nullptr, OPT_RATE },
	{ "max-redirects", required_argument, nullptr, OPT_REDIRECTS },
	{ "connect-timeout", required_argument, nullptr, OPT_CONNECT_TIMEOUT },
	{ "timeout", required_argument, nullptr, OPT_TIMEOUT },
	{ "max-body", required_argument, nullptr, OPT_MAX_BODY },
	{ "allow-reserved", no_argument, nullptr, OPT_ALLOW_RESERVED },
	{ "store", required_argument, nullptr, OPT_STORE },
	{ "run", required_argument, nullptr, OPT_RUN },
	{ "signatures", required_argument, nullptr, OPT_SIGNATURES },
	{ "no-builtin-signatures", no_argument, nullptr, OPT_NO_BUILTIN_SIGS },
	{ "no-signatures", no_argument, nullptr, OPT_NO_SIGS },
	{ "no-paths", no_argument, nullptr, OPT_NO_PATHS },
	{ "max-paths", required_argument, nullptr, OPT_MAX_PATHS },
	{ "min-confidence", required_argument, nullptr, OPT_MIN_CONFIDENCE },
	{ "dump-evidence", no_argument, nullptr, OPT_DUMP_EVIDENCE },
	{ "save-run", no_argument, nullptr, OPT_SAVE_RUN },
	{ "help", no_argument, nullptr, OPT_HELP },
	{ nullptr, 0, nullptr, 0 },
};

static void usage(const char* argv0) {
	std::cerr
		<< "usage: " << argv0 << " --scope LIST --allowed-ports LIST [options] TARGET...\n"
		<< "       " << argv0 << " --scope LIST --allowed-ports LIST --store DIR --run N|latest [options]\n"
		<< "  TARGET               ip:port, or http://ip[:port] / https://ip[:port]\n"
		<< "  --scope LIST         hard limit: only these addresses may be probed (required)\n"
		<< "  --allowed-ports LIST hard limit: only these ports may be probed (required)\n"
		<< "  --store DIR --run R  probe the web services found in a saved run instead of listing targets\n"
		<< "  --host NAME          Host header / TLS server name to use for the targets\n"
		<< "  --format text|json   (default text)      --include-body   include the page body in JSON\n"
		<< "  --keep-cookie-values store cookie values (by default only names and attributes)\n"
		<< "  --no-favicon         do not fetch the favicon\n"
		<< "  --rate N             requests per second (default 10)     --max-redirects N (default 3)\n"
		<< "  --connect-timeout MS (default 3000)   --timeout MS whole exchange (default 8000)   --max-body BYTES (default 131072)\n"
		<< "  --allow-reserved     allow loopback/multicast/link-local addresses\n"
		<< "signatures (what the service is, from what it shows):\n"
		<< "  --signatures PATH    also load custom signatures from a JSON file or a directory of them (repeatable)\n"
		<< "  --no-builtin-signatures   only use the custom ones     --no-signatures   do not detect anything\n"
		<< "  --no-paths           never fetch extra paths (/wp-login.php, /phpmyadmin/, ...) for signatures\n"
		<< "  --max-paths N        at most N extra paths per service, most valuable first (default 8)\n"
		<< "  --min-confidence C   hide detections below C, 0..1 (default 0: each signature has its own threshold)\n"
		<< "  --dump-evidence      print the facts signatures were matched against (JSON, to stderr)\n"
		<< "  --save-run           with --store/--run: save a copy of the run with the web results and detections attached\n"
		<< "                       as a new run (so `differ` can follow web changes)\n";
}

static double to_double(const char* s, const char* what) {
	try {
		size_t pos = 0;
		double v = std::stod(s, &pos);
		if (s[pos] != '\0') throw std::invalid_argument("");
		return v;
	} catch (const std::exception&) {
		throw std::invalid_argument(std::string("invalid number for ") + what + ": " + s);
	}
}

// "10.0.0.5:8080", "http://10.0.0.5", "https://10.0.0.5:8443"
static proculus::ProbeTarget parse_target(const std::string& text, const std::string& host) {
	std::string rest = text;
	std::optional<bool> tls;
	if (rest.compare(0, 7, "http://") == 0) {
		tls = false;
		rest = rest.substr(7);
	} else if (rest.compare(0, 8, "https://") == 0) {
		tls = true;
		rest = rest.substr(8);
	}
	if (const size_t slash = rest.find('/'); slash != std::string::npos) rest.erase(slash);
	std::string ip = rest;
	unsigned long port = tls ? (*tls ? 443 : 80) : 0;
	if (const size_t colon = rest.find(':'); colon != std::string::npos) {
		ip = rest.substr(0, colon);
		const std::string p = rest.substr(colon + 1);
		if (p.empty() || p.size() > 5 || p.find_first_not_of("0123456789") != std::string::npos) throw std::invalid_argument("bad port in target: " + text);
		port = std::stoul(p);
	}
	if (port == 0 || port > 65535) throw std::invalid_argument("target needs a port (ip:port or http(s)://ip): " + text);
	return proculus::ProbeTarget(ip, static_cast<uint16_t>(port), tls, host);
}

int main(int argc, char** argv) {
	using namespace proculus;
	ProbeLimits limits;
	std::string host, store_dir, run_arg, format = "text";
	bool include_body = false, builtin_sigs = true, use_sigs = true, use_paths = true, dump_evidence = false, save_run = false;
	size_t max_paths = 8;
	double min_confidence = 0;
	std::vector<std::string> sig_paths;
	std::vector<std::string> positional;

	try {
		opterr = 0;
		int opt;
		while ((opt = getopt_long(argc, argv, "", long_opts, nullptr)) != -1) {
			switch (opt) {
			case OPT_SCOPE: limits.scope = optarg; break;
			case OPT_PORTS: limits.allowed_ports = optarg; break;
			case OPT_HOST: host = optarg; break;
			case OPT_FORMAT:
				format = optarg;
				if (format != "text" && format != "json") throw std::invalid_argument("unknown format '" + format + "' (use text or json)");
				break;
			case OPT_BODY: include_body = true; break;
			case OPT_COOKIE_VALUES: limits.keep_cookie_values = true; break;
			case OPT_NO_FAVICON: limits.fetch_favicon = false; break;
			case OPT_RATE: limits.max_requests_per_second = to_double(optarg, "--rate"); break;
			case OPT_REDIRECTS: limits.max_redirects = static_cast<int>(to_double(optarg, "--max-redirects")); break;
			case OPT_CONNECT_TIMEOUT: limits.transport.connect_timeout_ms = static_cast<int>(to_double(optarg, "--connect-timeout")); break;
			case OPT_TIMEOUT: limits.transport.total_timeout_ms = static_cast<int>(to_double(optarg, "--timeout")); break;
			case OPT_MAX_BODY: limits.transport.max_body = static_cast<size_t>(to_double(optarg, "--max-body")); break;
			case OPT_ALLOW_RESERVED: limits.allow_reserved = true; break;
			case OPT_STORE: store_dir = optarg; break;
			case OPT_RUN: run_arg = optarg; break;
			case OPT_SIGNATURES: sig_paths.push_back(optarg); break;
			case OPT_NO_BUILTIN_SIGS: builtin_sigs = false; break;
			case OPT_NO_SIGS: use_sigs = false; break;
			case OPT_NO_PATHS: use_paths = false; break;
			case OPT_MAX_PATHS: max_paths = static_cast<size_t>(to_double(optarg, "--max-paths")); break;
			case OPT_MIN_CONFIDENCE:
				min_confidence = to_double(optarg, "--min-confidence");
				if (min_confidence < 0 || min_confidence > 1) throw std::invalid_argument("--min-confidence must be between 0 and 1");
				break;
			case OPT_DUMP_EVIDENCE: dump_evidence = true; break;
			case OPT_SAVE_RUN: save_run = true; break;
			case OPT_HELP: usage(argv[0]); return 0;
			default: throw std::invalid_argument(std::string("bad option: ") + argv[optind - 1]);
			}
		}
		while (optind < argc) positional.push_back(argv[optind++]);

		std::vector<ProbeTarget> targets;
		std::vector<std::pair<size_t, size_t>> where; // (host, service) in the loaded run, per target
		std::optional<RunRecord> source_run;
		std::optional<FileResultStore> store;
		if (!store_dir.empty() || !run_arg.empty()) {
			if (store_dir.empty() || run_arg.empty()) throw std::invalid_argument("--store and --run go together");
			if (!positional.empty()) throw std::invalid_argument("give either targets or --store/--run, not both");
			store.emplace(store_dir);
			int64_t id;
			if (run_arg == "latest") {
				auto runs = store->list();
				if (runs.empty()) throw std::runtime_error("no runs stored in " + store_dir);
				id = runs.back().id;
			} else {
				if (run_arg.size() > 15 || run_arg.find_first_not_of("0123456789") != std::string::npos) throw std::invalid_argument("not a run number: " + run_arg);
				id = std::stoll(run_arg);
			}
			auto run = store->load(id);
			if (!run) throw std::runtime_error("no run " + std::to_string(id) + " in " + store_dir);
			for (size_t hi = 0; hi < run->hosts.size(); hi++)
				for (size_t si = 0; si < run->hosts[hi].services.size(); si++) {
					const HostRecord& h = run->hosts[hi];
					const ServiceRecord& s = h.services[si];
					if (auto tls = web_service_scheme(s.name, s.port)) {
						where.emplace_back(hi, si);
						targets.emplace_back(h.ip, s.port, *tls, host);
						targets.back().service = { s.name, s.product, s.version, {} };
						if (!h.hostname.empty()) targets.back().service.hostnames.push_back(h.hostname);
					}
				}
			std::cerr << "run " << id << ": " << targets.size() << " web services\n";
			source_run = std::move(*run);
		} else {
			for (const std::string& t : positional) targets.push_back(parse_target(t, host));
		}
		if (save_run && !source_run) throw std::invalid_argument("--save-run needs --store and --run");
		if (targets.empty()) throw std::invalid_argument("nothing to probe (see --help)");

		// ---- signatures
		sig::SignatureSet sigs;
		if (use_sigs) {
			if (builtin_sigs) sigs = sig::builtin_signatures();
			bool bad = false;
			for (const std::string& path : sig_paths) {
				const std::filesystem::path fp(path);
				std::error_code ec;
				sig::LoadResult r = std::filesystem::is_directory(fp, ec) ? sigs.add_directory(fp) : sigs.add_file(fp);
				for (const sig::Diagnostic& d : r.diagnostics) {
					std::cerr << (d.level == sig::Diagnostic::Level::Error ? "error: " : "warning: ") << d.source;
					if (!d.signature.empty()) std::cerr << ": " << d.signature;
					if (!d.where.empty()) std::cerr << ": " << d.where;
					std::cerr << ": " << d.message << "\n";
				}
				bad |= r.has_errors();
			}
			if (bad) throw std::invalid_argument("custom signatures have errors; fix them (see `signatures lint`) or leave them out");
			if (use_paths && max_paths > 0) limits.probe_paths = sigs.required_paths(max_paths);
		}

		SocketTransport transport;
		HttpProber prober(transport, limits);

		int refused = 0;
		ProbeJson all = ProbeJson::array();
		RunRecord enriched;
		if (save_run) {
			enriched = *source_run;
			enriched.id = 0;
			enriched.source += "+web";
		}
		size_t probed = 0;
		for (size_t ti = 0; ti < targets.size(); ti++) {
			const ProbeTarget& t = targets[ti];
			try {
				HttpObservation o = prober.probe(t);
				Detections det;
				const Detections* dp = nullptr;
				if (use_sigs) {
					const sig::Evidence ev = to_evidence(o);
					det.found = sig::evaluate(sigs, ev, &det.stats);
					det.found.erase(std::remove_if(det.found.begin(), det.found.end(), [&](const sig::Detection& d) { return d.confidence < min_confidence; }),
						det.found.end());
					dp = &det;
					if (dump_evidence) std::cerr << sig::evidence_to_json(ev).dump(2, ' ', false, ProbeJson::error_handler_t::replace) << "\n";
				}
				if (save_run && o.status > 0) {
					enriched.hosts[where[ti].first].services[where[ti].second].web = to_web_record(o, dp ? dp->found : std::vector<sig::Detection>{});
					probed++;
				}
				if (format == "json") all.push_back(probe_to_json(o, include_body, dp));
				else std::cout << probe_to_text(o, dp) << "\n";
			} catch (const ProbeRefused& e) {
				refused++;
				if (format == "json") all.push_back({ { "ip", t.ip }, { "port", t.port }, { "refused", e.what() } });
				else std::cout << t.ip << ":" << t.port << "  REFUSED: " << e.what() << "\n\n";
			}
		}
		if (save_run) {
			const int64_t new_id = store->save(std::move(enriched));
			std::cerr << "saved run " << new_id << " (" << probed << " web services with results)\n";
		}
		if (format == "json") std::cout << all.dump(2, ' ', false, ProbeJson::error_handler_t::replace) << "\n";
		return refused ? 4 : 0;
	} catch (const FormatError& e) {
		std::cerr << "error: stored data is damaged: " << e.what() << "\n";
		return 3;
	} catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}
}
