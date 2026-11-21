#include "job.hpp"

#include <algorithm>
#include <sstream>

#include "proculus/netutil/ipset.hpp"
#include "proculus/netutil/portset.hpp"

namespace proculus {

namespace {

[[noreturn]] void reject(const std::string& why) { throw JobRejected(why); }

std::vector<std::string> split(const std::string& s, char sep) {
	std::vector<std::string> out;
	std::string cur;
	std::istringstream in(s);
	while (std::getline(in, cur, sep))
		if (!cur.empty()) out.push_back(cur);
	return out;
}

void load(IpSet& set, const std::string& list, const char* what) {
	try {
		set.add_list(list);
	} catch (const std::invalid_argument&) {
		reject(std::string("invalid ") + what + ": " + list);
	}
}

void load(PortSet& set, const std::string& list, const char* what) {
	try {
		set.add_list(list);
	} catch (const std::invalid_argument&) {
		reject(std::string("invalid ") + what + ": " + list);
	}
}

} // namespace

NmapCommand build_command(
	const ScanJob& job, const JobLimits& limits, const std::string& nmap_path) {
	if (limits.scope.empty()) reject("no scope configured: refusing to scan");
	if (limits.allowed_ports.empty())
		reject("no allowed ports configured: refusing to scan");
	if (job.rate < 1) reject("rate must be >= 1");
	if (job.rate > limits.max_rate)
		reject("rate " + std::to_string(job.rate) + " exceeds the limit of " +
			std::to_string(limits.max_rate));
	if (job.timing < 0 || job.timing > 4)
		reject("timing must be 0..4 (aggressive -T5 is not allowed)");
	if (job.retries < 0 || job.retries > 5) reject("retries must be 0..5");
	if (job.host_timeout_s < 1) reject("host timeout must be >= 1 s");
	if (job.timeout_s < 1) reject("timeout must be >= 1 s");

	NmapCommand cmd;
	cmd.timeout_s = std::min(job.timeout_s, limits.max_timeout_s);

	// --- targets: strip reserved space, then require everything to be in scope
	IpSet targets, scope;
	load(targets, job.targets, "targets");
	load(scope, limits.scope, "scope");
	uint64_t requested = targets.count();
	if (!limits.allow_reserved) targets.subtract_reserved();
	cmd.target_count = targets.count();
	cmd.reserved_stripped = requested - cmd.target_count;
	if (cmd.target_count == 0)
		reject("no scannable targets (empty or all reserved)");

	IpSet outside = targets.slice(0, cmd.target_count);
	outside.subtract(scope);
	if (outside.count() > 0)
		reject(std::to_string(outside.count()) +
			" target address(es) outside the allowed scope, e.g. " +
			outside.slice(0, 1).format());

	// --- ports
	PortSet allowed, requested_ports;
	load(allowed, limits.allowed_ports, "allowed ports");

	std::string port_arg;
	if (job.stage == Stage::Services) {
		if (job.ports.empty()) {
			port_arg = allowed.format();
		} else {
			load(requested_ports, job.ports, "ports");
			uint32_t want = requested_ports.count();
			requested_ports.intersect(allowed);
			if (requested_ports.count() != want)
				reject("ports outside the allowed list were requested: " +
					job.ports);
			port_arg = requested_ports.format();
		}
	}

	// --- command line (argv vector: no shell involved)
	std::vector<std::string>& a = cmd.argv;
	a = { nmap_path, "-oX", "-", "-n", "--no-stylesheet",
		"-T" + std::to_string(job.timing), "--max-retries",
		std::to_string(job.retries), "--host-timeout",
		std::to_string(job.host_timeout_s) + "s", "--max-rate",
		std::to_string(job.rate) };

	if (job.stage == Stage::Discovery) {
		a.push_back("-sn");
		PortSet probe;
		load(probe, job.probe_ports, "probe ports");
		probe.intersect(allowed);
		if (probe.count() > 0) a.push_back("-PS" + probe.format());
		if (job.privileged) a.push_back("-PE");
	} else {
		a.push_back("-Pn"); // hosts were already found by the discovery stage
		a.push_back(job.privileged ? "-sS" : "-sT");
		a.push_back("--open");
		a.push_back("-p");
		a.push_back(port_arg);
		if (job.version_detect) {
			a.push_back("-sV");
			a.push_back("--version-intensity");
			a.push_back("2");
		}
	}

	cmd.targets = targets.format(',');
	cmd.ports = port_arg;
	for (const auto& t : split(cmd.targets, ','))
		a.push_back(t);
	return cmd;
}

} // namespace proculus
