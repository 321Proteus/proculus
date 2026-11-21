#include "backend.hpp"

namespace proculus {

NmapResult NmapBackend::run(const NmapCommand& cmd, const ScanJob&) {
	RunOptions ro;
	ro.timeout = std::chrono::seconds(cmd.timeout_s);
	ro.cancel = cancel_;
	RunResult rr = run_process(cmd.argv, ro);

	if (rr.timed_out)
		throw ScanFailed("nmap exceeded the " + std::to_string(cmd.timeout_s) + " s limit and was stopped", true);
	if (rr.cancelled) throw ScanFailed("scan was cancelled", false, true);
	if (rr.exit_code != 0)
		throw ScanFailed("nmap failed (exit " + std::to_string(rr.exit_code) + ", signal " +
			std::to_string(rr.term_signal) + "): " + rr.err);
	if (rr.output_truncated) throw ScanFailed("nmap output exceeded the size limit");
	return parse_nmap_xml(rr.out);
}

} // namespace proculus
