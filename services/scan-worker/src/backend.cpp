#include "backend.hpp"

namespace proculus {

namespace {

// The value of attr="..." inside one XML tag ("" if absent).
std::string attribute(const std::string& tag, const char* name) {
	const std::string key = std::string(" ") + name + "=\"";
	const size_t a = tag.find(key);
	if (a == std::string::npos) return "";
	const size_t from = a + key.size(), to = tag.find('"', from);
	return to == std::string::npos ? "" : tag.substr(from, to - from);
}

// Reads the <taskprogress .../> elements nmap writes with --stats-every as they arrive.
struct ProgressReader {
	std::function<void(double, double)> report;
	size_t pos = 0;
	double scanned = 0, identified = 0;
	void feed(const std::string& out) {
		for (;;) {
			const size_t i = out.find("<taskprogress ", pos);
			if (i == std::string::npos) return;
			const size_t j = out.find("/>", i);
			if (j == std::string::npos) return; // not complete yet
			pos = j + 2;
			const std::string tag = out.substr(i, j - i);
			const std::string task = attribute(tag, "task");
			double percent = 0;
			try {
				percent = std::stod(attribute(tag, "percent"));
			} catch (const std::exception&) {
				continue;
			}
			const double f = percent < 0 ? 0 : percent > 100 ? 1 : percent / 100;
			if (task == "Service scan") {
				scanned = 1;
				identified = f;
			} else if (task == "Connect Scan" || task == "SYN Stealth Scan") {
				scanned = f;
			} else {
				continue;
			}
			report(scanned, identified);
		}
	}
};

} // namespace

NmapResult NmapBackend::run(const NmapCommand& cmd, const ScanJob& job) {
	RunOptions ro;
	ro.timeout = std::chrono::seconds(cmd.timeout_s);
	ro.cancel = cancel_;
	ProgressReader progress;
	if (job.on_progress) {
		progress.report = job.on_progress;
		ro.on_output = [&progress](const std::string& out) { progress.feed(out); };
	}
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
