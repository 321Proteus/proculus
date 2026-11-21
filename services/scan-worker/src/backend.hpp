#ifndef PROCULUS_BACKEND_HPP
#define PROCULUS_BACKEND_HPP

#include <stdexcept>

#include "job.hpp"
#include "nmap_xml.hpp"
#include "process.hpp"

namespace proculus {

// A scan that could not complete (nmap failed, timed out, was cancelled, ...).
struct ScanFailed : std::runtime_error {
	ScanFailed(
		const std::string& what, bool timed_out = false, bool cancelled = false)
		: std::runtime_error(what), timed_out(timed_out), cancelled(cancelled) {
	}
	bool timed_out;
	bool cancelled;
};

// Something that can execute a validated scan command. The command comes from
// build_command(), so the scope, port and rate checks have already been applied
// whichever backend runs it
class ScanBackend {
public:
	virtual ~ScanBackend() = default;
	// Throws ScanFailed if the scan does not complete.
	virtual NmapResult run(const NmapCommand& cmd, const ScanJob& job) = 0;
};

// Runs the real nmap.
class NmapBackend : public ScanBackend {
public:
	// `cancel`, if set, aborts a running scan (e.g. when the window closes).
	explicit NmapBackend(std::atomic<bool>* cancel = nullptr)
		: cancel_(cancel) {}
	NmapResult run(const NmapCommand& cmd, const ScanJob& job) override;

private:
	std::atomic<bool>* cancel_;
};

} // namespace proculus

#endif // PROCULUS_BACKEND_HPP
