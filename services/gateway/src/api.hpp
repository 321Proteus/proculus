#ifndef PROCULUS_GATEWAY_API_HPP
#define PROCULUS_GATEWAY_API_HPP

// The data behind the web UI, as JSON. Pure functions of the stored runs: no
// sockets here, so everything can be tested directly. The HTTP layer (server.cpp)
// only routes requests to these and maps the exceptions to status codes.

#include <stdexcept>
#include <string>

#include "proculus/edits/edits.hpp"
#include "proculus/results/results.hpp"

namespace proculus {

struct ApiError : std::runtime_error {
	ApiError(int status, const std::string& message) : std::runtime_error(message), status(status) {}
	int status;
};

struct ServicesQuery {
	std::string text;     // case-insensitive substring of address, host name, service, title or detection
	int min_score = 0;
	size_t limit = 50;    // 1..500
	size_t offset = 0;
	bool hide_ignored = false; // leave out services whose (edited) status is ignored or false_positive
	bool only_edited = false;  // only services or hosts somebody has edited
	std::string category;      // only services with a technology of this category (cms, framework, server, iot, admin, staging, other, ...)
};

struct ExportQuery {
	ServicesQuery filter;      // which services (limit and offset are ignored)
	std::string row;           // template for every service, see export_format.hpp (required)
	std::string header, footer; // optional; {run} and {count} only
	bool unique = false;       // drop rows that come out identical (e.g. only {ip})
	size_t limit = 50000;      // most rows returned (1..100000)
};

class Api {
public:
	// `edits` (optional, must outlive the Api) are applied on top of what the runs say: an edited host
	// name, priority and status show instead of the scanned ones (the scan values stay in the answer
	// too), and services marked ignored or false positive stay out of the dashboard.
	explicit Api(const ResultStore& store, EditStore* edits = nullptr) : store_(store), edits_(edits) {}

	Json runs() const;
	// `which` is a run number or "latest".
	Json dashboard(const std::string& which) const;
	Json services(const std::string& which, const ServicesQuery& q) const;
	// The services as text through the user's template: {run, rows, truncated, text}. 400 for a bad template.
	Json export_text(const std::string& which, const ExportQuery& q) const;
	Json diff(const std::string& before, const std::string& after) const;
	// Host states over time (replays all runs): counts and the hosts that need attention.
	Json hosts() const;

	// ---- user edits (404 if the server has no edit store; EditError for bad edits)
	bool has_edits() const { return edits_ != nullptr; }
	Json edits() const;
	Json apply_edit(const EditKey& key, const Json& changes, const std::string& user) const;
	Json clear_edit(const EditKey& key) const;

private:
	RunRecord load(const std::string& which) const;
	const ResultStore& store_;
	EditStore* edits_;
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_API_HPP
