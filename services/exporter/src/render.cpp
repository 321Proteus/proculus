#include "render.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace proculus {

Format parse_format(const std::string& name) {
	if (name == "text") return Format::Text;
	if (name == "json") return Format::Json;
	if (name == "csv") return Format::Csv;
	throw std::invalid_argument("unknown format '" + name + "' (use text, json or csv)");
}

std::string csv_field(const std::string& value, bool guard) {
	std::string v = value;
	if (guard && !v.empty() && std::string("=+-@\t\r").find(v[0]) != std::string::npos) v.insert(v.begin(), '\'');
	if (v.find_first_of(",\"\r\n") == std::string::npos) return v;
	std::string out = "\"";
	for (char c : v) {
		if (c == '"') out += '"';
		out += c;
	}
	return out + "\"";
}

namespace {

std::string pad(const std::string& s, size_t width) { return s.size() >= width ? s : s + std::string(width - s.size(), ' '); }

// Banners are untrusted: show control characters as '?' so they cannot move
// the cursor or inject escape sequences into a terminal.
std::string printable(const std::string& s) {
	std::string out = s;
	for (char& c : out)
		if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = '?';
	return out;
}

std::string run_text(const RunRecord& run) {
	std::ostringstream o;
	const RunSummary s = summarize(run);
	o << "Run " << run.id << "  (" << printable(run.source) << ")  " << printable(run.started) << " -> "
	  << printable(run.finished) << "\n"
	  << s.hosts << " hosts, " << s.services << " services; " << run.addresses_scanned << " addresses scanned in "
	  << run.chunks << " chunks (" << run.pauses << " pauses, " << run.cancelled_chunks << " chunks cut off)\n";

	for (const HostRecord& h : run.hosts) {
		o << "\n" << printable(h.ip);
		if (!h.hostname.empty()) o << "  " << printable(h.hostname);
		o << "\n";
		if (h.services.empty()) o << "    (no open services found)\n";
		for (const ServiceRecord& sv : h.services) {
			std::string what = printable(sv.product);
			if (!sv.version.empty()) what += (what.empty() ? "" : " ") + printable(sv.version);
			if (!sv.extrainfo.empty()) what += " (" + printable(sv.extrainfo) + ")";
			o << "    " << pad(std::to_string(sv.port) + "/" + printable(sv.protocol), 9) << pad(printable(sv.state), 7)
			  << pad(printable(sv.name), 11) << what << "\n";
		}
	}
	return o.str();
}

std::string run_csv(const RunRecord& run) {
	std::ostringstream o;
	o << "run,ip,hostname,port,protocol,state,service,product,version,extrainfo,confidence\n";
	for (const HostRecord& h : run.hosts) {
		if (h.services.empty()) {
			o << run.id << "," << csv_field(h.ip) << "," << csv_field(h.hostname) << ",,,,,,,,\n";
			continue;
		}
		for (const ServiceRecord& s : h.services) {
			o << run.id << "," << csv_field(h.ip) << "," << csv_field(h.hostname) << "," << s.port << ","
			  << csv_field(s.protocol) << "," << csv_field(s.state) << "," << csv_field(s.name) << ","
			  << csv_field(s.product) << "," << csv_field(s.version) << "," << csv_field(s.extrainfo) << ","
			  << s.confidence << "\n";
		}
	}
	return o.str();
}

} // namespace

std::string render_run(const RunRecord& run, Format f) {
	switch (f) {
	case Format::Json: return dump_json(run_to_json(run), 2) + "\n";
	case Format::Csv: return run_csv(run);
	case Format::Text: return run_text(run);
	}
	return "";
}

std::string render_list(const std::vector<RunSummary>& runs, Format f) {
	std::ostringstream o;
	switch (f) {
	case Format::Json: {
		Json arr = Json::array();
		for (const RunSummary& r : runs) {
			arr.push_back({ { "id", r.id }, { "source", r.source }, { "started", r.started },
				{ "finished", r.finished }, { "hosts", r.hosts }, { "services", r.services } });
		}
		return dump_json(arr, 2) + "\n";
	}
	case Format::Csv:
		o << "id,source,started,finished,hosts,services\n";
		for (const RunSummary& r : runs)
			o << r.id << "," << csv_field(r.source) << "," << csv_field(r.started) << "," << csv_field(r.finished) << ","
			  << r.hosts << "," << r.services << "\n";
		return o.str();
	case Format::Text:
		if (runs.empty()) return "no runs stored\n";
		o << pad("RUN", 6) << pad("SOURCE", 8) << pad("STARTED", 22) << pad("FINISHED", 22) << pad("HOSTS", 7) << "SERVICES\n";
		for (const RunSummary& r : runs)
			o << pad(std::to_string(r.id), 6) << pad(printable(r.source), 8) << pad(printable(r.started), 22)
			  << pad(printable(r.finished), 22) << pad(std::to_string(r.hosts), 7) << r.services << "\n";
		return o.str();
	}
	return "";
}

} // namespace proculus
