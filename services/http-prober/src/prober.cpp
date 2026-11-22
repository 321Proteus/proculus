#include "prober.hpp"

#include <algorithm>
#include <set>
#include <thread>

#include "proculus/netutil/ipset.hpp"
#include "proculus/netutil/portset.hpp"

namespace proculus {

// ------------------------------------------------------------------- gate

RateGate::RateGate(double per_second, std::function<Clock::time_point()> now, std::function<void(std::chrono::nanoseconds)> sleep)
	: now_(std::move(now)), sleep_(std::move(sleep)) {
	if (!(per_second > 0)) throw std::invalid_argument("request rate must be > 0");
	interval_ = std::chrono::nanoseconds(static_cast<long long>(1e9 / per_second));
}

void RateGate::wait() {
	const auto t = now_();
	if (next_ && t < *next_) {
		sleep_(*next_ - t);
		next_ = *next_ + interval_;
	} else {
		next_ = t + interval_;
	}
}

// ----------------------------------------------------------------- helpers

bool default_tls_port(uint16_t port) { return port == 443 || port == 8443 || port == 9443 || port == 4443 || port == 10443; }

std::optional<bool> web_service_scheme(const std::string& name, uint16_t port) {
	std::string n = name;
	std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	if (n.find("https") != std::string::npos || n.find("ssl/http") != std::string::npos) return true;
	if (n.find("http") != std::string::npos) return default_tls_port(port); // "http-alt" on 8443 is TLS in practice
	if (n.empty() || n == "unknown" || n == "tcpwrapped") {
		if (port == 80 || port == 8080 || port == 8000 || port == 8888) return false;
		if (default_tls_port(port)) return true;
	}
	return std::nullopt;
}

namespace {

std::string lower_copy(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

// Set-Cookie values are session secrets: keep names and attributes only.
void redact_cookie_headers(std::vector<Header>& headers) {
	for (Header& h : headers)
		if (lower_copy(h.name) == "set-cookie") h.value = redact_set_cookie(h.value);
}

bool looks_like_html(const std::string& content_type, const std::string& body) {
	const std::string ct = lower_copy(content_type);
	if (ct.find("html") != std::string::npos || ct.find("xml") != std::string::npos) return true;
	return ct.empty() && body.find('<') != std::string::npos;
}

} // namespace

// ------------------------------------------------------------------ prober

HttpProber::HttpProber(HttpTransport& transport, ProbeLimits limits) : HttpProber(transport, limits, RateGate(limits.max_requests_per_second)) {}

HttpProber::HttpProber(HttpTransport& transport, ProbeLimits limits, RateGate gate)
	: transport_(transport), limits_(std::move(limits)), gate_(std::move(gate)) {
	if (limits_.scope.empty()) throw std::invalid_argument("no scope configured: refusing to probe");
	if (limits_.allowed_ports.empty()) throw std::invalid_argument("no allowed ports configured: refusing to probe");
	for (const std::string& path : limits_.probe_paths)
		if (!valid_path(path) || path.find('?') != std::string::npos || path.find('#') != std::string::npos)
			throw std::invalid_argument("unusable probe path: " + path);
	if (limits_.max_redirects < 0 || limits_.max_redirects > 10) throw std::invalid_argument("max_redirects must be 0..10");
	if (!(limits_.max_requests_per_second > 0)) throw std::invalid_argument("request rate must be > 0");
}

HttpObservation HttpProber::probe(const ProbeTarget& target) {
	// ---- is this target allowed at all?
	uint32_t ip_value;
	if (pc_ip_parse(target.ip.c_str(), &ip_value) != 0) throw ProbeRefused("not an IPv4 address: " + target.ip);
	if (target.port == 0) throw ProbeRefused("port 0 is not valid");
	if (!target.host.empty() && !valid_host(target.host)) throw ProbeRefused("invalid host name: " + target.host);

	IpSet scope;
	try {
		scope.add_list(limits_.scope);
	} catch (const std::invalid_argument&) {
		throw ProbeRefused("invalid scope configuration");
	}
	if (!scope.contains(ip_value)) throw ProbeRefused(target.ip + " is outside the allowed scope");
	if (!limits_.allow_reserved && pc_ip_is_reserved(ip_value)) throw ProbeRefused(target.ip + " is a reserved address");

	PortSet ports;
	ports.add_list(limits_.allowed_ports);
	if (!ports.contains(target.port)) throw ProbeRefused("port " + std::to_string(target.port) + " is not in the allowed list");

	const std::string host = lower_copy(target.host);
	const auto started = std::chrono::steady_clock::now();
	HttpObservation obs;
	obs.ip = target.ip;
	obs.port = target.port;
	obs.host = host;
	obs.service = target.service;

	Url url;
	url.scheme = target.tls.value_or(default_tls_port(target.port)) ? "https" : "http";
	url.host = host.empty() ? target.ip : host;
	url.port = target.port;
	url.path = "/";

	// A redirect may only lead to the same site: the address we were asked to
	// probe, or the host name we were given for it.
	auto same_site = [&](const Url& u) { return u.host == target.ip || (!host.empty() && u.host == host); };
	auto port_allowed = [&](uint16_t p) { return ports.contains(p); };
	auto endpoint_for = [&](const Url& u) {
		Endpoint e;
		e.ip = target.ip;
		e.port = u.port;
		e.tls = u.scheme == "https";
		e.host = u.host == target.ip ? "" : u.host;
		return e;
	};

	std::set<std::string> visited;
	std::vector<Cookie> cookies;
	Exchange last;
	Url final_url = url;
	bool have_response = false;

	for (int hop = 0; hop <= limits_.max_redirects; hop++) {
		visited.insert(url.to_string());
		gate_.wait();
		obs.requests++;
		last = transport_.get(endpoint_for(url), url.path, limits_.transport);
		final_url = url;
		if (!last.response) break;
		have_response = true;

		for (const Header& h : last.response->headers) {
			if (lower_copy(h.name) != "set-cookie") continue;
			if (auto c = parse_set_cookie(h.value, limits_.keep_cookie_values)) {
				auto same = std::find_if(cookies.begin(), cookies.end(), [&](const Cookie& x) { return x.name == c->name; });
				if (same != cookies.end()) *same = *c;
				else cookies.push_back(*c);
			}
		}

		const int st = last.response->status;
		const std::string* location = find_header(last.response->headers, "Location");
		const bool redirect = (st == 301 || st == 302 || st == 303 || st == 307 || st == 308) && location;
		if (!redirect) break;

		Hop h;
		h.url = url.to_string();
		h.status = st;
		h.location = location->substr(0, 2048);
		const auto next = resolve_location(url, *location);
		if (!next) h.note = "Location is not a usable http(s) URL";
		else if (!same_site(*next)) h.note = "redirect leaves the target host (" + next->host + "); not followed";
		else if (!port_allowed(next->port)) h.note = "redirect to port " + std::to_string(next->port) + ", which is not in the allowed list; not followed";
		else if (visited.count(next->to_string())) h.note = "redirect loop";
		else if (hop == limits_.max_redirects) h.note = "too many redirects";
		else h.followed = true;
		obs.redirects.push_back(h);
		if (!h.followed) break;
		url = *next;
	}

	// ---- what the last response said
	obs.url = final_url.to_string();
	obs.tls = final_url.scheme == "https";
	obs.error = last.error;
	obs.error_detail = last.error_detail;
	obs.banner = last.banner;
	obs.tls_info = last.tls;
	obs.cookies = std::move(cookies);
	if (have_response) {
		const HttpResponse& r = *last.response;
		obs.status = r.status;
		obs.reason = r.reason;
		obs.http_version = r.version;
		obs.headers = r.headers;
		if (!limits_.keep_cookie_values) redact_cookie_headers(obs.headers);
		if (const std::string* s = find_header(r.headers, "Server")) obs.server = s->substr(0, 256);
		if (const std::string* c = find_header(r.headers, "Content-Type")) obs.content_type = c->substr(0, 256);
		obs.body = r.body;
		obs.body_length = r.body.size();
		obs.body_truncated = r.body_truncated;
		obs.body_sha256 = sha256_hex(r.body);
		if (looks_like_html(obs.content_type, r.body)) obs.title = extract_title(r.body);

		// ---- the favicon, if the page is a normal successful HTML page on the same site
		// (not after a failed or partial exchange: a struggling server gets no extra requests)
		if (limits_.fetch_favicon && last.error == FetchError::None && r.status >= 200 && r.status < 300 && looks_like_html(obs.content_type, r.body)) {
			const std::string href = find_icon_href(r.body);
			std::optional<Url> icon = resolve_location(final_url, href.empty() ? "/favicon.ico" : href);
			if (icon && same_site(*icon) && port_allowed(icon->port) && valid_path(icon->path)) {
				TransportLimits tl = limits_.transport;
				tl.max_body = 64 * 1024;
				gate_.wait();
				obs.requests++;
				Exchange ex = transport_.get(endpoint_for(*icon), icon->path, tl);
				if (ex.response && ex.response->status == 200 && !ex.response->body.empty() && !ex.response->body_truncated) {
					const std::string* ct = find_header(ex.response->headers, "Content-Type");
					const bool html = ct && lower_copy(*ct).find("html") != std::string::npos; // a "not found" page served with 200
					if (!html) obs.favicon_hash = favicon_hash(ex.response->body);
				}
			}
		}
	}

	// ---- extra paths: only after a clean, complete main exchange (a struggling server gets no extra requests)
	if (have_response && last.error == FetchError::None) {
		std::set<std::string> done;
		for (const std::string& path : limits_.probe_paths) {
			if (!done.insert(path).second) continue;
			TransportLimits tl = limits_.transport;
			tl.max_body = limits_.path_max_body;
			Url u = final_url;
			u.path = path;
			gate_.wait();
			obs.requests++;
			Exchange ex = transport_.get(endpoint_for(u), path, tl);
			PathResult pr;
			pr.path = path;
			pr.error = ex.error;
			if (ex.response) {
				const HttpResponse& r = *ex.response;
				pr.status = r.status;
				pr.headers = r.headers;
				if (!limits_.keep_cookie_values) redact_cookie_headers(pr.headers);
				if (const std::string* ct = find_header(r.headers, "Content-Type")) pr.content_type = ct->substr(0, 256);
				if (const std::string* l = find_header(r.headers, "Location")) pr.redirect = l->substr(0, 2048);
				pr.body = r.body;
				if (looks_like_html(pr.content_type, r.body)) pr.title = extract_title(r.body);
			}
			obs.paths.push_back(std::move(pr));
		}
	}
	obs.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
	return obs;
}

} // namespace proculus
