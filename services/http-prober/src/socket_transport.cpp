#include "transport.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>

#include "analyze.hpp"
#include "sigpipe_guard.hpp"
#include "tls_cert.hpp"

#ifdef MSG_NOSIGNAL
#define MSG_NOSIGNAL_FLAG MSG_NOSIGNAL
#else
#define MSG_NOSIGNAL_FLAG 0
#endif

namespace proculus {

namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t) { return std::chrono::duration<double, std::milli>(Clock::now() - t).count(); }

struct Deadline {
	Clock::time_point end;
	int remaining_ms() const {
		const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(end - Clock::now()).count();
		return left <= 0 ? 0 : static_cast<int>(std::min<long long>(left, 1 << 30));
	}
	bool expired() const { return Clock::now() >= end; }
};

// Waits until `fd` is ready for `events`; false on timeout.
bool wait_fd(int fd, short events, const Deadline& d) {
	pollfd p{fd, events, 0};
	for (;;) {
		const int ms = d.remaining_ms();
		if (ms == 0) return false;
		const int rc = poll(&p, 1, ms);
		if (rc > 0) return true;
		if (rc == 0) return false;
		if (errno != EINTR) return false;
	}
}

std::string ssl_error_text() {
	char buf[256];
	const unsigned long e = ERR_get_error();
	if (e == 0) return "unknown TLS error";
	ERR_error_string_n(e, buf, sizeof buf);
	ERR_clear_error();
	return buf;
}

// A connection, plain or TLS, with deadline-bounded I/O.
class Channel {
public:
	~Channel() {
		if (ssl_) SSL_free(ssl_);
		if (ctx_) SSL_CTX_free(ctx_);
		if (fd_ >= 0) ::close(fd_);
	}

	bool connect_to(const std::string& ip, uint16_t port, int timeout_ms, Exchange& ex) {
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
			ex.error = FetchError::ConnectFailed;
			ex.error_detail = "not an IPv4 address";
			return false;
		}
		fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
		if (fd_ < 0) {
			ex.error = FetchError::ConnectFailed;
			ex.error_detail = std::strerror(errno);
			return false;
		}
		fcntl(fd_, F_SETFL, fcntl(fd_, F_GETFL) | O_NONBLOCK);
#ifdef SO_NOSIGPIPE
		int one = 1;
		setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
		Deadline d{Clock::now() + std::chrono::milliseconds(timeout_ms)};
		if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 && errno != EINPROGRESS) {
			set_connect_error(errno, ex);
			return false;
		}
		if (!wait_fd(fd_, POLLOUT, d)) {
			ex.error = FetchError::ConnectTimeout;
			ex.error_detail = "no answer within " + std::to_string(timeout_ms) + " ms";
			return false;
		}
		int err = 0;
		socklen_t len = sizeof err;
		getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len);
		if (err != 0) {
			set_connect_error(err, ex);
			return false;
		}
		return true;
	}

	bool start_tls(const std::string& host, const Deadline& d, Exchange& ex) {
		ctx_ = SSL_CTX_new(TLS_client_method());
		if (!ctx_) {
			ex.error = FetchError::TlsFailed;
			ex.error_detail = "cannot create TLS context";
			return false;
		}
		// Old and badly configured servers are exactly what a scanner meets: accept
		// every protocol version and cipher, and do not verify the certificate.
		SSL_CTX_set_min_proto_version(ctx_, TLS1_VERSION);
		SSL_CTX_set_cipher_list(ctx_, "ALL:@SECLEVEL=0");
		SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
		ssl_ = SSL_new(ctx_);
		SSL_set_fd(ssl_, fd_);
		in_addr unused{};
		if (!host.empty() && inet_pton(AF_INET, host.c_str(), &unused) != 1) SSL_set_tlsext_host_name(ssl_, host.c_str());

		for (;;) {
			const int rc = SSL_connect(ssl_);
			if (rc == 1) return true;
			const int err = SSL_get_error(ssl_, rc);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				if (!wait_fd(fd_, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, d)) {
					ex.error = FetchError::Timeout;
					ex.error_detail = "TLS handshake timed out";
					return false;
				}
				continue;
			}
			ex.error = FetchError::TlsFailed;
			ex.error_detail = err == SSL_ERROR_SYSCALL ? "connection closed during the TLS handshake" : ssl_error_text();
			return false;
		}
	}

	TlsInfo tls_info(const std::string& host) const {
		TlsInfo t;
		t.version = SSL_get_version(ssl_);
		if (const char* c = SSL_get_cipher_name(ssl_)) t.cipher = c;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		X509* cert = SSL_get1_peer_certificate(ssl_);
#else
		X509* cert = SSL_get_peer_certificate(ssl_);
#endif
		if (cert) {
			t.certificate = describe_certificate(cert, host);
			X509_free(cert);
		}
		if (STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl_)) t.chain_length = static_cast<size_t>(sk_X509_num(chain));
		return t;
	}

	// Writes everything or fails (false) at the deadline / on error.
	bool write_all(const std::string& data, const Deadline& d, Exchange& ex) {
		size_t off = 0;
		while (off < data.size()) {
			if (ssl_) {
				const int n = SSL_write(ssl_, data.data() + off, static_cast<int>(data.size() - off));
				if (n > 0) {
					off += static_cast<size_t>(n);
					continue;
				}
				const int err = SSL_get_error(ssl_, n);
				if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
					if (!wait_fd(fd_, err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, d)) return fail(ex, FetchError::Timeout, "timed out sending the request");
					continue;
				}
				return fail(ex, FetchError::Reset, "connection lost while sending the request");
			}
			const ssize_t n = ::send(fd_, data.data() + off, data.size() - off, MSG_NOSIGNAL_FLAG);
			if (n > 0) {
				off += static_cast<size_t>(n);
				continue;
			}
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
				if (!wait_fd(fd_, POLLOUT, d)) return fail(ex, FetchError::Timeout, "timed out sending the request");
				continue;
			}
			return fail(ex, FetchError::Reset, "connection lost while sending the request");
		}
		return true;
	}

	enum class Read { Data, Eof, Timeout, Error };

	// Reads whatever is available (at least one byte) into `out`.
	Read read_some(std::string& out, const Deadline& d, size_t max_bytes) {
		char buf[16384];
		const size_t want = std::min(sizeof buf, max_bytes);
		for (;;) {
			if (ssl_) {
				const int n = SSL_read(ssl_, buf, static_cast<int>(want));
				if (n > 0) {
					out.append(buf, static_cast<size_t>(n));
					return Read::Data;
				}
				const int err = SSL_get_error(ssl_, n);
				if (err == SSL_ERROR_ZERO_RETURN) return Read::Eof;
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
					if (!wait_fd(fd_, err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, d)) return Read::Timeout;
					continue;
				}
				ERR_clear_error();
				// Many servers just close the TCP connection without a TLS close_notify.
				return err == SSL_ERROR_SYSCALL && errno == 0 ? Read::Eof : Read::Error;
			}
			const ssize_t n = ::recv(fd_, buf, want, 0);
			if (n > 0) {
				out.append(buf, static_cast<size_t>(n));
				return Read::Data;
			}
			if (n == 0) return Read::Eof;
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				if (!wait_fd(fd_, POLLIN, d)) return Read::Timeout;
				continue;
			}
			return Read::Error;
		}
	}

private:
	static bool fail(Exchange& ex, FetchError e, const std::string& detail) {
		ex.error = e;
		ex.error_detail = detail;
		return false;
	}

	static void set_connect_error(int err, Exchange& ex) {
		ex.error_detail = std::strerror(err);
		if (err == ECONNREFUSED) ex.error = FetchError::ConnectRefused;
		else if (err == ETIMEDOUT) ex.error = FetchError::ConnectTimeout;
		else ex.error = FetchError::ConnectFailed;
	}

	int fd_ = -1;
	SSL_CTX* ctx_ = nullptr;
	SSL* ssl_ = nullptr;
};

// ------------------------------------------------------------ response parsing

std::string printable_prefix(const std::string& s, size_t max = 64) {
	std::string out;
	for (unsigned char c : s) {
		if (c == '\r' || c == '\n') break;
		out += (c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '.';
		if (out.size() >= max) break;
	}
	return out;
}

std::string trim_ws(const std::string& s) {
	size_t a = 0, b = s.size();
	while (a < b && (s[a] == ' ' || s[a] == '\t')) a++;
	while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
	return s.substr(a, b - a);
}

std::string lower_copy(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

// Position of the end of the header block in `buf` and the length of the separator.
bool find_header_end(const std::string& buf, size_t& pos, size_t& sep) {
	const size_t crlf = buf.find("\r\n\r\n");
	const size_t lf = buf.find("\n\n");
	if (crlf == std::string::npos && lf == std::string::npos) return false;
	if (crlf != std::string::npos && (lf == std::string::npos || crlf < lf)) {
		pos = crlf;
		sep = 4;
	} else {
		pos = lf;
		sep = 2;
	}
	return true;
}

// Parses "HTTP/1.1 200 OK" plus header lines. Throws via `error` and returns false on malformed input.
bool parse_head(const std::string& head, HttpResponse& r, size_t max_headers, std::string& error) {
	std::vector<std::string> lines;
	size_t start = 0;
	while (start <= head.size()) {
		size_t nl = head.find('\n', start);
		std::string line = head.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
		if (!line.empty() && line.back() == '\r') line.pop_back();
		lines.push_back(std::move(line));
		if (nl == std::string::npos) break;
		start = nl + 1;
	}
	const std::string& status = lines[0];
	// "HTTP/1.x SP 3DIGIT [SP reason]"
	if (status.size() < 12 || status.compare(0, 5, "HTTP/") != 0 || status[6] != '.' || status[8] != ' ' ||
		!std::isdigit(static_cast<unsigned char>(status[5])) || !std::isdigit(static_cast<unsigned char>(status[7])) ||
		!std::isdigit(static_cast<unsigned char>(status[9])) || !std::isdigit(static_cast<unsigned char>(status[10])) ||
		!std::isdigit(static_cast<unsigned char>(status[11]))) {
		error = "malformed status line";
		return false;
	}
	r.version = status.substr(0, 8);
	r.status = std::stoi(status.substr(9, 3));
	r.reason = status.size() > 13 ? printable_prefix(status.substr(13), 80) : "";

	for (size_t i = 1; i < lines.size(); i++) {
		const std::string& line = lines[i];
		if (line.empty()) continue;
		if ((line[0] == ' ' || line[0] == '\t') && !r.headers.empty()) { // obsolete line folding
			r.headers.back().value += " " + trim_ws(line);
			continue;
		}
		const size_t colon = line.find(':');
		if (colon == std::string::npos || colon == 0) continue; // junk line: ignore
		std::string name = line.substr(0, colon);
		bool token = true;
		for (unsigned char c : name)
			if (c <= 0x20 || c >= 0x7f) token = false;
		if (!token) continue;
		if (r.headers.size() >= max_headers) {
			error = "too many headers";
			return false;
		}
		std::string value = trim_ws(line.substr(colon + 1));
		for (char& c : value)
			if (static_cast<unsigned char>(c) < 0x20 && c != '\t') c = ' ';
		r.headers.push_back({std::move(name), std::move(value)});
	}
	return true;
}

// Reads one chunk-encoded body from `buf` (more data is fetched through `more`).
// Returns false (error set) on malformed framing; sets `done` when the final chunk was read.
template <class More>
bool decode_chunked(std::string& buf, std::string& body, size_t max_body, bool& truncated, std::string& error, More more) {
	for (;;) {
		size_t eol;
		while ((eol = buf.find("\r\n")) == std::string::npos) {
			if (buf.size() > 64) {
				error = "bad chunk size line";
				return false;
			}
			if (!more()) return true; // connection ended: use what we have
		}
		std::string size_line = buf.substr(0, eol);
		if (const size_t semi = size_line.find(';'); semi != std::string::npos) size_line.erase(semi);
		size_line = trim_ws(size_line);
		if (size_line.empty() || size_line.size() > 8 || size_line.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
			error = "bad chunk size";
			return false;
		}
		const size_t size = std::stoul(size_line, nullptr, 16);
		buf.erase(0, eol + 2);
		if (size == 0) return true; // trailers are ignored
		size_t remaining = size;
		while (remaining > 0) {
			if (buf.empty() && !more()) return true;
			const size_t take = std::min(remaining, buf.size());
			if (body.size() < max_body) {
				body.append(buf, 0, std::min(take, max_body - body.size()));
				if (body.size() >= max_body && take > 0) truncated = true;
			} else {
				truncated = true;
			}
			buf.erase(0, take);
			remaining -= take;
			if (truncated && body.size() >= max_body) return true; // enough: stop reading
		}
		while (buf.size() < 2)
			if (!more()) return true;
		if (buf.compare(0, 2, "\r\n") != 0) {
			error = "missing chunk terminator";
			return false;
		}
		buf.erase(0, 2);
	}
}

} // namespace

Exchange SocketTransport::get(const Endpoint& ep, const std::string& path, const TransportLimits& limits) {
	SigpipeGuard no_sigpipe; // a peer that closes on us is an error, never a dead process
	Exchange ex;
	const auto started = Clock::now();
	auto finish = [&]() {
		ex.total_ms = ms_since(started);
		return ex;
	};

	// The caller validates these too; a transport must not trust that.
	const std::string host = ep.host.empty() ? ep.ip : ep.host;
	if (!valid_path(path) || !valid_host(host) || ep.port == 0) {
		ex.error = FetchError::Protocol;
		ex.error_detail = "invalid request (path or host)";
		return finish();
	}

	Channel ch;
	if (!ch.connect_to(ep.ip, ep.port, limits.connect_timeout_ms, ex)) return finish();
	ex.connect_ms = ms_since(started);

	const Deadline deadline{started + std::chrono::milliseconds(limits.total_timeout_ms)};
	if (ep.tls) {
		if (!ch.start_tls(ep.host, deadline, ex)) return finish();
		ex.tls = ch.tls_info(ep.host);
	}

	const bool default_port = (!ep.tls && ep.port == 80) || (ep.tls && ep.port == 443);
	std::string request = "GET " + path + " HTTP/1.1\r\nHost: " + host + (default_port ? "" : ":" + std::to_string(ep.port)) +
		"\r\nUser-Agent: " + limits.user_agent + "\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
	if (!ch.write_all(request, deadline, ex)) return finish();

	// --- headers (skipping any 1xx interim responses)
	std::string buf;
	HttpResponse resp;
	for (int interim = 0;; interim++) {
		size_t pos = 0, sep = 0;
		while (!find_header_end(buf, pos, sep)) {
			if (buf.size() > limits.max_header_bytes) {
				ex.error = FetchError::Protocol;
				ex.error_detail = "response headers exceed " + std::to_string(limits.max_header_bytes) + " bytes";
				return finish();
			}
			if (buf.size() >= 5 && buf.compare(0, 5, "HTTP/") != 0) {
				ex.error = FetchError::NotHttp;
				ex.banner = printable_prefix(buf);
				return finish();
			}
			const auto r = ch.read_some(buf, deadline, limits.max_header_bytes + 1 - std::min(buf.size(), limits.max_header_bytes));
			if (r == Channel::Read::Data) continue;
			if (buf.empty()) {
				ex.error = r == Channel::Read::Timeout ? FetchError::Timeout : FetchError::Reset;
				ex.error_detail = r == Channel::Read::Timeout ? "no response before the timeout" : "connection closed before any response";
			} else if (buf.compare(0, std::min<size_t>(5, buf.size()), "HTTP/", 0, std::min<size_t>(5, buf.size())) != 0) {
				ex.error = FetchError::NotHttp;
				ex.banner = printable_prefix(buf);
			} else {
				ex.error = r == Channel::Read::Timeout ? FetchError::Timeout : FetchError::Reset;
				ex.error_detail = "response ended inside the headers";
			}
			return finish();
		}
		std::string error;
		resp = HttpResponse{};
		if (!parse_head(buf.substr(0, pos), resp, limits.max_headers, error)) {
			ex.error = buf.compare(0, 5, "HTTP/") == 0 ? FetchError::Protocol : FetchError::NotHttp;
			ex.error_detail = error;
			if (ex.error == FetchError::NotHttp) ex.banner = printable_prefix(buf);
			return finish();
		}
		buf.erase(0, pos + sep);
		if (resp.status >= 100 && resp.status < 200 && resp.status != 101 && interim < 3) continue;
		break;
	}

	// --- body
	const bool no_body = resp.status == 204 || resp.status == 304 || (resp.status >= 100 && resp.status < 200);
	FetchError body_error = FetchError::None;
	std::string body_error_detail;

	// Reads more into `buf`; false when the peer closed, the deadline passed or reading failed.
	auto more = [&]() -> bool {
		const auto r = ch.read_some(buf, deadline, limits.max_body + 65536);
		if (r == Channel::Read::Data) return true;
		if (r == Channel::Read::Timeout) {
			body_error = FetchError::Timeout;
			body_error_detail = "timed out while the body was arriving";
		}
		return false;
	};

	if (!no_body) {
		const std::string* te = find_header(resp.headers, "Transfer-Encoding");
		const std::string* cl = find_header(resp.headers, "Content-Length");
		if (te && lower_copy(*te).find("chunked") != std::string::npos) {
			std::string error;
			if (!decode_chunked(buf, resp.body, limits.max_body, resp.body_truncated, error, more)) {
				body_error = FetchError::Protocol;
				body_error_detail = error;
			}
		} else if (cl && !cl->empty() && cl->size() <= 15 && cl->find_first_not_of("0123456789") == std::string::npos) {
			const size_t length = std::stoul(*cl);
			const size_t keep = std::min(length, limits.max_body);
			while (buf.size() < keep && more()) {}
			resp.body = buf.substr(0, std::min(buf.size(), keep));
			resp.body_truncated = length > limits.max_body; // we chose not to read the rest
			if (resp.body.size() < keep && body_error == FetchError::None) {
				body_error = FetchError::Reset;
				body_error_detail = "connection closed before the full body arrived";
			}
		} else {
			// no length given: the body runs until the server closes the connection
			while (buf.size() <= limits.max_body && more()) {}
			resp.body = buf.substr(0, std::min(buf.size(), limits.max_body));
			resp.body_truncated = buf.size() > limits.max_body;
		}
	}

	if (ex.tls && ex.tls->version.empty()) ex.tls->version = "unknown";
	ex.response = std::move(resp);
	ex.error = body_error;
	ex.error_detail = body_error_detail;
	return finish();
}

} // namespace proculus
