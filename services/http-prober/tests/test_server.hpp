#ifndef PROCULUS_TEST_SERVER_HPP
#define PROCULUS_TEST_SERVER_HPP

// A tiny scripted TCP/TLS server for transport tests. It listens on 127.0.0.1,
// reads a request, and answers with whatever bytes (and timing) the test says.
// Deliberately able to misbehave: slow, truncated, garbage, silent.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "sigpipe_guard.hpp"

namespace testsrv {

struct Script {
	std::vector<std::string> parts;  // written one after the other
	int initial_delay_ms = 0;        // before the first part
	int part_delay_ms = 0;           // between parts
	int hold_open_ms = 0;            // keep the connection open (silent) after the last part
	bool read_request = true;
};

struct Cert {
	EVP_PKEY* key = nullptr;
	X509* x509 = nullptr;
	~Cert() {
		EVP_PKEY_free(key);
		X509_free(x509);
	}
};

// Self-signed EC P-256 certificate.
inline void make_cert(Cert& c, const std::string& cn, const std::string& san, int valid_days_from_now = 30, int valid_for_days = 365) {
	c.key = EVP_EC_gen("P-256");
	c.x509 = X509_new();
	X509_set_version(c.x509, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(c.x509), 0xC0FFEE);
	X509_gmtime_adj(X509_getm_notBefore(c.x509), static_cast<long>(-valid_days_from_now) * 86400L);
	X509_gmtime_adj(X509_getm_notAfter(c.x509), static_cast<long>(valid_for_days - valid_days_from_now) * 86400L);
	X509_set_pubkey(c.x509, c.key);
	X509_NAME* name = X509_get_subject_name(c.x509);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Proculus Test"), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
	X509_set_issuer_name(c.x509, name);
	if (!san.empty()) {
		X509V3_CTX ctx;
		X509V3_set_ctx_nodb(&ctx);
		X509V3_set_ctx(&ctx, c.x509, c.x509, nullptr, nullptr, 0);
		X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san.c_str());
		X509_add_ext(c.x509, ext, -1);
		X509_EXTENSION_free(ext);
	}
	X509_sign(c.x509, c.key, EVP_sha256());
}

class Server {
public:
	using Handler = std::function<Script(const std::string& request)>;

	// `drop`: close every connection right after accepting it (after the TLS
	// handshake, if any) without reading anything: the client's write then fails.
	// `eager`: answer as soon as any bytes arrive instead of waiting for a complete
	// request, like a real server that rejects garbage straight away.
	explicit Server(Handler handler, const Cert* cert = nullptr, bool eager = false, bool drop = false)
		: handler_(std::move(handler)), eager_(eager), drop_(drop) {
		listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
		int one = 1;
		setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		a.sin_port = 0;
		bind(listen_fd_, reinterpret_cast<sockaddr*>(&a), sizeof a);
		listen(listen_fd_, 16);
		socklen_t len = sizeof a;
		getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&a), &len);
		port_ = ntohs(a.sin_port);

		if (cert) {
			ctx_ = SSL_CTX_new(TLS_server_method());
			SSL_CTX_use_certificate(ctx_, cert->x509);
			SSL_CTX_use_PrivateKey(ctx_, cert->key);
			SSL_CTX_set_tlsext_servername_callback(ctx_, &Server::sni_cb);
			SSL_CTX_set_tlsext_servername_arg(ctx_, this);
		}
		thread_ = std::thread([this] { loop(); });
	}

	~Server() {
		stop_ = true;
		thread_.join();
		::close(listen_fd_);
		if (ctx_) SSL_CTX_free(ctx_);
	}

	uint16_t port() const { return port_; }
	std::string last_request() const { std::lock_guard<std::mutex> l(m_); return last_request_; }
	std::string last_sni() const { std::lock_guard<std::mutex> l(m_); return last_sni_; }
	int connections() const { return connections_; }

private:
	static int sni_cb(SSL* ssl, int*, void* arg) {
		auto* self = static_cast<Server*>(arg);
		const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
		std::lock_guard<std::mutex> l(self->m_);
		self->last_sni_ = name ? name : "";
		return SSL_TLSEXT_ERR_OK;
	}

	void loop() {
		proculus::SigpipeGuard no_sigpipe; // writing to a client that has gone must not kill the test
		while (!stop_) {
			pollfd p{listen_fd_, POLLIN, 0};
			if (poll(&p, 1, 50) <= 0) continue;
			const int fd = accept(listen_fd_, nullptr, nullptr);
			if (fd < 0) continue;
			connections_++;
#ifdef SO_NOSIGPIPE
			int nosigpipe = 1;
			setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof nosigpipe);
#endif
			timeval tv{2, 0};
			setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
			setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
			serve(fd);
			::close(fd);
		}
	}

	static void sleep_ms(int ms) { if (ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

	void serve(int fd) {
		SSL* ssl = nullptr;
		if (ctx_) {
			ssl = SSL_new(ctx_);
			SSL_set_fd(ssl, fd);
			if (SSL_accept(ssl) != 1) {
				ERR_clear_error();
				SSL_free(ssl);
				return;
			}
		}
		auto rd = [&](char* b, size_t n) -> ssize_t { return ssl ? SSL_read(ssl, b, static_cast<int>(n)) : ::recv(fd, b, n, 0); };
		auto wr = [&](const std::string& s) {
			size_t off = 0;
			while (off < s.size() && !stop_) {
				const ssize_t n = ssl ? SSL_write(ssl, s.data() + off, static_cast<int>(s.size() - off)) : ::send(fd, s.data() + off, s.size() - off, 0);
				if (n <= 0) return;
				off += static_cast<size_t>(n);
			}
		};

		if (drop_) {
			if (ssl) {
				SSL_shutdown(ssl);
				SSL_free(ssl);
			}
			return;
		}
		std::string request;
		char buf[4096];
		while (request.find("\r\n\r\n") == std::string::npos && request.size() < 65536) {
			const ssize_t n = rd(buf, sizeof buf);
			if (n <= 0) break;
			request.append(buf, static_cast<size_t>(n));
			if (eager_) break;
		}
		{
			std::lock_guard<std::mutex> l(m_);
			last_request_ = request;
		}
		Script s = handler_(request);
		sleep_ms(s.initial_delay_ms);
		for (size_t i = 0; i < s.parts.size(); i++) {
			if (i) sleep_ms(s.part_delay_ms);
			wr(s.parts[i]);
		}
		for (int waited = 0; waited < s.hold_open_ms && !stop_; waited += 20) sleep_ms(20);
		if (ssl) {
			SSL_shutdown(ssl);
			SSL_free(ssl);
		}
	}

	Handler handler_;
	bool eager_ = false;
	bool drop_ = false;
	int listen_fd_ = -1;
	uint16_t port_ = 0;
	SSL_CTX* ctx_ = nullptr;
	std::thread thread_;
	std::atomic<bool> stop_{false};
	std::atomic<int> connections_{0};
	mutable std::mutex m_;
	std::string last_request_, last_sni_;
};

inline Script reply(const std::string& raw) {
	Script s;
	s.parts = {raw};
	return s;
}

inline std::string http_ok(const std::string& body, const std::string& extra_headers = "") {
	return "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\n" + extra_headers + "\r\n" + body;
}

} // namespace testsrv

#endif // PROCULUS_TEST_SERVER_HPP
