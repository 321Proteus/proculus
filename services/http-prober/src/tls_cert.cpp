#include "tls_cert.hpp"

#include <arpa/inet.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <ctime>

#include "analyze.hpp"

namespace proculus {

namespace {

std::string clean(const std::string& s, size_t max = 512) {
	std::string out;
	for (unsigned char c : s) {
		if (c < 0x20 || c == 0x7f) continue;
		out += static_cast<char>(c);
		if (out.size() >= max) break;
	}
	return out;
}

std::string name_text(const X509_NAME* name) {
	BIO* bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(bio, const_cast<X509_NAME*>(name), 0, XN_FLAG_RFC2253);
	char* data = nullptr;
	const long len = BIO_get_mem_data(bio, &data);
	std::string out = clean(std::string(data, static_cast<size_t>(len)));
	BIO_free(bio);
	return out;
}

std::string time_text(const ASN1_TIME* t) {
	struct tm tmv {};
	if (!t || ASN1_TIME_to_tm(t, &tmv) != 1) return "";
	char buf[32];
	std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tmv);
	return buf;
}

} // namespace

CertInfo describe_certificate(X509* x, const std::string& host) {
	CertInfo c;
	c.subject = name_text(X509_get_subject_name(x));
	c.issuer = name_text(X509_get_issuer_name(x));

	if (const ASN1_INTEGER* serial = X509_get0_serialNumber(x)) {
		if (BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr)) {
			if (char* hex = BN_bn2hex(bn)) {
				c.serial = hex;
				OPENSSL_free(hex);
			}
			BN_free(bn);
		}
	}

	c.not_before = time_text(X509_get0_notBefore(x));
	c.not_after = time_text(X509_get0_notAfter(x));
	c.expired = X509_cmp_current_time(X509_get0_notAfter(x)) < 0;
	c.not_yet_valid = X509_cmp_current_time(X509_get0_notBefore(x)) > 0;

	if (auto* names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr))) {
		for (int i = 0; i < sk_GENERAL_NAME_num(names) && c.san.size() < 100; i++) {
			const GENERAL_NAME* g = sk_GENERAL_NAME_value(names, i);
			if (g->type == GEN_DNS) {
				const std::string dns = clean(std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(g->d.dNSName)),
					static_cast<size_t>(ASN1_STRING_length(g->d.dNSName))), 253);
				if (!dns.empty()) c.san.push_back(dns);
			} else if (g->type == GEN_IPADD) {
				const unsigned char* d = ASN1_STRING_get0_data(g->d.iPAddress);
				const int len = ASN1_STRING_length(g->d.iPAddress);
				char buf[INET6_ADDRSTRLEN];
				if (len == 4 && inet_ntop(AF_INET, d, buf, sizeof buf)) c.san.push_back(buf);
				else if (len == 16 && inet_ntop(AF_INET6, d, buf, sizeof buf)) c.san.push_back(buf);
			}
		}
		GENERAL_NAMES_free(names);
	}

	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n = 0;
	if (X509_digest(x, EVP_sha256(), md, &n) == 1) {
		static const char* hex = "0123456789abcdef";
		for (unsigned int i = 0; i < n; i++) {
			c.sha256 += hex[md[i] >> 4];
			c.sha256 += hex[md[i] & 15];
		}
	}

	if (EVP_PKEY* key = X509_get0_pubkey(x)) {
		switch (EVP_PKEY_base_id(key)) {
		case EVP_PKEY_RSA: c.key_type = "RSA"; break;
		case EVP_PKEY_EC: c.key_type = "EC"; break;
		case EVP_PKEY_DSA: c.key_type = "DSA"; break;
		case EVP_PKEY_ED25519: c.key_type = "Ed25519"; break;
		case EVP_PKEY_ED448: c.key_type = "Ed448"; break;
		default: {
			const char* sn = OBJ_nid2sn(EVP_PKEY_base_id(key));
			c.key_type = sn ? clean(sn, 32) : "unknown";
		}
		}
		c.key_bits = EVP_PKEY_bits(key);
	}
	if (const char* ln = OBJ_nid2ln(X509_get_signature_nid(x))) c.signature_algorithm = clean(ln, 64);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	c.self_signed = X509_self_signed(x, 0) == 1;
#else
	c.self_signed = X509_check_issued(x, x) == X509_V_OK;
#endif

	if (!host.empty()) {
		in_addr addr{};
		const bool is_ip = inet_pton(AF_INET, host.c_str(), &addr) == 1;
		c.hostname_match = is_ip ? X509_check_ip_asc(x, host.c_str(), 0) == 1 : X509_check_host(x, host.c_str(), host.size(), 0, nullptr) == 1;
	}
	return c;
}

} // namespace proculus
