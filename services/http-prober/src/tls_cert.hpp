#ifndef PROCULUS_TLS_CERT_HPP
#define PROCULUS_TLS_CERT_HPP

#include <openssl/x509.h>

#include <string>

#include "http_types.hpp"

namespace proculus {

// Extracts what is worth knowing from a certificate. `host` (Host header /
// SNI name, may be empty) is used to check whether the certificate covers it.
// Text taken from the certificate is untrusted: control characters are removed.
CertInfo describe_certificate(X509* cert, const std::string& host);

} // namespace proculus

#endif // PROCULUS_TLS_CERT_HPP
