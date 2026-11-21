#ifndef PROCULUS_TARGET_H
#define PROCULUS_TARGET_H

#include "proculus/netutil/range.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	PC_TARGET_INVALID = 0,
	PC_TARGET_IP, // 10.0.0.5
	PC_TARGET_CIDR, // 10.0.0.0/24
	PC_TARGET_RANGE, // 10.0.0.1-10.0.0.9, 10.0.0.1-9
	PC_TARGET_DOMAIN, // example.com (needs DNS resolution)
} pc_target_kind;

/* Longest valid domain name (without trailing dot) plus NUL. */
#define PC_DOMAIN_MAX 254

typedef struct {
	pc_target_kind kind;
	pc_range range; /* valid for IP, CIDR and RANGE */
	char domain[PC_DOMAIN_MAX]; /* valid for DOMAIN: lowercase, no trailing dot
								 */
} pc_target;

/* Classifies and parses one user-supplied target line. Leading and trailing
 * ASCII whitespace is ignored. Returns 0 on success; -1 on error, in which
 * case out->kind is PC_TARGET_INVALID.
 *
 * Anything made only of digits, '.', '/' and '-' is treated as an IP-style
 * target and must parse as one, so 256.0.0.1 or 10.0.0.9-1 are rejected
 * instead of being mistaken for host names. Everything else must be a valid
 * RFC 1123 host name: labels of 1-63 letters/digits/hyphens (no leading or
 * trailing hyphen), at most 253 characters, and a last label that is not
 * all digits. A single trailing dot is accepted and removed. Non-ASCII
 * (IDN) input must be punycode-encoded by the caller. Wildcards and
 * underscores are rejected. */
int pc_target_parse(const char* s, pc_target* out);

/* String representation of the target type */
const char* pc_target_kind_name(pc_target_kind k);

#ifdef __cplusplus
}
#endif

#endif /* PROCULUS_TARGET_H */
