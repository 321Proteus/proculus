#ifndef PROCULUS_RANGE_H
#define PROCULUS_RANGE_H

#include <stddef.h>
#include <stdint.h>

#include "proculus/cidr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Inclusive IPv4 range, host byte order. Invariant: lo <= hi. */
typedef struct {
	uint32_t lo;
	uint32_t hi;
} pc_range;

/* Range covered by a CIDR block. */
pc_range pc_cidr_to_range(const pc_cidr* c);

/* Parses any single-target IPv4 notation:
 *   "10.0.0.5"             single address
 *   "10.0.0.0/24"          CIDR block
 *   "10.0.0.1-10.0.0.9"    explicit range
 *   "10.0.0.1-9"           nmap-style: last octet replaced (1..9)
 * Returns 0 on success, -1 on error (including lo > hi). */
int pc_range_parse(const char* s, pc_range* out);

/* Number of addresses in the range (1 .. 2^32). */
uint64_t pc_range_count(const pc_range* r);

/* Any inclusive IPv4 range decomposes into at most 62 CIDR blocks. */
#define PC_RANGE_MAX_CIDRS 64

/* Decomposes `r` into the minimal ordered list of CIDR blocks that exactly
 * covers it. Writes up to `cap` blocks (use PC_RANGE_MAX_CIDRS) and returns
 * the number written, or -1 if `cap` is too small. */
int pc_range_to_cidrs(const pc_range* r, pc_cidr* out, size_t cap);

/* True for addresses that are never a legitimate scan target: 0.0.0.0/8,
 * loopback 127/8, link-local 169.254/16, multicast 224/4 and the reserved
 * class-E block 240/4 (including broadcast). RFC 1918 private space is NOT
 * reserved: internal networks are the main use case. */
int pc_ip_is_reserved(uint32_t ip);

#ifdef __cplusplus
}
#endif

#endif /* PROCULUS_RANGE_H */
