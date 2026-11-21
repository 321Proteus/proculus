#ifndef PROCULUS_RANGE_H
#define PROCULUS_RANGE_H

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
pc_range pc_cidr_to_range(const pc_cidr *c);

/* Parses any single-target IPv4 notation:
 *   "10.0.0.5"             single address
 *   "10.0.0.0/24"          CIDR block
 *   "10.0.0.1-10.0.0.9"    explicit range
 *   "10.0.0.1-9"           nmap-style: last octet replaced (1..9)
 * Returns 0 on success, -1 on error (including lo > hi). */
int pc_range_parse(const char *s, pc_range *out);

/* Number of addresses in the range (1 .. 2^32). */
uint64_t pc_range_count(const pc_range *r);

#ifdef __cplusplus
}
#endif

#endif /* PROCULUS_RANGE_H */
