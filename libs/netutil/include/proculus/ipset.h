#ifndef PROCULUS_IPSET_H
#define PROCULUS_IPSET_H

#include <stddef.h>
#include <stdint.h>

#include "proculus/range.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A set of IPv4 addresses stored as sorted, disjoint, non-adjacent ranges.
 * Memory use scales with the number of ranges, not addresses, so a /8 costs
 * the same as a single host. Query functions normalise lazily, hence they
 * take a non-const pointer. Zero-initialise or call pc_ipset_init.
 */
typedef struct {
	pc_range* ranges;
	size_t len;
	size_t cap;
	int dirty; // unsorted or overlapping
} pc_ipset;

void pc_ipset_init(pc_ipset* s);
void pc_ipset_free(pc_ipset* s);

/* Adders return 0 on success, -1 on allocation failure. */
int pc_ipset_add_range(pc_ipset* s, pc_range r);
int pc_ipset_add_cidr(pc_ipset* s, const pc_cidr* c);

/* Parses `spec` with pc_range_parse and adds it. Returns -1 on bad input. */
int pc_ipset_add_spec(pc_ipset* s, const char* spec);

/* Removes every address of `r` from the set (exclusions). 0 / -1 (alloc). */
int pc_ipset_subtract_range(pc_ipset* s, pc_range r);

/* Removes every address in `other` from `s`. 0 / -1 (alloc). */
int pc_ipset_subtract(pc_ipset* s, pc_ipset* other);

int pc_ipset_contains(pc_ipset* s, uint32_t ip);
uint64_t pc_ipset_count(pc_ipset* s);

/* Number of disjoint ranges after normalisation, and the i-th one. */
size_t pc_ipset_range_count(pc_ipset* s);
pc_range pc_ipset_range_at(pc_ipset* s, size_t i);

/* Appends to `out` the addresses with index [start, start+count) in
 * ascending order (clamped to the set size). Used to cut a target set into
 * scan chunks without enumerating addresses. 0 / -1 (alloc).
 */
int pc_ipset_slice(pc_ipset* s, uint64_t start, uint64_t count, pc_ipset* out);

#ifdef __cplusplus
}
#endif

#endif /* PROCULUS_IPSET_H */
