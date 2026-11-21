#ifndef PROCULUS_PORTSET_H
#define PROCULUS_PORTSET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inclusive TCP/UDP port range, 1..65535 (port 0 is never valid). */
typedef struct {
	uint16_t lo;
	uint16_t hi;
} pc_port_range;

/* Set of ports stored as sorted, disjoint, non-adjacent ranges.
 * Query functions normalise lazily, hence the non-const pointers. */
typedef struct {
	pc_port_range* ranges;
	size_t len;
	size_t cap;
	int dirty;
} pc_portset;

void pc_portset_init(pc_portset* s);
void pc_portset_free(pc_portset* s);

/* 0 on success, -1 on invalid range (port 0, lo > hi) or allocation failure. */
int pc_portset_add_range(pc_portset* s, uint16_t lo, uint16_t hi);

/* Parses a list like "80,443,8000-8100" (commas/whitespace separate items)
 * and adds it. All-or-nothing: on error the set is left unchanged and -1 is
 * returned. Ports must be decimal 1..65535 without leading zeros. */
int pc_portset_add_list(pc_portset* s, const char* list);

/* Keeps only ports that are also in `other` (e.g. requested ∩ allowed).
 * 0 / -1 (alloc). */
int pc_portset_intersect(pc_portset* s, pc_portset* other);

int pc_portset_contains(pc_portset* s, uint16_t port);
uint32_t pc_portset_count(pc_portset* s);

size_t pc_portset_range_count(pc_portset* s);
pc_port_range pc_portset_range_at(pc_portset* s, size_t i);

/* Returns a malloc'd string such as "80,443,8000-8100" (empty string for an
 * empty set), parseable by pc_portset_add_list. Caller frees. NULL on OOM. */
char* pc_portset_format(pc_portset* s);

#ifdef __cplusplus
}
#endif

#endif /* PROCULUS_PORTSET_H */
