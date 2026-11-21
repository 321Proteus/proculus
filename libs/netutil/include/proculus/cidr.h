#ifndef PROCULUS_CIDR_H
#define PROCULUS_CIDR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IPv4 CIDR block. `base` is the network address in host byte order
 * (host bits are always zeroed by pc_cidr_parse). */
typedef struct {
	uint32_t base;
	uint8_t prefix; /* 0..32 */
} pc_cidr;

/* Size of the buffer needed by pc_ip_format ("255.255.255.255" + NUL). */
#define PC_IP_STR_MAX 16

/* Size of the buffer needed by pc_cidr_format ("255.255.255.255/32" + NUL). */
#define PC_CIDR_STR_MAX 19

/* Parses a dotted-quad IPv4 address. Strict: exactly 4 decimal octets
 * 0..255, no leading zeros, no whitespace. Returns 0 on success, -1 on error. */
int pc_ip_parse(const char *s, uint32_t *out);

/* Formats `ip` as dotted quad into `buf` (at least PC_IP_STR_MAX bytes). */
void pc_ip_format(uint32_t ip, char *buf);

/* Parses "a.b.c.d/len" or a bare "a.b.c.d" (treated as /32).
 * Returns 0 on success, -1 on error. */
int pc_cidr_parse(const char *s, pc_cidr *out);

/* Number of addresses in the block (1 .. 2^32). */
uint64_t pc_cidr_count(const pc_cidr *c);

/* i-th address of the block, 0 <= i < pc_cidr_count(c). */
uint32_t pc_cidr_nth(const pc_cidr *c, uint64_t i);

/* Formats as "a.b.c.d/len" into `buf` (at least PC_CIDR_STR_MAX bytes). */
void pc_cidr_format(const pc_cidr *c, char *buf);

/* 1 if `ip` lies inside the block, else 0. */
int pc_cidr_contains(const pc_cidr *c, uint32_t ip);

#ifdef __cplusplus
}
#endif

#endif /* PROCULUS_CIDR_H */
