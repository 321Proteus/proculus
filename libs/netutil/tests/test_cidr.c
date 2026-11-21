#undef NDEBUG
#include <assert.h>
#include <string.h>

#include "proculus/netutil/cidr.h"

static void check_bad(const char* s) {
	pc_cidr c;
	assert(pc_cidr_parse(s, &c) == -1);
}

int main(void) {
	pc_cidr c;
	char buf[PC_IP_STR_MAX];

	// normal block
	assert(pc_cidr_parse("10.0.0.0/24", &c) == 0);
	assert(c.prefix == 24 && pc_cidr_count(&c) == 256);
	pc_ip_format(pc_cidr_nth(&c, 255), buf);
	assert(strcmp(buf, "10.0.0.255") == 0);

	// host bits get normalised
	assert(pc_cidr_parse("192.168.1.77/16", &c) == 0);
	pc_ip_format(c.base, buf);
	assert(strcmp(buf, "192.168.0.0") == 0);

	// bare IP == /32
	assert(pc_cidr_parse("8.8.4.4", &c) == 0);
	assert(c.prefix == 32 && pc_cidr_count(&c) == 1);

	// edges
	assert(pc_cidr_parse("0.0.0.0/0", &c) == 0);
	assert(pc_cidr_count(&c) == 4294967296ULL);
	assert(pc_cidr_contains(&c, 0xffffffffu));
	assert(pc_cidr_parse("255.255.255.255/32", &c) == 0);
	assert(pc_cidr_nth(&c, 0) == 0xffffffffu);

	// contains
	assert(pc_cidr_parse("10.1.0.0/16", &c) == 0);
	uint32_t ip;
	assert(pc_ip_parse("10.1.200.3", &ip) == 0 && pc_cidr_contains(&c, ip));
	assert(pc_ip_parse("10.2.0.1", &ip) == 0 && !pc_cidr_contains(&c, ip));

	// invalid input
	check_bad("");
	check_bad("1.2.3");
	check_bad("1.2.3.4.5");
	check_bad("256.0.0.1");
	check_bad("1.2.3.4/33");
	check_bad("1.2.3.4/");
	check_bad("1.2.3.4/-1");
	check_bad("01.2.3.4");
	check_bad(" 1.2.3.4");
	check_bad("1.2.3.4 ");
	check_bad("example.com");
	assert(pc_cidr_parse(NULL, &c) == -1);

	return 0;
}
