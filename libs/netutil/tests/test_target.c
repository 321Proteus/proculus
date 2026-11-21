#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "proculus/target.h"

static void expect(const char* in, pc_target_kind kind) {
	pc_target t;
	int rc = pc_target_parse(in, &t);
	assert(t.kind == kind);
	assert((rc == 0) == (kind != PC_TARGET_INVALID));
}

static void expect_domain(const char* in, const char* want) {
	pc_target t;
	assert(pc_target_parse(in, &t) == 0);
	assert(t.kind == PC_TARGET_DOMAIN && strcmp(t.domain, want) == 0);
}

int main(void) {
	pc_target t;

	// IP-style
	expect("10.0.0.5", PC_TARGET_IP);
	expect("10.0.0.0/24", PC_TARGET_CIDR);
	expect("10.0.0.1-10.0.0.9", PC_TARGET_RANGE);
	expect("10.0.0.1-9", PC_TARGET_RANGE);
	assert(pc_target_parse("10.0.0.0/30", &t) == 0 &&
		t.range.hi - t.range.lo == 3);

	// whitespace is trimmed
	expect("  10.0.0.5\t\n", PC_TARGET_IP);
	expect(" example.com ", PC_TARGET_DOMAIN);

	// malformed IP-style input must not fall through to "domain"
	expect("256.0.0.1", PC_TARGET_INVALID);
	expect("10.0.0", PC_TARGET_INVALID);
	expect("10.0.0.9-1", PC_TARGET_INVALID);
	expect("10.0.0.1/33", PC_TARGET_INVALID);
	expect("1.2.3.4.5", PC_TARGET_INVALID);
	expect("1234", PC_TARGET_INVALID);
	expect("10.0.0.5.", PC_TARGET_INVALID);

	// domains
	expect_domain("example.com", "example.com");
	expect_domain("WWW.Example.COM", "www.example.com");
	expect_domain("example.com.", "example.com");
	expect_domain("localhost", "localhost");
	expect_domain("a-b.c-d.example", "a-b.c-d.example");
	expect_domain("host1.dc2.agh.edu.pl", "host1.dc2.agh.edu.pl");
	expect_domain("10.example.com", "10.example.com");
	expect_domain("xn--bcher-kva.example", "xn--bcher-kva.example");

	// invalid domains
	const char* bad[] = { "", "   ", ".", "..", ".example.com", "example..com",
		"-a.com", "a-.com", "a.-b.com", "exa_mple.com", "*.example.com",
		"exa mple.com", "example.com/path", "http://example.com",
		"example.com:80", "user@example.com",
		("b\xc3\xbc"
		 "cher.example"),
		"example.123", "1.2.3.a-", "a..", "example.com.." };
	for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
		expect(bad[i], PC_TARGET_INVALID);

	// length limits
	char label63[64], label64[65], longname[300];
	memset(label63, 'a', 63);
	label63[63] = '\0';
	memset(label64, 'a', 64);
	label64[64] = '\0';
	char name[200];
	strcpy(name, label63);
	strcat(name, ".com");
	expect(name, PC_TARGET_DOMAIN);
	strcpy(name, label64);
	strcat(name, ".com");
	expect(name, PC_TARGET_INVALID);

	// 253 chars ok, 254 not
	char l61[62];
	memset(l61, 'b', 61);
	l61[61] = '\0';
	snprintf(longname, sizeof longname, "%s.%s.%s.%s", label63, label63,
		label63, l61);
	assert(strlen(longname) == 253);
	expect(longname, PC_TARGET_DOMAIN);
	strcat(longname, "b");
	expect(longname, PC_TARGET_INVALID);

	// NULL, output cleared on failure
	assert(pc_target_parse(NULL, &t) == -1 && t.kind == PC_TARGET_INVALID);
	assert(pc_target_parse("bad..name", &t) == -1);
	assert(t.kind == PC_TARGET_INVALID && t.domain[0] == '\0');
	assert(strcmp(pc_target_kind_name(PC_TARGET_CIDR), "cidr") == 0);
	return 0;
}
