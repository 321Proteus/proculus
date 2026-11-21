#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "proculus/portset.h"

static void expect_format(pc_portset *s, const char *want) {
	char *got = pc_portset_format(s);
	assert(got && strcmp(got, want) == 0);
	free(got);
}

int main(void) {
	pc_portset s;
	pc_portset_init(&s);

	/* parse, merge, normalise ordering */
	assert(pc_portset_add_list(&s, "443, 80,8000-8100\n8101,81-82,80") == 0);
	expect_format(&s, "80-82,443,8000-8101");
	assert(pc_portset_count(&s) == 3 + 1 + 102);
	assert(pc_portset_contains(&s, 8101));
	assert(!pc_portset_contains(&s, 83));
	assert(pc_portset_range_count(&s) == 3);

	/* all-or-nothing on error */
	const char *bad[] = {"80,abc", "0", "65536", "80-", "-80", "90-80", "080", "80-90-100",
		"22;23", "1-0"};
	for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
		assert(pc_portset_add_list(&s, bad[i]) == -1);
		expect_format(&s, "80-82,443,8000-8101");
	}
	assert(pc_portset_add_list(&s, NULL) == -1);

	/* edges */
	pc_portset e;
	pc_portset_init(&e);
	expect_format(&e, "");
	assert(pc_portset_add_list(&e, "1,65535") == 0);
	assert(pc_portset_contains(&e, 1) && pc_portset_contains(&e, 65535));
	assert(!pc_portset_contains(&e, 2));
	assert(pc_portset_add_list(&e, "2-65534") == 0);
	assert(pc_portset_count(&e) == 65535 && pc_portset_range_count(&e) == 1);
	pc_portset_free(&e);

	/* requested ∩ allowed */
	pc_portset allowed;
	pc_portset_init(&allowed);
	assert(pc_portset_add_list(&allowed, "22,80,443,8000-8080") == 0);
	assert(pc_portset_intersect(&s, &allowed) == 0);
	expect_format(&s, "80,443,8000-8080");

	/* intersect with empty set -> empty */
	pc_portset empty;
	pc_portset_init(&empty);
	assert(pc_portset_intersect(&s, &empty) == 0);
	assert(pc_portset_count(&s) == 0);

	pc_portset_free(&s);
	pc_portset_free(&allowed);
	pc_portset_free(&empty);
	return 0;
}
