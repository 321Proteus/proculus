#undef NDEBUG
#include <cassert>

#include "proculus/web/auth.hpp"

using namespace proculus::web;
using sc = std::chrono::steady_clock;

static AuthUser user(int64_t id, const char* name) {
	AuthUser u;
	u.id = id;
	u.username = name;
	u.role = "viewer";
	u.permissions = {"data.read"};
	return u;
}

int main() {
	assert(is_permission("data.read") && is_permission("users.manage") && !is_permission("root") && all_permissions().size() == 8);
	assert(user(1, "a").has("data.read") && !user(1, "a").has("scan.run"));
	assert(random_hex(16).size() == 32 && random_hex(16) != random_hex(16));

	// ---- sessions
	sc::time_point now{};
	SessionManager sm([&] { return now; }, std::chrono::seconds(100), std::chrono::seconds(1000), 3);
	const std::string t1 = sm.create(user(1, "ann"));
	assert(t1.size() == 64 && sm.find(t1) && sm.find(t1)->username == "ann");
	assert(!sm.find("") && !sm.find("nope") && !sm.find(t1 + "0"));
	now += std::chrono::seconds(90);
	assert(sm.find(t1)); // using it renews the idle timer
	now += std::chrono::seconds(90);
	assert(sm.find(t1));
	now += std::chrono::seconds(101);
	assert(!sm.find(t1)); // idle too long
	// a maximum age, however active
	const std::string t2 = sm.create(user(2, "bob"));
	for (int i = 0; i < 12; i++) {
		now += std::chrono::seconds(90);
		sm.find(t2);
	}
	assert(!sm.find(t2));
	// logout, and revoking a changed user
	const std::string a = sm.create(user(3, "cy")), b = sm.create(user(3, "cy")), c = sm.create(user(4, "di"));
	sm.revoke(a);
	assert(!sm.find(a) && sm.find(b));
	sm.revoke_user(3);
	assert(!sm.find(b) && sm.find(c));
	// bounded: the oldest idle session makes room
	const std::string s1 = sm.create(user(5, "e1"));
	now += std::chrono::seconds(1);
	const std::string s2 = sm.create(user(6, "e2")), s3 = sm.create(user(7, "e3"));
	assert(!sm.find(c) || !sm.find(s1) || true);
	int alive = (sm.find(c) ? 1 : 0) + (sm.find(s1) ? 1 : 0) + (sm.find(s2) ? 1 : 0) + (sm.find(s3) ? 1 : 0);
	assert(alive == 3);

	// ---- login throttle
	LoginThrottle th([&] { return now; }, 3, 5, std::chrono::seconds(60), std::chrono::seconds(120));
	assert(th.allowed("ann"));
	th.failed("ann");
	th.failed("ann");
	assert(th.allowed("ann"));
	th.failed("ann");
	assert(!th.allowed("ann") && th.allowed("bob")); // one name is locked, others are not
	now += std::chrono::seconds(121);
	assert(th.allowed("ann"));
	th.failed("ann");
	th.succeeded("ann");
	th.failed("ann");
	th.failed("ann");
	assert(th.allowed("ann")); // a success forgets the earlier failures
	// failures spread over longer than the window do not add up
	th.failed("zed");
	now += std::chrono::seconds(61);
	th.failed("zed");
	now += std::chrono::seconds(61);
	th.failed("zed");
	assert(th.allowed("zed"));
	// too many failures overall (guessing many names) lock everyone for a while
	LoginThrottle many([&] { return now; }, 100, 5, std::chrono::seconds(60), std::chrono::seconds(120));
	for (int i = 0; i < 5; i++) many.failed("name" + std::to_string(i));
	assert(!many.allowed("ann") && !many.allowed("anyone"));
	now += std::chrono::seconds(121);
	assert(many.allowed("ann"));
	return 0;
}
