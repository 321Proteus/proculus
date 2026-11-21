#undef NDEBUG
#include <cassert>
#include <cstdlib>
#include <string>

#include "proculus/db/crypto.hpp"

using namespace proculus::db;

template <class F> static bool throws_crypto(F f) {
	try {
		f();
	} catch (const CryptoError&) { return true; }
	return false;
}

static KeyRing ring_of(uint8_t id) {
	KeyRing r;
	r.add(id, Key::generate());
	return r;
}

static void test_roundtrip() {
	FieldCipher c(ring_of(1));
	for (std::string pt : { std::string(""), std::string("a"),
			 std::string("Set-Cookie: sid=abc; HttpOnly"),
			 std::string(100000, 'x'),
			 std::string("zażółć gęślą jaźń \0 binary", 27) }) {
		auto blob = c.seal(pt, "http_endpoints.cookies");
		assert(c.open(blob, "http_endpoints.cookies") == pt);
		assert(blob.size() == 2 + 24 + pt.size() + 16);
	}
	// fresh random nonce each time
	assert(c.seal("same", "ctx") != c.seal("same", "ctx"));
}

static void test_tamper_and_context() {
	FieldCipher c(ring_of(1));
	auto blob = c.seal("secret", "overrides.value");

	assert(
		throws_crypto([&] { c.open(blob, "assets.note"); })); // wrong context
	for (size_t i = 0; i < blob.size(); i++) { // any flipped byte
		auto bad = blob;
		bad[i] ^= 0x01;
		assert(throws_crypto([&] { c.open(bad, "overrides.value"); }));
	}
	assert(throws_crypto([&] { c.open({}, "x"); })); // too short
	assert(throws_crypto([&] { c.open(std::vector<uint8_t>(10, 0), "x"); }));
	auto trunc = blob;
	trunc.pop_back();
	assert(throws_crypto([&] { c.open(trunc, "overrides.value"); }));

	FieldCipher other(ring_of(1)); // same id, different key
	assert(throws_crypto([&] { other.open(blob, "overrides.value"); }));
}

static void test_rotation() {
	Key k1 = Key::generate(), k2 = Key::generate();
	KeyRing old_ring;
	old_ring.add(1, k1);
	auto old_blob = FieldCipher(old_ring).seal("old data", "t.c");

	KeyRing rotated = old_ring;
	rotated.add(2, k2);
	FieldCipher c(rotated);
	assert(c.open(old_blob, "t.c") == "old data"); // still readable
	auto fresh = c.seal("new data", "t.c");
	assert(fresh[1] == 2); // new data uses the newest key
	assert(c.open(fresh, "t.c") == "new data");

	// a ring without the old key cannot read old data
	KeyRing only_new;
	only_new.add(2, k2);
	assert(throws_crypto([&] { FieldCipher(only_new).open(old_blob, "t.c"); }));
}

static void test_keys_and_ring_parsing() {
	Key k = Key::generate();
	assert(k.to_hex().size() == 64);
	assert(Key::from_hex(k.to_hex()).to_hex() == k.to_hex());
	assert(Key::from_hex("  " + k.to_hex() + "\n").to_hex() == k.to_hex());
	assert(throws_crypto([] { Key::from_hex(""); }));
	assert(throws_crypto([] { Key::from_hex(std::string(63, 'a')); }));
	assert(throws_crypto([] { Key::from_hex(std::string(64, 'g')); }));
	assert(throws_crypto([] { Key::from_hex(std::string(66, 'a')); }));

	std::string a = Key::generate().to_hex(), b = Key::generate().to_hex();
	KeyRing r = KeyRing::from_text(
		"# comment\n1:" + a + "\n\n  2 : " + b + "  # newest\n");
	assert(r.current_id() == 2 && r.find(1) && r.find(2) && !r.find(3));
	assert(KeyRing::from_text(a).current_id() == 1); // bare hex = id 1

	assert(throws_crypto([] { KeyRing::from_text(""); }));
	assert(throws_crypto([&] { KeyRing::from_text("0:" + a); }));
	assert(throws_crypto([&] { KeyRing::from_text("256:" + a); }));
	assert(throws_crypto([&] { KeyRing::from_text("x:" + a); }));
	assert(throws_crypto(
		[&] { KeyRing::from_text("1:" + a + "\n1:" + b); })); // duplicate id
	assert(throws_crypto([] { FieldCipher(KeyRing{}); }));
	assert(throws_crypto([] { KeyRing{}.current_id(); }));
}

static void test_env() {
	unsetenv("PROCULUS_KEY_FILE");
	unsetenv("PROCULUS_KEY");
	assert(throws_crypto([] { KeyRing::from_env(); }));

	std::string a = Key::generate().to_hex();
	setenv("PROCULUS_KEY", ("3:" + a).c_str(), 1);
	assert(KeyRing::from_env().current_id() == 3);
	setenv("PROCULUS_KEY", "garbage", 1);
	assert(throws_crypto([] { KeyRing::from_env(); }));

	setenv("PROCULUS_KEY_FILE", "/nonexistent/keys",
		1); // file wins over the variable
	assert(throws_crypto([] { KeyRing::from_env(); }));
	unsetenv("PROCULUS_KEY_FILE");
	unsetenv("PROCULUS_KEY");
}

static void test_passwords() {
	std::string h = hash_password("correct horse");
	assert(h.rfind("$argon2id$", 0) == 0);
	assert(verify_password(h, "correct horse"));
	assert(!verify_password(h, "correct horsf"));
	assert(!verify_password(h, ""));
	assert(!verify_password("not a hash", "x"));
	assert(hash_password("correct horse") != h); // salted
}

int main() {
	test_roundtrip();
	test_tamper_and_context();
	test_rotation();
	test_keys_and_ring_parsing();
	test_env();
	test_passwords();
	return 0;
}
