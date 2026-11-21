#ifndef PROCULUS_DB_CRYPTO_HPP
#define PROCULUS_DB_CRYPTO_HPP

// Field-level encryption for values stored in *_enc columns, plus password
// hashing. Built on libsodium (XChaCha20-Poly1305, Argon2id).
//
// Sealed blob layout:  [version=1][key id][24-byte nonce][ciphertext || 16-byte
// tag] The `context` string (e.g. "http_endpoints.cookies") is authenticated
// but not stored, so a blob copied into another column fails to open.

#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace proculus::db {

struct CryptoError : std::runtime_error {
	using std::runtime_error::runtime_error;
};

// A 256-bit secret key; wiped from memory on destruction.
class Key {
public:
	static constexpr size_t kSize = 32;

	Key() = default;
	~Key();
	Key(const Key&) = default;
	Key& operator=(const Key&) = default;

	// 64 hex characters. Throws CryptoError on anything else.
	static Key from_hex(std::string_view hex);
	static Key generate();
	std::string to_hex() const;

	const uint8_t* data() const { return bytes_.data(); }

private:
	std::array<uint8_t, kSize> bytes_{};
};

// Keys by id, so old data stays readable after a rotation: new data is sealed
// with the current (highest) id, old blobs open with whichever id they name.
class KeyRing {
public:
	void add(uint8_t id, Key key);
	bool empty() const { return keys_.empty(); }
	uint8_t current_id() const; // highest id; throws if empty
	const Key* find(uint8_t id) const;

	// Reads keys from the environment (first match wins):
	//   PROCULUS_KEY_FILE  path to a file with one "id:hex" per line ('#'
	//   comments) PROCULUS_KEY       a single "id:hex" or bare 64-char hex (id
	//   1)
	// Throws CryptoError when nothing is configured or the format is wrong.
	static KeyRing from_env();

	// Same format as the key file; exposed for tests and tooling.
	static KeyRing from_text(std::string_view text);

private:
	std::map<uint8_t, Key> keys_;
};

class FieldCipher {
public:
	explicit FieldCipher(KeyRing keys);

	std::vector<uint8_t> seal(
		std::string_view plaintext, std::string_view context) const;
	// Throws CryptoError if the blob is malformed, was sealed under another
	// context or key, or has been modified.
	std::string open(
		const std::vector<uint8_t>& blob, std::string_view context) const;

private:
	KeyRing keys_;
};

// Argon2id hash in libsodium's self-describing string format (salt included).
std::string hash_password(std::string_view password);
bool verify_password(std::string_view hash, std::string_view password);

} // namespace proculus::db

#endif // PROCULUS_DB_CRYPTO_HPP
