#include "proculus/db/crypto.hpp"

#include <sodium.h>

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace proculus::db {

namespace {

constexpr uint8_t kVersion = 1;
constexpr size_t kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
constexpr size_t kTag = crypto_aead_xchacha20poly1305_ietf_ABYTES;      // 16
constexpr size_t kHeader = 2 + kNonce;

void init_sodium() {
	static const bool ok = sodium_init() >= 0;
	if (!ok) throw CryptoError("libsodium initialisation failed");
}

std::string trim(std::string_view s) {
	size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string_view::npos) return "";
	size_t b = s.find_last_not_of(" \t\r\n");
	return std::string(s.substr(a, b - a + 1));
}

void add_entry(KeyRing& ring, const std::string& entry) {
	uint8_t id = 1;
	std::string hex = entry;
	if (auto colon = entry.find(':'); colon != std::string::npos) {
		std::string id_text = trim(entry.substr(0, colon));
		hex = trim(entry.substr(colon + 1));
		char* end = nullptr;
		unsigned long v = std::strtoul(id_text.c_str(), &end, 10);
		if (id_text.empty() || *end != '\0' || v < 1 || v > 255)
			throw CryptoError("key id must be a number 1..255");
		id = static_cast<uint8_t>(v);
	}
	if (ring.find(id)) throw CryptoError("duplicate key id " + std::to_string(id));
	ring.add(id, Key::from_hex(hex));
}

} // namespace

// ---------------------------------------------------------------- Key

Key::~Key() {
	if (sodium_init() >= 0) sodium_memzero(bytes_.data(), bytes_.size());
}

Key Key::from_hex(std::string_view hex) {
	init_sodium();
	std::string h = trim(hex);
	Key k;
	size_t len = 0;
	const char* end = nullptr;
	if (h.size() != kSize * 2 ||
		sodium_hex2bin(k.bytes_.data(), k.bytes_.size(), h.c_str(), h.size(), nullptr, &len, &end) != 0 ||
		len != kSize || *end != '\0')
		throw CryptoError("a key must be exactly 64 hex characters");
	return k;
}

Key Key::generate() {
	init_sodium();
	Key k;
	randombytes_buf(k.bytes_.data(), k.bytes_.size());
	return k;
}

std::string Key::to_hex() const {
	char buf[kSize * 2 + 1];
	sodium_bin2hex(buf, sizeof buf, bytes_.data(), bytes_.size());
	return buf;
}

// ------------------------------------------------------------ KeyRing

void KeyRing::add(uint8_t id, Key key) {
	if (id == 0) throw CryptoError("key id 0 is reserved");
	keys_[id] = key;
}

uint8_t KeyRing::current_id() const {
	if (keys_.empty()) throw CryptoError("no encryption keys configured");
	return keys_.rbegin()->first;
}

const Key* KeyRing::find(uint8_t id) const {
	auto it = keys_.find(id);
	return it == keys_.end() ? nullptr : &it->second;
}

KeyRing KeyRing::from_text(std::string_view text) {
	KeyRing ring;
	std::istringstream in{std::string(text)};
	std::string line;
	while (std::getline(in, line)) {
		if (auto hash = line.find('#'); hash != std::string::npos) line.erase(hash);
		line = trim(line);
		if (!line.empty()) add_entry(ring, line);
	}
	if (ring.empty()) throw CryptoError("no keys found");
	return ring;
}

KeyRing KeyRing::from_env() {
	if (const char* path = std::getenv("PROCULUS_KEY_FILE"); path && *path) {
		std::ifstream f(path);
		if (!f) throw CryptoError(std::string("cannot read key file ") + path);
		std::ostringstream ss;
		ss << f.rdbuf();
		return from_text(ss.str());
	}
	if (const char* key = std::getenv("PROCULUS_KEY"); key && *key) {
		KeyRing ring;
		add_entry(ring, trim(key));
		return ring;
	}
	throw CryptoError("set PROCULUS_KEY_FILE or PROCULUS_KEY to the data encryption key");
}

// -------------------------------------------------------- FieldCipher

FieldCipher::FieldCipher(KeyRing keys) : keys_(std::move(keys)) {
	init_sodium();
	if (keys_.empty()) throw CryptoError("no encryption keys configured");
}

std::vector<uint8_t> FieldCipher::seal(std::string_view plaintext, std::string_view context) const {
	const uint8_t id = keys_.current_id();
	std::vector<uint8_t> blob(kHeader + plaintext.size() + kTag);
	blob[0] = kVersion;
	blob[1] = id;
	randombytes_buf(blob.data() + 2, kNonce);

	unsigned long long clen = 0;
	crypto_aead_xchacha20poly1305_ietf_encrypt(blob.data() + kHeader, &clen,
		reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
		reinterpret_cast<const unsigned char*>(context.data()), context.size(), nullptr,
		blob.data() + 2, keys_.find(id)->data());
	blob.resize(kHeader + static_cast<size_t>(clen));
	return blob;
}

std::string FieldCipher::open(const std::vector<uint8_t>& blob, std::string_view context) const {
	if (blob.size() < kHeader + kTag || blob[0] != kVersion) throw CryptoError("malformed encrypted value");
	const Key* key = keys_.find(blob[1]);
	if (!key) throw CryptoError("value was sealed with unknown key id " + std::to_string(blob[1]));

	std::string out(blob.size() - kHeader - kTag, '\0');
	unsigned long long mlen = 0;
	if (crypto_aead_xchacha20poly1305_ietf_decrypt(reinterpret_cast<unsigned char*>(out.data()), &mlen,
		    nullptr, blob.data() + kHeader, blob.size() - kHeader,
		    reinterpret_cast<const unsigned char*>(context.data()), context.size(),
		    blob.data() + 2, key->data()) != 0)
		throw CryptoError("encrypted value failed authentication (wrong key/context or tampered)");
	out.resize(static_cast<size_t>(mlen));
	return out;
}

// ---------------------------------------------------------- passwords

std::string hash_password(std::string_view password) {
	init_sodium();
	char out[crypto_pwhash_STRBYTES];
	if (crypto_pwhash_str(out, password.data(), password.size(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
		    crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
		throw CryptoError("password hashing failed (out of memory)");
	return out;
}

bool verify_password(std::string_view hash, std::string_view password) {
	init_sodium();
	std::string h(hash); // needs a NUL-terminated string
	return crypto_pwhash_str_verify(h.c_str(), password.data(), password.size()) == 0;
}

} // namespace proculus::db
