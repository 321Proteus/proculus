#ifndef PROCULUS_GATEWAY_SIGNATURE_STORE_HPP
#define PROCULUS_GATEWAY_SIGNATURE_STORE_HPP

// The administrator's own signatures: one JSON document (the format of libs/signatures) that the
// UI edits as text. It is checked before it is saved (syntax, every rule of the signature format,
// and the examples inside it), saved to a file, and read by the runner at the start of every scan,
// next to the built-in signatures. Signatures only ever detect: the format cannot express
// anything that sends data, and the loader caps the extra paths one file may ask for.
//
// check() and save() never touch the running scans; the next scan uses what was saved.

#include <filesystem>
#include <mutex>
#include <string>

#include "api.hpp"
#include "proculus/sig/signature.hpp"

namespace proculus {

class SignatureStore {
public:
	// `file` empty: nothing is kept on disk (changes are lost on restart).
	explicit SignatureStore(std::filesystem::path file = {});

	const std::filesystem::path& file() const { return file_; }
	// The saved document, or "" when there is none.
	std::string text() const;
	// {text, signatures: [{id, name, category, interest, tags, description, threshold, signals, enabled, builtin, source}]}:
	// the built-in signatures and the custom ones as the scanner will see them (overrides and "disable" applied).
	Json list() const;
	// Validates `text` without saving: {ok, loaded, errors:[...], warnings:[...], examples:[...]} (examples: failed ones).
	Json check(const std::string& text) const;
	// Saves `text` (empty text removes the custom signatures). ApiError 400, carrying the problems in the message, if check() finds errors or failing examples.
	Json save(const std::string& text);

private:
	std::filesystem::path file_;
	mutable std::mutex m_;
	sig::SignatureSet builtin_;
};

} // namespace proculus

#endif // PROCULUS_GATEWAY_SIGNATURE_STORE_HPP
