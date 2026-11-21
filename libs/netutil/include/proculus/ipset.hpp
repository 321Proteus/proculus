#ifndef PROCULUS_IPSET_HPP
#define PROCULUS_IPSET_HPP

// Thin RAII wrapper over the C pc_ipset for C++ services.

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

#include "proculus/ipset.h"

namespace proculus {

class IpSet {
public:
	IpSet() { pc_ipset_init(&set_); }
	~IpSet() { pc_ipset_free(&set_); }
	IpSet(const IpSet&) = delete;
	IpSet& operator=(const IpSet&) = delete;
	IpSet(IpSet&& o) noexcept : set_(o.set_) { pc_ipset_init(&o.set_); }
	IpSet& operator=(IpSet&& o) noexcept {
		if (this != &o) {
			pc_ipset_free(&set_);
			set_ = o.set_;
			pc_ipset_init(&o.set_);
		}
		return *this;
	}

	void add(pc_range r) { check(pc_ipset_add_range(&set_, r), "add"); }
	// Throws std::invalid_argument on a malformed spec.
	void add_spec(const std::string& spec) {
		if (pc_ipset_add_spec(&set_, spec.c_str()) != 0)
			throw std::invalid_argument("invalid IP spec: " + spec);
	}
	void subtract(pc_range r) {
		check(pc_ipset_subtract_range(&set_, r), "subtract");
	}
	void subtract(IpSet& other) {
		check(pc_ipset_subtract(&set_, &other.set_), "subtract");
	}
	void subtract_reserved() {
		check(pc_ipset_subtract_reserved(&set_), "subtract_reserved");
	}

	bool contains(uint32_t ip) { return pc_ipset_contains(&set_, ip) != 0; }
	uint64_t count() { return pc_ipset_count(&set_); }

	// Addresses last-exclusively as a new set
	IpSet slice(uint64_t start, uint64_t count) {
		IpSet out;
		check(pc_ipset_slice(&set_, start, count, &out.set_), "slice");
		return out;
	}

	// Minimal CIDR list joined by sep, e.g. 10.0.0.0/24,10.0.1.5.
	std::string format(char sep = ',') {
		char* s = pc_ipset_format(&set_, sep);
		if (!s) throw std::bad_alloc();
		std::string out(s);
		free(s);
		return out;
	}

	pc_ipset* raw() { return &set_; }

private:
	static void check(int rc, const char* what) {
		if (rc != 0)
			throw std::runtime_error(std::string("ipset ") + what + " failed");
	}
	pc_ipset set_;
};

} // namespace proculus

#endif // PROCULUS_IPSET_HPP
