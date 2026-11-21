#ifndef PROCULUS_PORTSET_HPP
#define PROCULUS_PORTSET_HPP

// Thin RAII wrapper over the C pc_portset for C++ services.

#include <cstdlib>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "portset.h"

namespace proculus {

class PortSet {
public:
	PortSet() { pc_portset_init(&set_); }
	~PortSet() { pc_portset_free(&set_); }
	PortSet(const PortSet&) = delete;
	PortSet& operator=(const PortSet&) = delete;
	PortSet(PortSet&& o) noexcept : set_(o.set_) { pc_portset_init(&o.set_); }
	PortSet& operator=(PortSet&& o) noexcept {
		if (this != &o) {
			pc_portset_free(&set_);
			set_ = o.set_;
			pc_portset_init(&o.set_);
		}
		return *this;
	}

	// Throws std::invalid_argument on a malformed list
	void add_list(const std::string& list) {
		if (pc_portset_add_list(&set_, list.c_str()) != 0)
			throw std::invalid_argument("invalid port list: " + list);
	}
	void intersect(PortSet& other) {
		if (pc_portset_intersect(&set_, &other.set_) != 0)
			throw std::bad_alloc();
	}
	bool contains(uint16_t port) {
		return pc_portset_contains(&set_, port) != 0;
	}
	uint32_t count() { return pc_portset_count(&set_); }

	// e.g. "80,443,8000-8100"
	std::string format() {
		char* s = pc_portset_format(&set_);
		if (!s) throw std::bad_alloc();
		std::string out(s);
		std::free(s);
		return out;
	}

private:
	pc_portset set_;
};

} // namespace proculus

#endif // PROCULUS_PORTSET_HPP
