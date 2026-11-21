#ifndef PROCULUS_RESULT_JSON_HPP
#define PROCULUS_RESULT_JSON_HPP

#include <string>

#include "nmap_xml.hpp"

namespace proculus {

// Serialises a parsed scan as a JSON document (UTF-8, pretty-printed).
std::string to_json(const NmapResult& r);

// Escapes `s` as the body of a JSON string (without the quotes).
std::string json_escape(const std::string& s);

} // namespace proculus

#endif // PROCULUS_RESULT_JSON_HPP
