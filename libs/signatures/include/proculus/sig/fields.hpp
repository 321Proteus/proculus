#ifndef PROCULUS_SIG_FIELDS_HPP
#define PROCULUS_SIG_FIELDS_HPP

// The vocabulary of facts a signature may test. A signature refers to a field
// by name; this header is the single place that says which names exist, what
// type each has, and which operators make sense for it.
//
//   number:  status  port  favicon_hash  body_length  tls.key_bits
//   string:  url  title  body  server  content_type  host
//            tls.version  tls.cipher  tls.subject  tls.issuer
//            tls.key_type  tls.signature_algorithm
//            service.name  service.product  service.version
//   bool:    tls  tls.self_signed  tls.expired  tls.not_yet_valid  tls.hostname_match
//   list:    cookie  cookie_insecure  cookie_no_httponly  redirect_location
//            tls.san  hostnames  header_names
//   dynamic: header:<name>                 list    values of a response header
//            path:<p>:status               number  \  a safe extra path that the prober
//            path:<p>:body|title|          string  /  fetches (GET only), e.g. /wp-login.php
//              content_type|redirect
//            path:<p>:header:<name>        list
//
// A list matches if any element matches.

#include <map>
#include <optional>
#include <string>

namespace proculus::sig {

enum class FieldType { Number, String, Bool, StringList };

enum class Op { Equals, Contains, Prefix, Suffix, Regex, Exists, Gt, Ge, Lt, Le };

const char* to_string(Op op);
std::optional<Op> parse_op(const std::string& name);
const char* to_string(FieldType t);

// The fixed fields (not header:/path: ones), by name.
const std::map<std::string, FieldType>& known_fields();

// The type of `field`, or nullopt with `error` set if there is no such field or
// a dynamic field is malformed.
std::optional<FieldType> field_type(const std::string& field, std::string& error);

// Which operators apply to a field of this type.
bool op_allowed(FieldType type, Op op);

// For path:<p>:... fields, the probed path; otherwise nullopt.
std::optional<std::string> probe_path_of(const std::string& field);

// A path a signature may ask the prober to fetch. Detection must stay safe:
// absolute, short, plain characters only, no query string, no "..", no
// fragments. A signature can look at a page; it cannot send parameters.
bool valid_probe_path(const std::string& path);

} // namespace proculus::sig

#endif // PROCULUS_SIG_FIELDS_HPP
