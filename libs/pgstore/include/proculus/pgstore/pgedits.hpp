#ifndef PROCULUS_PGEDITS_HPP
#define PROCULUS_PGEDITS_HPP

// The EditStore of libs/edits in Postgres (table entity_edits). The edited values
// are sealed with the field cipher, bound to their column; the address, port,
// protocol, who and when stay readable. Edits of one key are serialised with an
// advisory lock, so two people editing different fields do not overwrite each
// other. Every operation uses its own connection.

#include <memory>
#include <string>

#include "proculus/db/crypto.hpp"
#include "proculus/edits/edits.hpp"

namespace proculus {

std::unique_ptr<EditStore> make_pg_edit_store(const std::string& conninfo, db::FieldCipher cipher);

} // namespace proculus

#endif
