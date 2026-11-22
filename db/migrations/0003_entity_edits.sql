-- User edits of scanned data (see libs/edits): keyed by what they are about
-- (address, and port and protocol for a service; port 0 = the host itself),
-- not by any scan, so no scan ever touches them and they survive every later
-- scan. The edited values are sealed; the key and who/when stay readable.
--
-- (The older `overrides` table is keyed by ids of the derived assets/services
-- tables, which are not populated; this replaces its purpose.)

CREATE TABLE entity_edits (
    id        bigserial PRIMARY KEY,
    ip        inet NOT NULL,
    port      integer NOT NULL DEFAULT 0 CHECK (port BETWEEN 0 AND 65535),
    protocol  text NOT NULL DEFAULT '',
    data_enc  bytea NOT NULL,
    edited_by text NOT NULL DEFAULT '',
    edited_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (ip, port, protocol)
);
