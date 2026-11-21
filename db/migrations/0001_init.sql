-- Proculus initial schema.
--
-- Conventions:
--  * Columns ending in _enc hold sealed bytea blobs (XChaCha20-Poly1305, see
--    libs/db crypto). Their plaintext is sensitive: banners, headers, cookies,
--    TLS data, free-text notes, user-edited values.
--  * IPs, ports and timestamps stay in the clear so they can be indexed,
--    joined and diffed.
--  * observations are append-only history; assets/services/http_endpoints hold
--    the current state derived from them. User edits live in overrides and are
--    never overwritten by a scan.

-- ---------------------------------------------------------------- RBAC

CREATE TABLE roles (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    permissions text[] NOT NULL DEFAULT '{}',
    builtin     boolean NOT NULL DEFAULT false
);

CREATE TABLE users (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL,
    password_hash text NOT NULL,
    role_id       bigint NOT NULL REFERENCES roles(id),
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX users_username_key ON users (lower(username));

-- Permissions: data.read, data.edit, data.create, data.delete, export,
-- scan.run, config.manage (profiles, schedules, signatures, scope), users.manage
INSERT INTO roles (name, description, permissions, builtin) VALUES
    ('admin',   'Administration: everything, including users and configuration',
        ARRAY['data.read','data.edit','data.create','data.delete','export','scan.run','config.manage','users.manage'], true),
    ('manager', 'Add, delete and modify data; run scans',
        ARRAY['data.read','data.edit','data.create','data.delete','export','scan.run'], true),
    ('editor',  'Modify and read existing data',
        ARRAY['data.read','data.edit','export'], true),
    ('viewer',  'Read only',
        ARRAY['data.read','export'], true);

-- ------------------------------------------------------- configuration

CREATE TABLE settings (
    key        text PRIMARY KEY,   -- e.g. scope, allowed_ports, exclusions
    value      jsonb NOT NULL,
    updated_by bigint REFERENCES users(id),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE targets (
    id         bigserial PRIMARY KEY,
    spec       text NOT NULL UNIQUE,  -- as entered: IP, CIDR, range or domain
    kind       text NOT NULL CHECK (kind IN ('ip','cidr','range','domain')),
    tags       text[] NOT NULL DEFAULT '{}',
    enabled    boolean NOT NULL DEFAULT true,
    source     text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','csv','json','api')),
    note_enc   bytea,
    created_by bigint REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scan_profiles (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL UNIQUE,
    config     jsonb NOT NULL,        -- rate, ports, timing, stages, ...
    created_by bigint REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE schedules (
    id               bigserial PRIMARY KEY,
    profile_id       bigint NOT NULL REFERENCES scan_profiles(id) ON DELETE CASCADE,
    name             text NOT NULL,
    interval_seconds integer NOT NULL CHECK (interval_seconds > 0),
    window_start     time NOT NULL,   -- a run may only be active inside the window
    window_end       time NOT NULL,
    timezone         text NOT NULL DEFAULT 'UTC',
    days_of_week     smallint[] NOT NULL DEFAULT '{1,2,3,4,5,6,7}',
    enabled          boolean NOT NULL DEFAULT true,
    last_run_at      timestamptz,
    next_run_at      timestamptz
);

-- ------------------------------------------------------------- scanning

CREATE TABLE scan_runs (
    id              bigserial PRIMARY KEY,
    profile_id      bigint REFERENCES scan_profiles(id) ON DELETE SET NULL,
    schedule_id     bigint REFERENCES schedules(id) ON DELETE SET NULL,
    status          text NOT NULL DEFAULT 'planned'
                    CHECK (status IN ('planned','running','completed','aborted','failed')),
    created_by      bigint REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    window_deadline timestamptz,      -- unfinished chunks go back to pending after this
    total_addresses bigint NOT NULL DEFAULT 0
);
CREATE INDEX scan_runs_status_idx ON scan_runs (status);

-- Work queue: workers claim rows with FOR UPDATE SKIP LOCKED.
CREATE TABLE scan_chunks (
    id            bigserial PRIMARY KEY,
    run_id        bigint NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    stage         text NOT NULL CHECK (stage IN ('discovery','services','http')),
    idx           integer NOT NULL,
    targets       text NOT NULL,      -- comma-separated CIDR list
    address_count bigint NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','done','failed')),
    attempts      integer NOT NULL DEFAULT 0,
    claimed_by    text,
    claimed_at    timestamptz,
    finished_at   timestamptz,
    error         text,
    UNIQUE (run_id, stage, idx)
);
CREATE INDEX scan_chunks_pending_idx ON scan_chunks (run_id, stage, idx) WHERE status = 'pending';

-- Append-only history. Port columns are NULL for host-level (discovery) rows;
-- `attempt` distinguishes repeated measurements of unstable hosts in one run.
CREATE TABLE observations (
    id           bigserial PRIMARY KEY,
    run_id       bigint NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    chunk_id     bigint REFERENCES scan_chunks(id) ON DELETE SET NULL,
    observed_at  timestamptz NOT NULL DEFAULT now(),
    attempt      smallint NOT NULL DEFAULT 1,
    ip           inet NOT NULL,
    host_up      boolean NOT NULL,
    port         integer CHECK (port BETWEEN 1 AND 65535),
    protocol     text,
    port_state   text,
    service_name text,
    product      text,
    version      text,
    extrainfo    text,
    tunnel       text,
    confidence   smallint,
    cpes         text[],
    banner_enc   bytea
);
CREATE UNIQUE INDEX observations_key ON observations
    (run_id, ip, coalesce(port, 0), coalesce(protocol, ''), attempt);
CREATE INDEX observations_ip_time_idx ON observations (ip, observed_at);

CREATE TABLE http_observations (
    id            bigserial PRIMARY KEY,
    run_id        bigint NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    observed_at   timestamptz NOT NULL DEFAULT now(),
    ip            inet NOT NULL,
    port          integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    scheme        text NOT NULL CHECK (scheme IN ('http','https')),
    status_code   integer,
    favicon_hash  integer,
    title_enc     bytea,
    headers_enc   bytea,
    cookies_enc   bytea,
    tls_enc       bytea,
    redirects_enc bytea
);
CREATE INDEX http_observations_ip_idx ON http_observations (ip, port, observed_at);

-- ------------------------------------------------ current state (derived)

CREATE TABLE assets (
    id             bigserial PRIMARY KEY,
    ip             inet NOT NULL UNIQUE,
    state          text NOT NULL DEFAULT 'new'
                   CHECK (state IN ('new','active','flapping','stale','gone')),
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz,
    last_run_id    bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    miss_count     integer NOT NULL DEFAULT 0,   -- consecutive misses
    confidence     real NOT NULL DEFAULT 0,
    interest       integer NOT NULL DEFAULT 0,   -- analytic priority score
    tags           text[] NOT NULL DEFAULT '{}',
    -- hits / scans per hour of day (UTC), for time-of-day differences
    presence_hits  integer[] NOT NULL DEFAULT array_fill(0, ARRAY[24]),
    presence_total integer[] NOT NULL DEFAULT array_fill(0, ARRAY[24])
);
CREATE INDEX assets_state_idx ON assets (state);

CREATE TABLE services (
    id          bigserial PRIMARY KEY,
    asset_id    bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port        integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol    text NOT NULL DEFAULT 'tcp',
    status      text NOT NULL DEFAULT 'new' CHECK (status IN ('new','active','changed','gone')),
    name        text,
    product     text,
    version     text,
    extrainfo   text,
    banner_enc  bytea,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz,
    last_run_id bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    miss_count  integer NOT NULL DEFAULT 0,
    UNIQUE (asset_id, port, protocol)
);

CREATE TABLE http_endpoints (
    id            bigserial PRIMARY KEY,
    asset_id      bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port          integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    scheme        text NOT NULL CHECK (scheme IN ('http','https')),
    status_code   integer,
    favicon_hash  integer,
    title_enc     bytea,
    headers_enc   bytea,
    cookies_enc   bytea,
    tls_enc       bytea,
    redirects_enc bytea,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz,
    last_run_id   bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    UNIQUE (asset_id, port, scheme)
);

-- ------------------------------------------------------------ signatures

CREATE TABLE signatures (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL UNIQUE,
    category   text NOT NULL CHECK (category IN ('cms','framework','server','iot','staging','admin','other')),
    definition jsonb NOT NULL,        -- matchers + weights (passive/safe checks only)
    enabled    boolean NOT NULL DEFAULT true,
    builtin    boolean NOT NULL DEFAULT false,
    created_by bigint REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE detections (
    id           bigserial PRIMARY KEY,
    asset_id     bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    endpoint_id  bigint REFERENCES http_endpoints(id) ON DELETE CASCADE,
    signature_id bigint NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    confidence   real NOT NULL,
    evidence_enc bytea,
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    last_run_id  bigint REFERENCES scan_runs(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX detections_key ON detections
    (asset_id, coalesce(endpoint_id, 0), signature_id);

-- ------------------------------------------------- user edits and audit

-- Edits to scanned data. Applied on read; scans never touch this table, so
-- edits survive every later scan.
CREATE TABLE overrides (
    id          bigserial PRIMARY KEY,
    entity_type text NOT NULL CHECK (entity_type IN ('asset','service','http_endpoint','detection')),
    entity_id   bigint NOT NULL,
    field       text NOT NULL,
    value_enc   bytea NOT NULL,
    set_by      bigint REFERENCES users(id),
    set_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (entity_type, entity_id, field)
);

CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    user_id   bigint REFERENCES users(id) ON DELETE SET NULL,
    action    text NOT NULL,
    entity    text,
    entity_id bigint,
    detail    jsonb,
    source_ip inet
);
CREATE INDEX audit_log_at_idx ON audit_log (at);
