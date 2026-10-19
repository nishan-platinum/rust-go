CREATE TABLE IF NOT EXISTS admins (
    id            bigserial PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Only a SHA-256 of the session token is stored, so a leaked table cannot be
-- replayed as cookies.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash bytea PRIMARY KEY,
    admin_id   bigint NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    user_agent text NOT NULL DEFAULT '',
    ip         text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

-- Database servers SciCom CX can create managed tenant databases on. The admin
-- credentials are only used for CREATE/DROP DATABASE and USER.
CREATE TABLE IF NOT EXISTS db_servers (
    id                 bigserial PRIMARY KEY,
    name               text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
    db_type            text NOT NULL CHECK (db_type IN ('postgres', 'mysql', 'mariadb', 'mongodb')),
    host               text NOT NULL,
    port               integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    admin_username     text NOT NULL,
    admin_password_enc bytea NOT NULL,
    params             jsonb NOT NULL DEFAULT '{}',
    is_default         boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now()
);
-- At most one default server per database type.
CREATE UNIQUE INDEX IF NOT EXISTS db_servers_one_default ON db_servers (db_type) WHERE is_default;

-- The tenant id is also its subdomain: <id>.<BASE_DOMAIN>. Max 28 chars so the
-- generated DB user name (scx_<id>) fits MySQL's 32-char limit.
CREATE TABLE IF NOT EXISTS tenants (
    id             text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,26}[a-z0-9]$'),
    name           text NOT NULL,
    db_type        text NOT NULL CHECK (db_type IN ('postgres', 'mysql', 'mariadb', 'mongodb')),
    host           text NOT NULL,
    port           integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username       text NOT NULL,
    password_enc   bytea NOT NULL,
    database       text NOT NULL,
    params         jsonb NOT NULL DEFAULT '{}',
    -- Bumped on every connection change; the engine rebuilds the pool.
    config_version bigint NOT NULL DEFAULT 1,
    -- Bumped to revoke every token issued to the tenant.
    token_version  bigint NOT NULL DEFAULT 1,
    enabled        boolean NOT NULL DEFAULT true,
    -- managed: SciCom CX created the database on server_id and may drop it.
    -- external: an existing database we only connect to (never dropped).
    mode           text NOT NULL DEFAULT 'external' CHECK (mode IN ('managed', 'external')),
    server_id      bigint REFERENCES db_servers(id) ON DELETE RESTRICT,
    -- Whether <id>.<BASE_DOMAIN> is served. Off for clients that only use
    -- their own domain (tenant_domains).
    subdomain_enabled boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    -- Control-plane guard against two tenants sharing one database. The engine
    -- also enforces this inside the database itself (hostnames can alias).
    UNIQUE (db_type, host, port, database)
);

-- Sessions of tenant users on their subdomain portal. The users themselves
-- live in the tenant's own database; a session is only valid for its tenant.
CREATE TABLE IF NOT EXISTS tenant_sessions (
    token_hash bytea PRIMARY KEY,
    tenant_id  text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    text NOT NULL,
    email      text NOT NULL,
    name       text NOT NULL,
    role       text NOT NULL,
    csrf_token text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS tenant_sessions_expires_idx ON tenant_sessions (expires_at);

-- Optional custom domains (e.g. support.acme.com). The subdomain always
-- works; a custom domain is only served once ownership is verified.
CREATE TABLE IF NOT EXISTS tenant_domains (
    domain       text PRIMARY KEY CHECK (domain = lower(domain)),
    tenant_id    text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    verify_token text NOT NULL,
    verified_at  timestamptz,
    is_primary   boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);
-- At most one primary domain per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_domains_one_primary ON tenant_domains (tenant_id) WHERE is_primary;

CREATE TABLE IF NOT EXISTS audit_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    actor     text NOT NULL,
    action    text NOT NULL,
    tenant_id text NOT NULL DEFAULT '',
    detail    text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_log_at_idx ON audit_log (at DESC);
