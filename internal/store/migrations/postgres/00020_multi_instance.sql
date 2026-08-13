-- +goose Up
-- Multi-instance: the directory tier and the workspace tier (#71,
-- multi-instance ADR). Roll-forward only: no Down section by policy.
--
-- STRUCTURALLY IDENTICAL to the sqlite dialect, which carries the reasoning
-- for every table, column and CHECK here. This file states only what differs,
-- which is the type vocabulary (TIMESTAMPTZ, BYTEA, BIGINT) and one genuine
-- dialect divergence noted at the sessions ALTER below.
--
-- hikyo:table instance_identity class=instance chain=-
-- hikyo:table remotes class=instance chain=-
-- hikyo:table remote_snapshots class=instance chain=-
-- hikyo:table instance_connections class=authn chain=-
-- hikyo:table workspace_origins class=authn chain=-
-- hikyo:table workspace_handoffs class=authn chain=-
-- hikyo:table sessions_rebuilt class=authn chain=-

-- The instance's own opaque identity, minted at init because migration is
-- init, preserved by backup/restore, returned only in the authenticated
-- directory listing.
CREATE TABLE instance_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    identity TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

INSERT INTO instance_identity (id, identity, created_at)
VALUES (1, 'ins_' || replace(gen_random_uuid()::text, '-', ''), now());

-- A connection entry. URL and pin are immutable; `name` is the one mutable
-- field; the credential is write-only after storage.
CREATE TABLE remotes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    spki_pin TEXT NOT NULL,
    credential_sealed BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
);

-- The last-known snapshot: last attempt and its outcome, plus the last
-- SUCCESSFUL listing, which is what "unreachable 2h — last known state shown"
-- reads from.
CREATE TABLE remote_snapshots (
    remote_id TEXT PRIMARY KEY REFERENCES remotes (id) ON DELETE CASCADE,
    last_attempt_at TIMESTAMPTZ NOT NULL,
    last_outcome TEXT NOT NULL CHECK (
        last_outcome IN (
            'ok', 'unreachable', 'credential-rejected', 'pin-mismatch',
            'redirect-refused', 'identity-conflict', 'self-connected'
        )
    ),
    observed_at TIMESTAMPTZ,
    instance_identity TEXT,
    version TEXT,
    org_count BIGINT,
    project_count BIGINT,
    listing TEXT,
    CHECK (
        (
            observed_at IS NULL AND instance_identity IS NULL AND version IS NULL
            AND org_count IS NULL AND project_count IS NULL AND listing IS NULL
        )
        OR (
            observed_at IS NOT NULL AND instance_identity IS NOT NULL AND version IS NOT NULL
            AND org_count IS NOT NULL AND project_count IS NOT NULL AND listing IS NOT NULL
        )
    ),
    CHECK (last_outcome <> 'ok' OR observed_at IS NOT NULL)
);

-- Principal and credential as one row: one credential per principal, ever.
CREATE TABLE instance_connections (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL UNIQUE REFERENCES principals (id),
    label TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('hikyo-token')),
    verifier BYTEA UNIQUE,
    prefix_hint TEXT NOT NULL,
    lifetime TEXT NOT NULL CHECK (lifetime IN ('finite', 'indefinite')),
    expires_at TIMESTAMPTZ,
    credential_epoch BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CHECK (
        (lifetime = 'finite' AND expires_at IS NOT NULL)
        OR (lifetime = 'indefinite' AND expires_at IS NULL)
    ),
    CHECK (kind <> 'hikyo-token' OR verifier IS NOT NULL)
);

-- Exact origins, no wildcards: the primary key is the origin itself.
CREATE TABLE workspace_origins (
    origin TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
);

-- The single-use handoff transaction.
CREATE TABLE workspace_handoffs (
    id TEXT PRIMARY KEY,
    state_verifier BYTEA NOT NULL UNIQUE,
    code_verifier BYTEA UNIQUE,
    origin TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('establishment', 'step-up')),
    session_id TEXT,
    operation TEXT,
    env_id TEXT,
    key_set TEXT,
    principal_id TEXT REFERENCES principals (id),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CHECK (
        (purpose = 'establishment' AND session_id IS NULL AND operation IS NULL)
        OR (purpose = 'step-up' AND session_id IS NOT NULL AND operation IS NOT NULL)
    )
);

CREATE INDEX workspace_handoffs_expiry ON workspace_handoffs (expires_at);

-- The workspace session is a `sessions` row — see the sqlite dialect for why
-- reuse is the requirement rather than a shortcut, and for the reasoning on
-- every column below.
--
-- Postgres could have widened the CHECK in place with three ALTERs. It rebuilds
-- the table instead, matching sqlite statement for statement, because the
-- cross-engine directive-parity lint requires every `hikyo:table` directive to
-- exist on both engines — a temporary table on one side only is a build
-- failure. One schema account, paid for in postgres DDL.
--
-- In-flight MFA ceremonies do not survive this migration, on either engine and
-- for the same stated reason. See the sqlite dialect.
CREATE TABLE sessions_rebuilt (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals (id),
    verifier BYTEA NOT NULL UNIQUE,
    artifact TEXT NOT NULL CHECK (artifact IN ('cli', 'browser', 'workspace')),
    session_generation BIGINT NOT NULL,
    credential_epoch BIGINT NOT NULL,
    auth_method TEXT NOT NULL,
    factors TEXT NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    ceremony_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    source_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    csrf_verifier BYTEA,
    provider_id TEXT REFERENCES oidc_providers (id) ON DELETE CASCADE,
    saml_provider_id TEXT REFERENCES saml_providers (id) ON DELETE CASCADE,
    requesting_origin TEXT,
    handoff_id TEXT,
    CONSTRAINT sessions_one_federated_provider
    CHECK (provider_id IS NULL OR saml_provider_id IS NULL),
    CHECK (
        (artifact = 'workspace' AND requesting_origin IS NOT NULL AND handoff_id IS NOT NULL)
        OR (artifact <> 'workspace' AND requesting_origin IS NULL AND handoff_id IS NULL)
    )
);

INSERT INTO sessions_rebuilt (
    id, principal_id, verifier, artifact, session_generation, credential_epoch,
    auth_method, factors, authenticated_at, ceremony_id, created_at,
    last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent,
    csrf_verifier, provider_id, saml_provider_id, requesting_origin, handoff_id
)
SELECT
    id, principal_id, verifier, artifact, session_generation, credential_epoch,
    auth_method, factors, authenticated_at, ceremony_id, created_at,
    last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent,
    csrf_verifier, provider_id, saml_provider_id, NULL, NULL
FROM sessions;

DELETE FROM reauth_windows;

-- Postgres refuses to drop a table a live FK depends on, so the dependency is
-- dropped by name and restored against the rebuilt table. sqlite has no
-- equivalent statement and needs none: its FK is inline in the child's DDL and
-- follows the rename.
ALTER TABLE reauth_windows DROP CONSTRAINT reauth_windows_session_id_fkey;

DROP TABLE sessions;

ALTER TABLE sessions_rebuilt RENAME TO sessions;

ALTER TABLE reauth_windows ADD CONSTRAINT reauth_windows_session_id_fkey
FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE;

CREATE INDEX sessions_principal_idx ON sessions (principal_id);

CREATE INDEX sessions_origin_idx ON sessions (requesting_origin);
