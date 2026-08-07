-- +goose Up
-- Keyring persistence (#43, encryption ADR): wrapped key blobs only — the
-- datastore never holds unwrapped key material, and the root key is never
-- stored at all. State columns and generation counters are the rotation
-- state-machine scaffolding; the five rotation operations land later.
-- Roll-forward only: no Down section by policy.
CREATE TABLE master_keys (
    version INTEGER PRIMARY KEY,
    root_key_epoch INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
    blob BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX master_keys_one_active ON master_keys (state) WHERE state = 'active';

-- purpose 'scanning' is reserved by the secret-scanning amendment; unused
-- until its ticket lands.
CREATE TABLE tier3_keys (
    id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (purpose IN ('project', 'instance', 'token', 'scanning')),
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    master_key_version INTEGER NOT NULL REFERENCES master_keys (version),
    state TEXT NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
    blob BLOB NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (purpose, org_id, project_id, version)
);
CREATE UNIQUE INDEX tier3_keys_one_active ON tier3_keys (purpose, org_id, project_id) WHERE state = 'active';

-- Fencing scaffolding (encryption ADR § Rotation): the 'hierarchy' row
-- serializes tier-3 key creation against future master/root rotation; per-
-- scope rows arrive with each tier-3 key.
CREATE TABLE key_generations (
    scope TEXT PRIMARY KEY,
    generation INTEGER NOT NULL
);
INSERT INTO key_generations (scope, generation) VALUES ('hierarchy', 1);
