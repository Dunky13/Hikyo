-- +goose Up
-- Keyring persistence (#43, encryption ADR): wrapped key blobs only — the
-- datastore never holds unwrapped key material, and the root key is never
-- stored at all. State columns and generation counters are the rotation
-- state-machine scaffolding; the five rotation operations land later.
-- Roll-forward only: no Down section by policy.
-- A row is one WRAPPER of one master version under one root epoch — not
-- the master itself. The dual-wrapped transition state of rotate-root-key
-- (encryption ADR § Rotation) is two active rows sharing a version with
-- different epochs; startup accepts any wrapper the presented root opens.
-- Scope-class declarations (tenant-isolation ADR; the derived registry must
-- be total, so #44's analyzer fails the build on an undeclared table).
-- Keyring rows are instance-scoped crypto material, not tenant-owned: a
-- tier-3 key's scope lives in its AAD, which is what binds the ciphertext,
-- and no query here carries a tenant predicate. They are reachable only
-- under a SystemProof minted at the boot mint site.
--
-- hikyo:table master_keys class=instance chain=-
-- hikyo:table tier3_keys class=instance chain=-
-- hikyo:table key_generations class=instance chain=-

CREATE TABLE master_keys (
    version BIGINT NOT NULL,
    root_key_epoch BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
    blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (version, root_key_epoch)
);
CREATE UNIQUE INDEX master_keys_one_active_per_epoch ON master_keys (root_key_epoch) WHERE state = 'active';

-- purpose 'scanning' is reserved by the secret-scanning amendment; unused
-- until its ticket lands. master_key_version carries no FK: master versions
-- are not unique rows once dual-wrapped; the keyring store verifies it
-- against the active master inside the creation transaction instead.
CREATE TABLE tier3_keys (
    id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (purpose IN ('project', 'instance', 'token', 'scanning')),
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    master_key_version BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'retiring', 'retired')),
    blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (purpose, org_id, project_id, version)
);
CREATE UNIQUE INDEX tier3_keys_one_active ON tier3_keys (purpose, org_id, project_id) WHERE state = 'active';

-- Fencing scaffolding (encryption ADR § Rotation): the 'hierarchy' row
-- serializes tier-3 key creation against future master/root rotation; per-
-- scope rows arrive with each tier-3 key.
CREATE TABLE key_generations (
    scope TEXT PRIMARY KEY,
    generation BIGINT NOT NULL
);
INSERT INTO key_generations (scope, generation) VALUES ('hierarchy', 1);
