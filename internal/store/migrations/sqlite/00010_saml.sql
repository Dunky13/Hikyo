-- +goose Up
-- SAML SP storage (#72, saml-sp ADR). Roll-forward only: no Down section.
--
-- hikyo:table saml_providers class=authn chain=-
-- hikyo:table saml_transactions class=authn chain=-
-- hikyo:table saml_replay class=authn chain=-
-- hikyo:table saml_sp_keys class=authn chain=-

-- SQLite cannot widen a CHECK in place. Rebuild the identity table and copy
-- every pre-amendment OIDC row unchanged; the new discriminator admits SAML
-- without weakening the byte-exact (kind, issuer, subject) key.
ALTER TABLE external_identities RENAME TO external_identities_oidc;

CREATE TABLE external_identities (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    kind TEXT NOT NULL CHECK (kind IN ('oidc', 'saml')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (kind, issuer, subject)
);

INSERT INTO external_identities
    (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at)
SELECT id, account_id, 'oidc', issuer, subject, provider_id, credential_epoch, created_at
FROM external_identities_oidc;

DROP TABLE external_identities_oidc;

-- SAML provider policy and pinned metadata. entity_id is immutable after
-- create. Public signing certificates are stored as the wrapper's canonical
-- JSON byte representation; the service validates that representation before
-- this boundary. No JIT column exists: SAML authentication never provisions.
CREATE TABLE saml_providers (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind = 'saml'),
    entity_id TEXT NOT NULL,
    acs_url TEXT NOT NULL,
    sso_redirect_url TEXT NOT NULL,
    signing_certificates BLOB NOT NULL,
    assurance_policy TEXT,
    allow_email_nameid INTEGER NOT NULL CHECK (allow_email_nameid IN (0, 1)),
    force_sign_requests INTEGER NOT NULL CHECK (force_sign_requests IN (0, 1)),
    metadata_want_authn_requests_signed INTEGER NOT NULL CHECK (metadata_want_authn_requests_signed IN (0, 1)),
    metadata_source TEXT NOT NULL CHECK (metadata_source IN ('file', 'url')),
    metadata_url TEXT,
    metadata_signed INTEGER NOT NULL CHECK (metadata_signed IN (0, 1)),
    metadata_signing_fingerprint TEXT,
    metadata_valid_until TEXT,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    row_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (metadata_source = 'file' AND metadata_url IS NULL)
        OR (metadata_source = 'url' AND metadata_url IS NOT NULL)
    ),
    CHECK (metadata_signed = 0 OR metadata_signing_fingerprint IS NOT NULL)
);

-- One active provider per (kind, issuer/entityID). Disabled historical rows
-- may coexist so delete/recreate and operator reconciliation remain possible.
CREATE UNIQUE INDEX saml_providers_entity_enabled
    ON saml_providers (kind, entity_id)
    WHERE enabled = 1;

-- Server-side request binding. request_id and RelayState are independent
-- unique handles; consumed_at's NULL guard is the atomic one-use claim.
CREATE TABLE saml_transactions (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    relay_state_verifier BLOB NOT NULL UNIQUE,
    initiator_verifier BLOB NOT NULL,
    provider_id TEXT NOT NULL REFERENCES saml_providers (id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    acs_url TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'link', 'reauth')),
    initiating_session_id TEXT,
    account_id TEXT,
    environment_id TEXT,
    ceremony_id TEXT,
    credential_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    CHECK (
        (purpose = 'login'
            AND initiator_verifier IS NOT NULL
            AND initiating_session_id IS NULL
            AND account_id IS NULL
            AND environment_id IS NULL
            AND ceremony_id IS NULL)
        OR
        (purpose = 'link'
            AND initiator_verifier IS NOT NULL
            AND initiating_session_id IS NOT NULL
            AND account_id IS NOT NULL
            AND environment_id IS NULL
            AND ceremony_id IS NOT NULL)
        OR
        (purpose = 'reauth'
            AND initiator_verifier IS NOT NULL
            AND initiating_session_id IS NOT NULL
            AND account_id IS NOT NULL
            AND environment_id IS NOT NULL)
    )
);

-- Assertion replay state deliberately has no provider FK: removing and
-- re-adding a provider must not reopen an assertion's replay window. The
-- issuer-qualified primary key avoids collisions between independent IdPs.
CREATE TABLE saml_replay (
    issuer TEXT NOT NULL,
    assertion_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (issuer, assertion_id)
);

CREATE INDEX saml_replay_expiry_idx ON saml_replay (expires_at);

-- Instance SP request-signing material. The private key is envelope-encrypted
-- under InstanceFieldAAD; at most one active key exists, while any number of
-- retiring keys may remain published during a manual rollover.
CREATE TABLE saml_sp_keys (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('active', 'retiring')),
    encrypted_private_key BLOB NOT NULL,
    certificate_der BLOB NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    dek_version INTEGER NOT NULL,
    row_version INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX saml_sp_keys_one_active
    ON saml_sp_keys (state) WHERE state = 'active';

-- SAML sessions need their own FK because the existing provider_id points at
-- oidc_providers. The cross-column CHECK makes provider provenance singular.
ALTER TABLE sessions ADD COLUMN saml_provider_id TEXT
    REFERENCES saml_providers (id) ON DELETE CASCADE
    CHECK (provider_id IS NULL OR saml_provider_id IS NULL);
