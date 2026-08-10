-- +goose Up
-- SAML SP storage (#72, saml-sp ADR). Roll-forward only: no Down section.
--
-- hikyo:table saml_providers class=authn chain=-
-- hikyo:table saml_transactions class=authn chain=-
-- hikyo:table saml_replay class=authn chain=-
-- hikyo:table saml_sp_keys class=authn chain=-

-- Existing rows are OIDC by construction. Pin that backfill explicitly before
-- widening the discriminator so an old identity cannot acquire a new meaning.
UPDATE external_identities SET kind = 'oidc' WHERE kind = 'oidc';
ALTER TABLE external_identities DROP CONSTRAINT external_identities_kind_check;
ALTER TABLE external_identities ADD CONSTRAINT external_identities_kind_check
    CHECK (kind IN ('oidc', 'saml'));

CREATE TABLE saml_providers (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind = 'saml'),
    entity_id TEXT NOT NULL,
    acs_url TEXT NOT NULL,
    sso_redirect_url TEXT NOT NULL,
    signing_certificates BYTEA NOT NULL,
    assurance_policy TEXT,
    allow_email_nameid BIGINT NOT NULL CHECK (allow_email_nameid IN (0, 1)),
    force_sign_requests BIGINT NOT NULL CHECK (force_sign_requests IN (0, 1)),
    metadata_want_authn_requests_signed BIGINT NOT NULL CHECK (metadata_want_authn_requests_signed IN (0, 1)),
    metadata_source TEXT NOT NULL CHECK (metadata_source IN ('file', 'url')),
    metadata_url TEXT,
    metadata_signed BIGINT NOT NULL CHECK (metadata_signed IN (0, 1)),
    metadata_signing_fingerprint TEXT,
    metadata_valid_until TIMESTAMPTZ,
    enabled BIGINT NOT NULL CHECK (enabled IN (0, 1)),
    row_version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (
        (metadata_source = 'file' AND metadata_url IS NULL)
        OR (metadata_source = 'url' AND metadata_url IS NOT NULL)
    ),
    CHECK (metadata_signed = 0 OR metadata_signing_fingerprint IS NOT NULL)
);

CREATE UNIQUE INDEX saml_providers_entity_enabled
    ON saml_providers (kind, entity_id)
    WHERE enabled = 1;

CREATE TABLE saml_transactions (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    relay_state_verifier BYTEA NOT NULL UNIQUE,
    initiator_verifier BYTEA NOT NULL,
    provider_id TEXT NOT NULL REFERENCES saml_providers (id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    acs_url TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'link', 'reauth')),
    initiating_session_id TEXT,
    account_id TEXT,
    environment_id TEXT,
    ceremony_id TEXT,
    credential_epoch BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
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

CREATE TABLE saml_replay (
    issuer TEXT NOT NULL,
    assertion_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer, assertion_id)
);

CREATE INDEX saml_replay_expiry_idx ON saml_replay (expires_at);

CREATE TABLE saml_sp_keys (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('active', 'retiring')),
    encrypted_private_key BYTEA NOT NULL,
    certificate_der BYTEA NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    dek_version BIGINT NOT NULL,
    row_version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX saml_sp_keys_one_active
    ON saml_sp_keys (state) WHERE state = 'active';

ALTER TABLE sessions ADD COLUMN saml_provider_id TEXT
    REFERENCES saml_providers (id) ON DELETE CASCADE;
ALTER TABLE sessions ADD CONSTRAINT sessions_one_federated_provider
    CHECK (provider_id IS NULL OR saml_provider_id IS NULL);
