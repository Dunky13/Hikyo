-- +goose Up
-- Multi-provider OIDC (#54, human-auth ADR -- Login methods, Identity linking,
-- The OIDC transaction). Roll-forward only: no Down section by policy.
--
-- Every table here is class=authn, for the same reason 00005's and 00006's
-- are: the artifacts that decide who a caller is and how strongly they
-- authenticated are resolved on the proof-free surface, because the proof is
-- what that answer produces.
--
-- wenv:table oidc_providers class=authn chain=-
-- wenv:table external_identities class=authn chain=-
-- wenv:table oidc_transactions class=authn chain=-

-- A configured OpenID Provider. The issuer is byte-exact and IMMUTABLE after
-- create (A3): a PUT that changes it is refused by name, remedy is
-- delete+create, because the identity space is keyed by issuer and rebinding
-- it silently would move every linked identity under a new authority. At most
-- one ENABLED provider per (kind, issuer) so a login for an issuer resolves to
-- one policy. client_secret is envelope-encrypted under the instance DEK
-- (InstanceFieldAAD). jit_policy and assurance_policy are nullable JSON, both
-- absent by default (weakest privilege: no JIT, single-factor assurance).
-- redirect_uri is the per-provider callback string (A1), registered at create
-- and replayed verbatim at token exchange.
CREATE TABLE oidc_providers (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('oidc')),
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret BLOB NOT NULL,
    scopes TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    jit_policy TEXT,
    assurance_policy TEXT,
    enabled INTEGER NOT NULL,
    dek_version INTEGER NOT NULL,
    row_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- One enabled provider per (kind, issuer). Disabled rows do not collide, so a
-- delete-then-recreate for the same issuer is possible while a stale disabled
-- row lingers.
CREATE UNIQUE INDEX oidc_providers_issuer_enabled
    ON oidc_providers (kind, issuer)
    WHERE enabled = 1;

-- A linked external identity. The identity key is (kind, issuer, subject),
-- byte-exact (no trimming, case-fold or URL normalization): two issuers
-- differing only in case are two identity spaces, two subjects differing only
-- in case are two identities. Email is never a linking key and there is no
-- email column, ever. provider_id is provenance only (A3): NOT part of the
-- uniqueness key, plain string, so deleting a provider leaves the identity
-- standing (login then refuses to operator reconciliation because the recorded
-- provider is no longer the enabled one for the issuer). credential_epoch makes
-- a restored link inert until reconciled.
CREATE TABLE external_identities (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    kind TEXT NOT NULL CHECK (kind IN ('oidc')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (kind, issuer, subject)
);

-- A server-side OIDC transaction record: short-lived, single-use, and the
-- single source of callback truth. state_verifier is the SHA-256 of the st
-- artifact carried across the IdP redirect. nonce is stored HASHED
-- (compare-only, A19); pkce_verifier stays raw because it is sent at exchange.
-- provider_id is ON DELETE CASCADE (A14): deleting a provider drops its live
-- transactions. issuer is a pinned copy validated against the token AND
-- re-checked equal to the live provider row at exchange (A11). redirect_uri is
-- the per-provider callback replayed at exchange (A1). binding_kind is a NOT
-- NULL discriminator (A2) with no default callback branch: a session-bound tx
-- carries initiating_session_id, a browser-cookie-bound tx carries
-- browser_binding_verifier (the hash of the ob cookie), and the CHECKs make the
-- matching column mandatory. ceremony_id is non-null for link (A6): the
-- account-security proof bound to this exact link, consumed with the tx.
CREATE TABLE oidc_transactions (
    id TEXT PRIMARY KEY,
    state_verifier BLOB NOT NULL UNIQUE,
    nonce BLOB NOT NULL,
    pkce_verifier TEXT NOT NULL,
    provider_id TEXT NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'link', 'reauth')),
    binding_kind TEXT NOT NULL CHECK (binding_kind IN ('session', 'browser-cookie')),
    initiating_session_id TEXT,
    browser_binding_verifier BLOB,
    account_id TEXT,
    environment_id TEXT,
    ceremony_id TEXT,
    credential_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    -- The binding discriminator has no default branch: exactly the matching
    -- column is required.
    CHECK (binding_kind <> 'session' OR initiating_session_id IS NOT NULL),
    CHECK (binding_kind <> 'browser-cookie' OR browser_binding_verifier IS NOT NULL),
    -- link and reauth bind an account; link additionally binds the proof
    -- ceremony; reauth additionally binds the environment its window scopes.
    CHECK (purpose <> 'link' OR (account_id IS NOT NULL AND ceremony_id IS NOT NULL)),
    CHECK (purpose <> 'reauth' OR (account_id IS NOT NULL AND environment_id IS NOT NULL))
);

-- The federated-session sweep key (A4): set at mint for a session authenticated
-- through a provider, NULL for local sessions. A provider disable/delete or an
-- issuer/client/assurance-policy change deletes sessions by this key, so a
-- stale-assurance session cannot survive a policy narrowing. reauth_windows
-- cascade from their session (00006), so the sweep reaches their windows too.
ALTER TABLE sessions ADD COLUMN provider_id TEXT;
