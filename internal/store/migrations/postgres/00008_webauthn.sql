-- +goose Up
-- WebAuthn / passkeys (#54, human-auth ADR -- WebAuthn relying-party policy,
-- Passkey login, Account-security mutations). Roll-forward only: no Down
-- section by policy.
--
-- Every table here is class=authn, for the same reason 00005/00006/00007's are:
-- the artifacts that decide who a caller is and how strongly they authenticated
-- are resolved on the proof-free surface, because the proof is what that answer
-- produces.
--
-- wenv:table webauthn_credentials class=authn chain=-
-- wenv:table webauthn_ceremonies class=authn chain=-

-- An opaque, random per-account WebAuthn user handle. NEVER a username, email or
-- account id (ADR: opaque random user handles): the handle travels to the
-- authenticator and back on every discoverable-login assertion, so a guessable
-- one would leak identity across relying parties. Nullable because an account
-- has one only once it enrols a passkey; UNIQUE so a discoverable login resolves
-- to exactly one account. Mirrors the sqlite dialect, which adds the column
-- plain and enforces uniqueness with a partial index.
ALTER TABLE accounts ADD COLUMN webauthn_user_handle BYTEA;

CREATE UNIQUE INDEX accounts_webauthn_user_handle
    ON accounts (webauthn_user_handle)
    WHERE webauthn_user_handle IS NOT NULL;

-- A registered WebAuthn credential (public key + metadata). The private key
-- never leaves the authenticator; wenv stores only the public key and the
-- ceremony-derived flags. credential_id is the authenticator-chosen id, UNIQUE
-- across the instance so an assertion resolves to one row. sign_count with
-- row_version is the clone-detection CAS (B9): a real regression on a
-- non-backup credential disables it (disabled_at), sweeps its sessions and
-- advances the generation. discoverable records residency from credProps at
-- enrolment; absent credProps means discoverable=0, fail-closed on the login
-- capability (B13). backup_eligible/backup_state gate the sign-count skip for
-- synced passkeys (B9). credential_epoch makes a restored credential inert.
CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    aaguid BYTEA NOT NULL,
    sign_count BIGINT NOT NULL,
    transports TEXT NOT NULL,
    discoverable BIGINT NOT NULL,
    backup_eligible BIGINT NOT NULL,
    backup_state BIGINT NOT NULL,
    label TEXT NOT NULL,
    credential_epoch BIGINT NOT NULL,
    row_version BIGINT NOT NULL,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

-- A WebAuthn ceremony: a random, single-use, expiring challenge bound to a
-- (session, account, purpose) and, for reauth, to the enumerated operation. The
-- go-webauthn SessionData JSON holds no secret (a challenge without the private
-- key proves nothing), so it is stored plain. account_id is NULL for a
-- discoverable login (the account is not known until the assertion resolves the
-- user handle); session_id is the acting session for the account-bound purposes.
-- credential_id is provenance, set at finish for the passkey that answered the
-- ceremony, plain TEXT (not a FK) so it survives a credential delete like the
-- OIDC provider_id provenance column: the clone sweep traces sessions through
-- their ceremony's credential_id. Rows are kept after consume (consumed_at) so a
-- minted session's ceremony_id keeps resolving to the credential that authored
-- it. operation_binding is the reauth enumerated unit, pinned server-side before
-- the ceremony (the challenge is single-use and the row owns the unit).
CREATE TABLE webauthn_ceremonies (
    id TEXT PRIMARY KEY,
    challenge_verifier BYTEA NOT NULL UNIQUE,
    session_data BYTEA NOT NULL,
    account_id TEXT REFERENCES accounts (id),
    session_id TEXT,
    purpose TEXT NOT NULL CHECK (purpose IN ('enrol', 'login', 'reauth', 'step-up', 'account-security')),
    operation_binding TEXT,
    environment_id TEXT,
    credential_id TEXT,
    credential_epoch BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    -- account-security binds both the acting session and the account so a proof
    -- cannot be produced without one (B21); reauth binds the enumerated unit.
    CHECK (purpose <> 'account-security' OR (account_id IS NOT NULL AND session_id IS NOT NULL)),
    CHECK (purpose <> 'reauth' OR operation_binding IS NOT NULL)
);
