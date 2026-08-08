-- +goose Up
-- Factors and the account-security surface (#54, human-auth ADR — TOTP,
-- recovery codes, reauthentication windows, browser sessions). Roll-forward
-- only: no Down section by policy.
--
-- Every table here is `class=authn`, for the same reason 00005's are: the
-- artifacts that decide who a caller is and how strongly they authenticated
-- are resolved on the proof-free surface, because the proof is what that
-- answer produces.
--
-- wenv:table totp_credentials class=authn chain=-
-- wenv:table totp_challenges class=authn chain=-
-- wenv:table recovery_codes class=authn chain=-
-- wenv:table reauth_windows class=authn chain=-

-- Browser sessions carry a synchronizer CSRF token; CLI sessions do not (a
-- cookie's attributes protect nothing on a non-browser client). The token is a
-- fast-hash verifier of a high-entropy artifact, like the session value
-- itself, returned once at mint and regenerated on rotation. The requirement
-- to present it is a property of "the value arrived in the cookie", decided in
-- the transport, never inferred from this row.
ALTER TABLE sessions ADD COLUMN csrf_verifier BYTEA;

-- TOTP seed, envelope-encrypted under the instance DEK (#14 placed MFA seeds
-- there). `confirmed_at` NULL means an enrolment that has proved nothing: an
-- unconfirmed seed satisfies no code check. The partial unique index below
-- keeps a pending enrolment from displacing a confirmed factor — a factor
-- removal disguised as a start.
--
-- `last_step` is the single-use guard per (account, time step): a code is
-- accepted only for a step strictly greater than the last consumed one within
-- the skew window, and the step is written in the same transaction. It is
-- floored at the row's creation step so re-enrolment with a kept seed cannot
-- rewind it and re-admit a spent code.
CREATE TABLE totp_credentials (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    seed BYTEA NOT NULL,
    dek_version BIGINT NOT NULL,
    credential_epoch BIGINT NOT NULL,
    row_version BIGINT NOT NULL,
    last_step BIGINT NOT NULL,
    created_step BIGINT NOT NULL,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

-- At most one confirmed TOTP factor per account; unconfirmed enrolments do not
-- collide, so a start never destroys the standing factor.
CREATE UNIQUE INDEX totp_confirmed_unique
    ON totp_credentials (account_id)
    WHERE confirmed_at IS NOT NULL;

-- A purpose-bound single-use challenge for a TOTP code presentation. A code is
-- six digits with no server-issued challenge of its own, so the binding the
-- account-security and reauth rules require — "this code authorizes THIS
-- operation and nothing else" — lives here: the server commits to the purpose
-- (and, for reauth, the enumerated unit) before the user is asked for a code.
CREATE TABLE totp_challenges (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    session_id TEXT,
    purpose TEXT NOT NULL CHECK (purpose IN ('step-up', 'reauth', 'account-security')),
    operation_binding TEXT,
    environment_id TEXT,
    credential_epoch BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    -- reauth binds the enumerated unit; account-security binds the acting
    -- session so a proof cannot be produced without one.
    CHECK (purpose <> 'reauth' OR operation_binding IS NOT NULL),
    CHECK (purpose <> 'account-security' OR session_id IS NOT NULL)
);

-- Recovery codes: single-use, >=128-bit each, hashed, the batch as a whole
-- envelope-encrypted. Regeneration replaces the batch atomically (CAS on
-- row_version), invalidating the previous one. A batch at a superseded epoch
-- is inert like any other restored artifact.
CREATE TABLE recovery_codes (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id),
    batch BYTEA NOT NULL,
    dek_version BIGINT NOT NULL,
    credential_epoch BIGINT NOT NULL,
    row_version BIGINT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL
);

-- A reauthentication window over one environment, opened by a possession-factor
-- ceremony and consulted at the disclosure chokepoint. Two clocks: the sliding
-- window (refreshed per disclosure) and the hard cap (measured from the
-- ceremony, never extended). `single_decision` marks a window that a 0-window
-- WebAuthn ceremony opened for exactly one enumerated unit — `consumed_at`
-- claims it, so it cannot authorize a second decision.
--
-- Keyed by session, never by principal: a dead session's window must never
-- answer for a fresh one, which is what "never inherits prior windows" means.
CREATE TABLE reauth_windows (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL,
    ceremony_id TEXT NOT NULL,
    factor_class TEXT NOT NULL CHECK (factor_class IN ('webauthn', 'totp', 'oidc')),
    single_decision BIGINT NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    window_expires_at TIMESTAMPTZ NOT NULL,
    hard_expires_at TIMESTAMPTZ NOT NULL,
    credential_epoch BIGINT NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (session_id, environment_id)
);

-- Admit recovery-code consumption as a fourth, differently-shaped issuer, and
-- record which credential kind an authority may establish. The recovery issuer
-- may only ever establish a password: a stolen recovery sheet must not be able
-- to enrol a possession factor and thereby manufacture multi-factor assurance.
-- Postgres can alter the CHECK in place, so no table rebuild is needed.
ALTER TABLE credential_authorities
    ADD COLUMN established_credential_kind TEXT NOT NULL DEFAULT 'password'
    CHECK (established_credential_kind IN ('password'));

ALTER TABLE credential_authorities DROP CONSTRAINT credential_authorities_issued_by_check;

ALTER TABLE credential_authorities
    ADD CONSTRAINT credential_authorities_issued_by_check
    CHECK (issued_by IN ('bootstrap', 'credential-reset', 'break-glass', 'recovery'));

ALTER TABLE credential_authorities
    ADD CONSTRAINT credential_authorities_recovery_password_only
    CHECK (issued_by <> 'recovery' OR established_credential_kind = 'password');
