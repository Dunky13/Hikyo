-- +goose Up
-- Human authentication storage (#47, human-auth ADR — bootstrap and local
-- floor slice). Roll-forward only: no Down section by policy.
--
-- Every table here is `class=authn`: the SQL predicate analyzer refuses any
-- unannotated query against them, so the only door is the enumerated
-- resolution surface (internal/store/authn). That is deliberate. Resolving
-- who a caller is cannot itself run under a proof — the proof is what the
-- answer produces — which is the same bootstrap carve-out chain resolution
-- and grant lookup already live in.
--
-- hikyo:table auth_instance_state class=authn chain=-
-- hikyo:table accounts class=authn chain=-
-- hikyo:table password_credentials class=authn chain=-
-- hikyo:table sessions class=authn chain=-
-- hikyo:table credential_authorities class=authn chain=-

-- The instance credential epoch. Restore increments it, and every human
-- authentication artifact records the epoch it was created under; an artifact
-- from an earlier epoch is inert — it cannot authenticate, cannot be
-- reauthenticated against, and cannot be reset with a pre-restore token.
-- That is the mechanism behind "restored verifiers are never trusted as-is".
CREATE TABLE auth_instance_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    credential_epoch INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO auth_instance_state (id, credential_epoch, updated_at)
VALUES (1, 1, '1970-01-01T00:00:00.000000Z');

-- Principals gain the session generation counter. It lives on the principal,
-- not the account, because advancing it must invalidate every session of that
-- principal atomically and without reaching the client — which token rotation
-- structurally cannot do, since an idle or stolen session is never told.
-- Machine principals carry it for the same reason (restore, revocation).
ALTER TABLE principals ADD COLUMN session_generation INTEGER NOT NULL DEFAULT 1;

-- A human account. Accounts are created by invitation or by the bootstrap
-- path — there is no self-registration, ever, and none is representable here.
-- `username` is a login handle, never an email and never a linking key.
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL UNIQUE REFERENCES principals (id),
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Argon2id verifiers, envelope-encrypted under the instance DEK. The hash
-- stays a hash — a root-key holder still cannot reverse it — and the
-- encryption is an outer layer that denies an offline guessing attack to an
-- attacker holding the database without the root key.
--
-- `row_version` is load-bearing, not hygiene: `reencrypt` is resumable and
-- lock-free, so a read-decrypt-reseal-write racing a password reset would
-- write the stale verifier back under the new DEK version and silently
-- resurrect a superseded password. Every writer compare-and-swaps on it.
CREATE TABLE password_credentials (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id),
    verifier BLOB NOT NULL,
    kdf_memory_kib INTEGER NOT NULL,
    kdf_time INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    dek_version INTEGER NOT NULL,
    credential_epoch INTEGER NOT NULL,
    row_version INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

-- Opaque server-side sessions. The stored value is an unsalted SHA-256
-- verifier: fast hashing is safe here precisely because the artifact carries
-- >=256 bits of entropy, and it is what makes authentication a single indexed
-- read. Revocation is a delete in the request's own transaction, which is the
-- literal reading of "no cross-request authorization cache".
--
-- The assurance record is how THIS session authenticated — the thing the
-- chokepoint consults — not what the account could have presented.
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals (id),
    verifier BLOB NOT NULL UNIQUE,
    artifact TEXT NOT NULL CHECK (artifact IN ('cli', 'browser')),
    session_generation INTEGER NOT NULL,
    credential_epoch INTEGER NOT NULL,
    auth_method TEXT NOT NULL,
    factors TEXT NOT NULL,
    authenticated_at TEXT NOT NULL,
    ceremony_id TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL
);

CREATE INDEX sessions_principal_idx ON sessions (principal_id);

-- A credential-establishment authority: the named — and only — exception to
-- "a new credential may never authorize its own enrolment", for the three
-- cases that have no prior credential by construction (a freshly initialized
-- instance, an administrative reset, an identity re-established after an
-- epoch bump).
--
-- Target-bound, purpose-bound, single-use, expiring, >=128-bit, hashed at
-- rest. Consuming it establishes exactly one initial credential and nothing
-- more: no session, no assurance, no reauthentication window.
CREATE TABLE credential_authorities (
    id TEXT PRIMARY KEY,
    verifier BLOB NOT NULL UNIQUE,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    purpose TEXT NOT NULL CHECK (purpose IN ('establish-credential')),
    issued_by TEXT NOT NULL CHECK (issued_by IN ('bootstrap', 'credential-reset', 'break-glass')),
    credential_epoch INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
