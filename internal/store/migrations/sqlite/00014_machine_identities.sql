-- +goose Up
-- Machine identities: service accounts and their credentials (#61,
-- machine-identities ADR). Roll-forward only: no Down section by policy.
--
-- The ADR's principal model in one sentence: a service account is a
-- principal in the grant table, and a credential is an AUTHENTICATOR for it.
-- Nothing here carries scope. Authority is the union of the grants on the
-- principal and nothing else — there is no per-credential scope column, and
-- adding one later would be the second permission language #15 forbids.
--
-- Both tables are `class=authn`, for the reason 00005 states: resolving who
-- a caller is cannot itself run under a proof, because the proof is what the
-- answer produces. A machine credential resolves at the SAME chokepoint as
-- authorize(), so its row — and the service-account row naming its principal
-- — sit on the enumerated resolution surface (internal/store/authn) rather
-- than behind the proof-gated repos. Tenant confinement is not weakened by
-- that: the service-account row carries its own (org_id, project_id) under a
-- composite ancestry FK, and the grant API's machine-project rule (#55,
-- checkMachineProject) confines its grants to that project's subtree.
--
-- hikyo:table service_accounts class=authn chain=-
-- hikyo:table machine_credentials class=authn chain=-
-- hikyo:table credential_policy class=authn chain=-

-- A service account. Project-owned, administered under
-- `manage-identities(project)`.
--
-- `kind` is declared at creation and is IMMUTABLE — one of `workload` or
-- `automation`. The CHECK is the floor; there is deliberately no UPDATE
-- statement anywhere that names the column, because in-place widening of a
-- credential class that N workloads already hold is exactly what the ADR
-- refuses ("a project that guessed wrong creates a second service account").
--
-- `principal_id` is UNIQUE: one service account is one principal, so grant
-- attribution has a stable subject across every rotation. The composite
-- ancestry FK is the same shape environments and folders use — a service
-- account whose chain crosses tenants is unrepresentable rather than merely
-- unwritten.
--
-- `created_by` is the principal that minted it. It is NOT NULL because every
-- creation path runs under `manage-identities(project)` and therefore has an
-- acting principal to name; there is no system-created service account.
CREATE TABLE service_accounts (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL UNIQUE REFERENCES principals (id),
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('workload', 'automation')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, name)
);

CREATE INDEX service_accounts_project ON service_accounts (org_id, project_id);

-- A credential authenticating one service account.
--
-- `kind` is the CREDENTIAL-KIND DISCRIMINATOR the ADR requires ("the API and
-- schema MUST NOT assume the bearer token is the only kind"). v1 writes only
-- `hikyo-token`; `oidc-federation` is out of scope for this ticket and is
-- deliberately NOT in the CHECK — an enumeration is widened by the migration
-- that ships the kind, so an unimplemented kind cannot be written by an
-- API that does not yet validate it.
--
-- `verifier` is an unsalted SHA-256 of the whole presented value under a
-- unique index — the threat model's rule for >=256-bit artifacts, and what
-- makes authentication a single indexed read. It is NULLABLE because a
-- future credential kind may hold no bearer value at all (a federation
-- binding holds nothing at rest); the CHECK below ties presence to the kind
-- so a bearer credential can never be written without one. sqlite treats
-- NULLs as distinct under UNIQUE, which is the wanted behaviour here and the
-- one place it agrees with postgres' default.
--
-- `lifetime` and `expires_at` together are the ADR's typed lifetime:
-- `indefinite` is a VALUE, not a large number, so it is unreachable by
-- raising any ceiling. The CHECK makes the pairing total — a finite
-- credential has an instant, an indefinite one has none — which is what
-- keeps a clamp from being able to manufacture the indefinite case.
--
-- `credential_epoch` is #16's mechanism carried onto machines: a restore
-- bumps the epoch and every machine credential becomes inert. Re-activation
-- of a restored bearer verifier is never offered (§ Restore); the column is
-- what makes that a mechanism rather than an assertion.
--
-- `revoked_at` is set in place rather than the row deleted, so the audit
-- trail's credential id keeps resolving to a describable row after an
-- incident. Revocation bites at the NEXT FETCH — the predicate is read in
-- the authenticating transaction, uncached.
CREATE TABLE machine_credentials (
    id TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id),
    kind TEXT NOT NULL CHECK (kind IN ('hikyo-token')),
    verifier BLOB UNIQUE,
    prefix_hint TEXT NOT NULL,
    lifetime TEXT NOT NULL CHECK (lifetime IN ('finite', 'indefinite')),
    expires_at TEXT,
    credential_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    CHECK (
        (lifetime = 'finite' AND expires_at IS NOT NULL)
        OR (lifetime = 'indefinite' AND expires_at IS NULL)
    ),
    CHECK (kind <> 'hikyo-token' OR verifier IS NOT NULL)
);

CREATE INDEX machine_credentials_account ON machine_credentials (service_account_id);

-- The instance credential policy (ADR § Lifetime), under `instance-config`.
-- One row, like auth_instance_state, for the same reason: there is exactly
-- one instance and a table that could hold two would need a rule about which
-- one wins.
--
-- The three values are the operations spec's, seeded with the defaults this
-- ticket chose and recorded for ratification:
--
--   max_finite_lifetime_seconds  7776000  (90 days) — the ceiling clamping
--                                every project's finite credentials.
--   allow_indefinite             0        — the ADR's separate opt-in,
--                                DEFAULT OFF. Raising the ceiling can never
--                                manufacture it, which is why it is its own
--                                column and not a sentinel in the other one.
--   max_live_credentials         5        — the concurrent-credential cap
--                                per service account, sized so overlap-based
--                                rotation has room and a mint loop does not.
--
-- `updated_at` and `updated_by` are NULL while the row is still the shipped
-- default. A non-null "changed by nobody at the epoch" would be a claim
-- about an act that never happened.
CREATE TABLE credential_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_finite_lifetime_seconds INTEGER NOT NULL CHECK (max_finite_lifetime_seconds > 0),
    allow_indefinite INTEGER NOT NULL CHECK (allow_indefinite IN (0, 1)),
    max_live_credentials INTEGER NOT NULL CHECK (max_live_credentials > 0),
    updated_at TEXT,
    updated_by TEXT
);

INSERT INTO credential_policy (
    id, max_finite_lifetime_seconds, allow_indefinite, max_live_credentials, updated_at, updated_by
) VALUES (1, 7776000, 0, 5, NULL, NULL);
