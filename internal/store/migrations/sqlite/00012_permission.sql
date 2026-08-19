-- +goose Up
-- Permission model, full (#55, permission-model ADR). Three additions:
-- grant origins, the per-environment protection/window settings the
-- `project-settings` capability governs, and the machine principal class the
-- normative machine allowlists key on. Roll-forward only: no Down section.

-- hikyo:table grant_origins class=authn chain=-

-- Grant origins (scim-provisioning amendment (a)): a grant row exists while
-- at least one origin holds it, and is revoked — with the locked
-- session-generation advance — when its LAST origin is released. Evaluation
-- never consults this table: authority is the bare (principal, capability,
-- scope) triple, and authorize() reads `grants` alone.
--
-- `subject` is the origin's holder identity, discriminated by `kind`:
--   manual            -> the granting principal's id
--   break-glass       -> the literal 'local-host-authority' (break-glass has
--                        no granting principal: it is the one authorization
--                        path not evaluated against a grant)
--   scim / structural -> the binding id (#73 writes these; refused here)
--   lockout-retention -> the cause (#73)
-- It is NOT NULL so UNIQUE behaves identically on both engines — the same
-- NULL-distinctness divergence that kept `grants` free of a triple UNIQUE.
--
-- The FK is RESTRICT (no ON DELETE CASCADE) on purpose: deleting a grant row
-- while an origin still holds it is exactly the invariant violation the ADR
-- forbids, so the database refuses it rather than tidying it away.
CREATE TABLE grant_origins (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES grants (id),
    kind TEXT NOT NULL CHECK (
        kind IN ('manual', 'break-glass', 'scim', 'structural', 'lockout-retention')
    ),
    subject TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (grant_id, kind, subject)
);

CREATE INDEX grant_origins_grant ON grant_origins (grant_id);

-- Backfill: every pre-existing grant row carries exactly manual(granted_by),
-- which is the amendment's own words. The rows that can exist here were
-- written by the first-administrator bootstrap, which has no granting
-- principal, so the fill is the self-grant — visible as such on the
-- membership line rather than invented as somebody else's act. Unlike
-- 00006's tables this is NOT a "no real rows exist" premise: a bootstrapped
-- instance legitimately holds grants, and an unfilled row would be a grant
-- no origin holds.
INSERT INTO grant_origins (id, grant_id, kind, subject, created_at)
SELECT 'gor_' || g.id, g.id, 'manual', g.principal_id, g.created_at FROM grants AS g;

-- Per-environment protection and reauthentication window (permission-model ADR
-- - The reveal guard). Both sit under `project-settings`, which is split out
-- of `definitions-edit` precisely because these restrain the definitions
-- editor.
--
-- `protected` carries a DEFAULT, unlike 00009's `display_order`, and the
-- difference is deliberate: an unprotected environment is the real initial
-- state of every environment, so a writer that omits the column gets the
-- truth, not a silent claim. `reauth_window_seconds` is NULLABLE and NULL
-- means "inherit the instance default" — a non-null copy of the instance
-- default would freeze that default at creation time, which is a lie about
-- what the environment was configured with.
ALTER TABLE environments ADD COLUMN protected INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1));
ALTER TABLE environments ADD COLUMN reauth_window_seconds INTEGER;

-- The machine principal class the permission-model ADR's normative allowlists key
-- on (workload / automation / provisioning-connection / instance-connection).
-- NULL for humans. It is NOT constrained by a CHECK because sqlite cannot add
-- one to a table this many rows reference; the closed set is enforced in Go
-- at the grant writer, fail-closed (an unclassified machine principal holds
-- nothing the allowlists admit).
ALTER TABLE principals ADD COLUMN class TEXT;

-- NO BACKFILL, deliberately. A machine principal that predates this column
-- carries no evidence of which class it belongs to: the credential binding
-- that would say so is the machine-identities ticket's (#17) and does not
-- exist yet. Guessing `automation` would hand a pre-existing WORKLOAD
-- credential the edit/publish/definitions-edit set the automation allowlist
-- admits, which is a privilege escalation performed by a migration.
--
-- Unclassified therefore stays NULL and fails closed: every allowlist path
-- refuses a machine principal whose class is not in the closed set, so such a
-- principal can hold no NEW grant until an operator classifies it explicitly.
-- Its existing grants keep evaluating — authorization reads the grant table
-- and never the class — so nothing in flight breaks; only widening is blocked,
-- which is the direction that needs the evidence.
