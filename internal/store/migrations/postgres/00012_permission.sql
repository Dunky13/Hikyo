-- +goose Up
-- Permission model, full (#55, permission-model ADR). Structurally identical
-- to the sqlite dialect; see that file for the reasoning behind every column.
-- Roll-forward only: no Down section.

-- hikyo:table grant_origins class=authn chain=-

CREATE TABLE grant_origins (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES grants (id),
    kind TEXT NOT NULL CHECK (
        kind IN ('manual', 'break-glass', 'scim', 'structural', 'lockout-retention')
    ),
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (grant_id, kind, subject)
);

CREATE INDEX grant_origins_grant ON grant_origins (grant_id);

INSERT INTO grant_origins (id, grant_id, kind, subject, created_at)
SELECT 'gor_' || g.id, g.id, 'manual', g.principal_id, g.created_at FROM grants AS g;

ALTER TABLE environments ADD COLUMN protected BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE environments ADD COLUMN reauth_window_seconds BIGINT;

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
