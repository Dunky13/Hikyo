-- +goose Up
-- Definitions Git flow: the project's definitions source mode and the immutable
-- plan ledger behind `definitions plan` / `definitions apply` (#70,
-- source-of-truth ADR). Roll-forward only.
--
-- definitions_source governs the write path. In `git` the definition-write
-- chokepoint refuses every ordinary edit and only `definitions apply` may write
-- (ADR § Git-governed projects). The default is `db`, so an existing project's
-- behaviour is unchanged. Values and environment settings are unaffected in
-- both modes and carry no guard.
ALTER TABLE projects ADD COLUMN definitions_source TEXT NOT NULL DEFAULT 'db'
    CHECK (definitions_source IN ('db', 'git'));

-- hikyo:table definitions_plans class=project chain=org_id,project_id
-- An immutable, expiring plan. `plan` writes the row pinning the bundle's
-- canonical digest, the schema revision, and each environment's published
-- snapshot revision it was computed against; `apply` re-checks every pin and,
-- on success, stamps applied_at/by and the display-only provenance. The row is
-- kept after apply: it IS the last-applied provenance record the UI reads, so
-- there is no delete on the success path — only the hourly GC prunes expired,
-- unapplied plans. bundle holds the canonical bytes verbatim; env_revisions,
-- protected_envs and diff hold canonical JSON. provenance_* are length-bounded,
-- sanitized labels — never an input to any decision (ADR § Provenance).
-- `applied` is deliberately paired with applied_at/by: the explicit state
-- keeps the tenant predicate mechanically provable, while the CHECK prevents
-- the redundant representations from drifting.
CREATE TABLE definitions_plans (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    bundle TEXT NOT NULL,
    digest TEXT NOT NULL,
    base_schema_revision INTEGER NOT NULL,
    env_revisions TEXT NOT NULL,
    protected_envs TEXT NOT NULL,
    diff TEXT NOT NULL,
    additive INTEGER NOT NULL CHECK (additive IN (0, 1)),
    applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0, 1)),
    applied_at TEXT,
    applied_by TEXT,
    provenance_commit TEXT,
    provenance_ref TEXT,
    provenance_actor TEXT,
    CHECK (
        (applied = 0 AND applied_at IS NULL AND applied_by IS NULL)
        OR (applied = 1 AND applied_at IS NOT NULL AND applied_by IS NOT NULL)
    ),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    FOREIGN KEY (created_by) REFERENCES principals (id)
);

-- The open-plan quota and the prune both scan by (project, applied,
-- expires_at): an open plan is unapplied and unexpired.
CREATE INDEX definitions_plans_project_open
    ON definitions_plans (org_id, project_id, applied, expires_at);
CREATE INDEX definitions_plans_expiry
    ON definitions_plans (expires_at);
