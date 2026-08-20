-- +goose Up
-- Definitions Git flow (#70, source-of-truth ADR). Roll-forward only.
-- Structurally identical to the sqlite migration; only scalar types differ.
ALTER TABLE projects ADD COLUMN definitions_source TEXT NOT NULL DEFAULT 'db'
    CHECK (definitions_source IN ('db', 'git'));

-- hikyo:table definitions_plans class=project chain=org_id,project_id
-- `applied` is deliberately paired with applied_at/by: the explicit state
-- keeps the tenant predicate mechanically provable, while the CHECK prevents
-- the redundant representations from drifting.
CREATE TABLE definitions_plans (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    bundle TEXT NOT NULL,
    digest TEXT NOT NULL,
    base_schema_revision BIGINT NOT NULL,
    env_revisions TEXT NOT NULL,
    protected_envs TEXT NOT NULL,
    diff TEXT NOT NULL,
    additive BOOLEAN NOT NULL,
    applied BOOLEAN NOT NULL DEFAULT FALSE,
    applied_at TIMESTAMPTZ,
    applied_by TEXT,
    provenance_commit TEXT,
    provenance_ref TEXT,
    provenance_actor TEXT,
    CHECK (
        (NOT applied AND applied_at IS NULL AND applied_by IS NULL)
        OR (applied AND applied_at IS NOT NULL AND applied_by IS NOT NULL)
    ),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    FOREIGN KEY (created_by) REFERENCES principals (id)
);

CREATE INDEX definitions_plans_project_open
    ON definitions_plans (org_id, project_id, applied, expires_at);
CREATE INDEX definitions_plans_expiry
    ON definitions_plans (expires_at);
