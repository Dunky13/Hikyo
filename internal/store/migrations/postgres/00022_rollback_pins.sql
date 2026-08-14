-- +goose Up
-- Rollback and durable revision pins (#52). Roll-forward only.
-- Structurally identical to the sqlite migration; only scalar types differ.
--
-- hikyo:table revision_pins class=environment chain=org_id,project_id

ALTER TABLE snapshots ADD COLUMN payload_present BOOLEAN NOT NULL DEFAULT TRUE;

CREATE UNIQUE INDEX snapshots_chain_id
    ON snapshots (org_id, project_id, environment_id, id);

ALTER TABLE pending_changes ADD COLUMN source TEXT NOT NULL DEFAULT 'values'
    CHECK (source IN ('values', 'restore'));

CREATE TABLE revision_pins (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    workload_principal_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    authority_principal_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    authorized_at TIMESTAMPTZ NOT NULL,
    history_authorized BOOLEAN NOT NULL,
    schema_override BOOLEAN NOT NULL,
    UNIQUE (org_id, project_id, environment_id, workload_principal_id),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, environment_id, snapshot_id)
        REFERENCES snapshots (org_id, project_id, environment_id, id),
    FOREIGN KEY (workload_principal_id) REFERENCES principals (id) ON DELETE CASCADE,
    FOREIGN KEY (authority_principal_id) REFERENCES principals (id)
);

CREATE INDEX revision_pins_project ON revision_pins (org_id, project_id);
CREATE INDEX revision_pins_snapshot ON revision_pins (snapshot_id, expires_at);
