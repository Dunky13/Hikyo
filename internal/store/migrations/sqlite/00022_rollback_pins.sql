-- +goose Up
-- Rollback and durable revision pins (#52). Roll-forward only.
--
-- hikyo:table revision_pins class=environment chain=org_id,project_id

-- Payload presence is separate from lineage. GC (#53) clears payload rows and
-- flips this bit in one transaction; restore and pinned delivery then refuse
-- the named revision instead of mistaking an empty, valid snapshot for one
-- whose payload was collected.
ALTER TABLE snapshots ADD COLUMN payload_present INTEGER NOT NULL DEFAULT 1
    CHECK (payload_present IN (0, 1));

CREATE UNIQUE INDEX snapshots_chain_id
    ON snapshots (org_id, project_id, environment_id, id);

-- A publish containing any restore-authored draft records trigger=restore.
-- Existing rows and ordinary value staging remain source=values.
ALTER TABLE pending_changes ADD COLUMN source TEXT NOT NULL DEFAULT 'values'
    CHECK (source IN ('values', 'restore'));

-- A pin is the durable retention reference GC can observe. Expired rows remain
-- here deliberately: expiry ends retention protection but never changes
-- delivery; release is the act that removes routing.
CREATE TABLE revision_pins (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    workload_principal_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    authority_principal_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    authorized_at TEXT NOT NULL,
    history_authorized INTEGER NOT NULL CHECK (history_authorized IN (0, 1)),
    schema_override INTEGER NOT NULL CHECK (schema_override IN (0, 1)),
    UNIQUE (org_id, project_id, environment_id, workload_principal_id),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, environment_id, snapshot_id)
        REFERENCES snapshots (org_id, project_id, environment_id, id),
    FOREIGN KEY (workload_principal_id) REFERENCES principals (id) ON DELETE CASCADE,
    FOREIGN KEY (authority_principal_id) REFERENCES principals (id)
);

CREATE INDEX revision_pins_project ON revision_pins (org_id, project_id);
CREATE INDEX revision_pins_snapshot ON revision_pins (snapshot_id, expires_at);
