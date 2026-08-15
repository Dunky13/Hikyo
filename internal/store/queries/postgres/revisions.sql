-- Revisions, drafts and publishing (#51). Tenant-scoped statements: the
-- reserved chain_* parameters are bound by the store's binding layer from
-- proof fields only - never from caller arguments; the SQL predicate analyzer
-- enforces the conjunct shape.
--
-- `environment_id` is an ordinary column on all four tables (see the
-- migration), and every environment-addressed statement below binds it from
-- the proof's resolved chain - spelled `chain_env_id`, the same reserved name
-- values.sql uses. The project-scoped statements are the ones that must span
-- environments: publish reads the publisher's whole working state across the
-- project before it knows which environments it touches, the matrix signals
-- are a project-wide question, and a key delete cascades across every
-- environment at once.

-- name: InsertPendingChange :exec
INSERT INTO pending_changes (
    id, org_id, project_id, environment_id, key_id, owner_id,
    operation, ciphertext, staged_from_revision, staged_from_entry, created_at, source, secret, material_secret
) VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(chain_project_id),
    sqlc.arg(chain_env_id), sqlc.arg(key_id), sqlc.arg(owner_id),
    sqlc.arg(operation), sqlc.narg(ciphertext), sqlc.arg(staged_from_revision),
    sqlc.arg(staged_from_entry), sqlc.arg(created_at), sqlc.arg(source), sqlc.arg(secret), sqlc.arg(material_secret)
);

-- DeletePendingChangeForCell collects the superseded version. Editing a cell
-- mints a new version id rather than mutating the old row, and the old row is
-- removed in the same transaction: only the latest version per (owner, key,
-- environment) is publishable, so keeping the predecessor would store draft
-- material nothing may ever publish.
-- name: DeletePendingChangeForCell :execrows
DELETE FROM pending_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id) AND key_id = sqlc.arg(key_id)
  AND owner_id = sqlc.arg(owner_id);

-- name: DeletePendingChangeByID :execrows
DELETE FROM pending_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id) AND id = sqlc.arg(id);

-- name: DeletePendingChangesForEnvironment :execrows
DELETE FROM pending_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id);

-- DeletePendingChangesForKey is the key-delete cascade: deleting a key
-- invalidates every pending change referencing it, so a publish naming one of
-- those versions is refused loudly instead of resurrecting a key the schema no
-- longer declares.
-- name: DeletePendingChangesForKey :execrows
DELETE FROM pending_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND key_id = sqlc.arg(key_id);

-- ListPendingChangesForOwner is the publish path's read: a publish carries
-- ONLY the publisher's own pending changes, so the query that returns draft
-- material is keyed on the owner and there is no statement that hands one
-- principal another's ciphertext.
-- name: ListPendingChangesForOwner :many
SELECT id, org_id, project_id, environment_id, key_id, owner_id,
       operation, ciphertext, staged_from_revision, staged_from_entry, created_at, source, secret, material_secret
FROM pending_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND owner_id = sqlc.arg(owner_id)
ORDER BY environment_id, key_id;

-- ListPendingChangesForOwnerInEnvironment is the preview read. Owner and
-- environment are both predicates in SQL, so the preview cannot hand one
-- principal another's ciphertext or material from another environment.
-- name: ListPendingChangesForOwnerInEnvironment :many
SELECT id, org_id, project_id, environment_id, key_id, owner_id,
       operation, ciphertext, staged_from_revision, staged_from_entry, created_at, source, secret, material_secret
FROM pending_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id) AND owner_id = sqlc.arg(owner_id)
ORDER BY key_id;

-- ListPendingMarkers is the matrix signal's read and the group-closure
-- collision check's read. It returns NO ciphertext: what another principal's
-- draft may disclose is write-presence and nothing else, and the cheapest way
-- to hold that rule is a statement that cannot carry the material.
-- name: ListPendingMarkers :many
SELECT id, environment_id, key_id, owner_id, operation
FROM pending_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
ORDER BY environment_id, key_id, owner_id;

-- name: InsertSnapshot :exec
INSERT INTO snapshots (
    id, org_id, project_id, environment_id, revision,
    schema_revision, published_by, published_at
) VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(chain_project_id),
    sqlc.arg(chain_env_id), sqlc.arg(revision), sqlc.arg(schema_revision),
    sqlc.arg(published_by), sqlc.arg(published_at)
);

-- GetLatestSnapshot is the delivery-shaped read: a workload fetch defaults to
-- the latest published snapshot for its (project, environment).
-- name: GetLatestSnapshot :one
SELECT id, org_id, project_id, environment_id, revision, schema_revision,
       published_by, published_at, payload_present, collected_at, collected_policy
FROM snapshots
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id)
ORDER BY revision DESC
LIMIT 1;

-- name: GetSnapshotByRevision :one
SELECT id, org_id, project_id, environment_id, revision, schema_revision,
       published_by, published_at, payload_present, collected_at, collected_policy
FROM snapshots
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id) AND revision = sqlc.arg(revision);

-- name: ListSnapshots :many
SELECT id, org_id, project_id, environment_id, revision, schema_revision,
       published_by, published_at, payload_present, collected_at, collected_policy
FROM snapshots
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id)
ORDER BY revision DESC;

-- name: DeleteSnapshotsForEnvironment :execrows
DELETE FROM snapshots
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id);

-- name: InsertSnapshotEntry :exec
INSERT INTO snapshot_entries (
    id, org_id, project_id, environment_id, snapshot_id,
    key_id, key_name, classification, ciphertext, value_entry_id
) VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(chain_project_id),
    sqlc.arg(chain_env_id), sqlc.arg(snapshot_id), sqlc.arg(key_id),
    sqlc.arg(key_name), sqlc.arg(classification), sqlc.arg(ciphertext),
    sqlc.arg(value_entry_id)
);

-- name: ListSnapshotEntries :many
SELECT id, org_id, project_id, environment_id, snapshot_id,
       key_id, key_name, classification, ciphertext, value_entry_id
FROM snapshot_entries
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id) AND snapshot_id = sqlc.arg(snapshot_id)
ORDER BY key_name;

-- name: RecordSecretValueOccurrence :exec
INSERT INTO secret_value_occurrences (
    value_entry_id, org_id, project_id, environment_id
) VALUES (
    sqlc.arg(value_entry_id), sqlc.arg(chain_org_id),
    sqlc.arg(chain_project_id), sqlc.arg(chain_env_id)
);

-- name: ListSecretValueOccurrenceIDs :many
SELECT value_entry_id
FROM secret_value_occurrences
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id)
ORDER BY value_entry_id;

-- name: DeleteSecretValueOccurrencesForEnvironment :execrows
DELETE FROM secret_value_occurrences
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id);
-- name: DeleteSnapshotEntriesForEnvironment :execrows
DELETE FROM snapshot_entries
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id);

-- name: InsertRevisionKeyChange :exec
INSERT INTO revision_key_changes (
    org_id, project_id, environment_id, revision, key_id, key_name, change
) VALUES (
    sqlc.arg(chain_org_id), sqlc.arg(chain_project_id), sqlc.arg(chain_env_id),
    sqlc.arg(revision), sqlc.arg(key_id), sqlc.arg(key_name), sqlc.arg(change)
);

-- name: ListRevisionKeyChanges :many
SELECT org_id, project_id, environment_id, revision, key_id, key_name, change
FROM revision_key_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id) AND revision = sqlc.arg(revision)
ORDER BY key_name;

-- name: GetRevisionPinForWorkload :one
SELECT id, org_id, project_id, environment_id, workload_principal_id,
       snapshot_id, revision, authority_principal_id, expires_at, created_at,
       authorized_at, history_authorized, schema_override
FROM revision_pins
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id)
  AND workload_principal_id = sqlc.arg(workload_principal_id);

-- name: ListRevisionPins :many
SELECT id, org_id, project_id, environment_id, workload_principal_id,
       snapshot_id, revision, authority_principal_id, expires_at, created_at,
       authorized_at, history_authorized, schema_override
FROM revision_pins
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id)
ORDER BY workload_principal_id;

-- name: CountRevisionPinsForProject :one
SELECT COUNT(*) FROM revision_pins
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id);

-- name: InsertRevisionPin :exec
INSERT INTO revision_pins (
    id, org_id, project_id, environment_id, workload_principal_id,
    snapshot_id, revision, authority_principal_id, expires_at, created_at,
    authorized_at, history_authorized, schema_override
) VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(chain_project_id),
    sqlc.arg(chain_env_id), sqlc.arg(workload_principal_id), sqlc.arg(snapshot_id),
    sqlc.arg(revision), sqlc.arg(authority_principal_id), sqlc.arg(expires_at),
    sqlc.arg(created_at), sqlc.arg(authorized_at), sqlc.arg(history_authorized),
    sqlc.arg(schema_override)
);

-- name: DeleteRevisionPin :execrows
DELETE FROM revision_pins
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id)
  AND workload_principal_id = sqlc.arg(workload_principal_id);

-- name: DeleteRevisionPinsForEnvironment :execrows
DELETE FROM revision_pins
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id);

-- name: DeleteRevisionKeyChangesForEnvironment :execrows
DELETE FROM revision_key_changes
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
  AND environment_id = sqlc.arg(chain_env_id);
