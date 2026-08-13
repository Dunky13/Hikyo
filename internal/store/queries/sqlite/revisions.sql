-- Revisions, drafts and publishing (#51). Tenant-scoped statements: the
-- reserved chain parameters are bound by the store's binding layer from proof
-- fields only - never from caller arguments; the SQL predicate analyzer
-- enforces the conjunct shape.
--
-- `environment_id` is an ordinary column on all four tables (see the
-- migration), and every environment-addressed statement below binds it from
-- the proof's resolved chain. The project-scoped statements are the ones that
-- must span environments: publish reads the publisher's whole working state
-- across the project before it knows which environments it touches, the matrix
-- signals are a project-wide question, and a key delete cascades across every
-- environment at once.

-- name: InsertPendingChange :exec
INSERT INTO pending_changes (
    id, org_id, project_id, environment_id, key_id, owner_id,
    operation, ciphertext, staged_from_revision, staged_from_entry, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- DeletePendingChangeForCell collects the superseded version. Editing a cell
-- mints a new version id rather than mutating the old row, and the old row is
-- removed in the same transaction: only the latest version per (owner, key,
-- environment) is publishable, so keeping the predecessor would store draft
-- material nothing may ever publish.
-- name: DeletePendingChangeForCell :execrows
DELETE FROM pending_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND key_id = ? AND owner_id = ?;

-- name: DeletePendingChangeByID :execrows
DELETE FROM pending_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND id = ?;

-- name: DeletePendingChangesForEnvironment :execrows
DELETE FROM pending_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ?;

-- DeletePendingChangesForKey is the key-delete cascade: deleting a key
-- invalidates every pending change referencing it, so a publish naming one of
-- those versions is refused loudly instead of resurrecting a key the schema no
-- longer declares.
-- name: DeletePendingChangesForKey :execrows
DELETE FROM pending_changes
WHERE org_id = ? AND project_id = ? AND key_id = ?;

-- ListPendingChangesForOwner is the publish path's read: a publish carries
-- ONLY the publisher's own pending changes, so the query that returns draft
-- material is keyed on the owner and there is no statement that hands one
-- principal another's ciphertext.
-- name: ListPendingChangesForOwner :many
SELECT id, org_id, project_id, environment_id, key_id, owner_id,
       operation, ciphertext, staged_from_revision, staged_from_entry, created_at
FROM pending_changes
WHERE org_id = ? AND project_id = ? AND owner_id = ?
ORDER BY environment_id, key_id;

-- ListPendingMarkers is the matrix signal's read and the group-closure
-- collision check's read. It returns NO ciphertext: what another principal's
-- draft may disclose is write-presence and nothing else, and the cheapest way
-- to hold that rule is a statement that cannot carry the material.
-- name: ListPendingMarkers :many
SELECT id, environment_id, key_id, owner_id, operation
FROM pending_changes
WHERE org_id = ? AND project_id = ?
ORDER BY environment_id, key_id, owner_id;

-- name: InsertSnapshot :exec
INSERT INTO snapshots (
    id, org_id, project_id, environment_id, revision,
    schema_revision, published_by, published_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- GetLatestSnapshot is the delivery-shaped read: a workload fetch defaults to
-- the latest published snapshot for its (project, environment).
-- name: GetLatestSnapshot :one
SELECT id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at
FROM snapshots
WHERE org_id = ? AND project_id = ? AND environment_id = ?
ORDER BY revision DESC
LIMIT 1;

-- name: GetSnapshotByRevision :one
SELECT id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at
FROM snapshots
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND revision = ?;

-- name: ListSnapshots :many
SELECT id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at
FROM snapshots
WHERE org_id = ? AND project_id = ? AND environment_id = ?
ORDER BY revision DESC;

-- name: DeleteSnapshotsForEnvironment :execrows
DELETE FROM snapshots
WHERE org_id = ? AND project_id = ? AND environment_id = ?;

-- name: InsertSnapshotEntry :exec
INSERT INTO snapshot_entries (
    id, org_id, project_id, environment_id, snapshot_id,
    key_id, key_name, classification, ciphertext, value_entry_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListSnapshotEntries :many
SELECT id, org_id, project_id, environment_id, snapshot_id,
       key_id, key_name, classification, ciphertext, value_entry_id
FROM snapshot_entries
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND snapshot_id = ?
ORDER BY key_name;

-- name: DeleteSnapshotEntriesForEnvironment :execrows
DELETE FROM snapshot_entries
WHERE org_id = ? AND project_id = ? AND environment_id = ?;

-- name: InsertRevisionKeyChange :exec
INSERT INTO revision_key_changes (
    org_id, project_id, environment_id, revision, key_id, key_name, change
) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListRevisionKeyChanges :many
SELECT org_id, project_id, environment_id, revision, key_id, key_name, change
FROM revision_key_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND revision = ?
ORDER BY key_name;

-- name: DeleteRevisionKeyChangesForEnvironment :execrows
DELETE FROM revision_key_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ?;
