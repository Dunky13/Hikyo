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
    operation, ciphertext, staged_from_revision, staged_from_entry, created_at, source, secret, material_secret
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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
       operation, ciphertext, staged_from_revision, staged_from_entry, created_at, source, secret, material_secret
FROM pending_changes
WHERE org_id = ? AND project_id = ? AND owner_id = ?
ORDER BY environment_id, key_id;

-- ListPendingChangesForOwnerInEnvironment is the preview read. Owner and
-- environment are both predicates in SQL, so the preview cannot hand one
-- principal another's ciphertext or material from another environment.
-- name: ListPendingChangesForOwnerInEnvironment :many
SELECT id, org_id, project_id, environment_id, key_id, owner_id,
       operation, ciphertext, staged_from_revision, staged_from_entry, created_at, source, secret, material_secret
FROM pending_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND owner_id = ?
ORDER BY key_id;

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
SELECT id, org_id, project_id, environment_id, revision, schema_revision,
       published_by, published_at, payload_present, collected_at, collected_policy
FROM snapshots
WHERE org_id = ? AND project_id = ? AND environment_id = ?
ORDER BY revision DESC
LIMIT 1;

-- name: GetSnapshotByRevision :one
SELECT id, org_id, project_id, environment_id, revision, schema_revision,
       published_by, published_at, payload_present, collected_at, collected_policy
FROM snapshots
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND revision = ?;

-- ProjectSnapshotRevisions returns the project-confined revision rows used to
-- build the definitions plan/apply pin (#70). The repository folds the maximum
-- per environment; keeping aggregation out of SQL leaves the chain predicate in
-- the conservative analyzer's provable shape.
-- name: ProjectSnapshotRevisions :many
SELECT environment_id, revision FROM snapshots
WHERE org_id = ? AND project_id = ?;

-- name: ListSnapshots :many
SELECT id, org_id, project_id, environment_id, revision, schema_revision,
       published_by, published_at, payload_present, collected_at, collected_policy
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

-- name: RecordSecretValueOccurrence :exec
INSERT INTO secret_value_occurrences (
    value_entry_id, org_id, project_id, environment_id
)
VALUES (?, ?, ?, ?);

-- name: ListSecretValueOccurrenceIDs :many
SELECT value_entry_id
FROM secret_value_occurrences
WHERE org_id = ? AND project_id = ? AND environment_id = ?
ORDER BY value_entry_id;

-- name: DeleteSecretValueOccurrencesForEnvironment :execrows
DELETE FROM secret_value_occurrences
WHERE org_id = ? AND project_id = ? AND environment_id = ?;
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

-- name: GetRevisionPinForWorkload :one
SELECT id, org_id, project_id, environment_id, workload_principal_id,
       snapshot_id, revision, authority_principal_id, expires_at, created_at,
       authorized_at, history_authorized, schema_override
FROM revision_pins
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND workload_principal_id = ?;

-- name: ListRevisionPins :many
SELECT id, org_id, project_id, environment_id, workload_principal_id,
       snapshot_id, revision, authority_principal_id, expires_at, created_at,
       authorized_at, history_authorized, schema_override
FROM revision_pins
WHERE org_id = ? AND project_id = ? AND environment_id = ?
ORDER BY workload_principal_id;

-- name: CountRevisionPinsForProject :one
SELECT COUNT(*) FROM revision_pins WHERE org_id = ? AND project_id = ?;

-- name: InsertRevisionPin :exec
INSERT INTO revision_pins (
    id, org_id, project_id, environment_id, workload_principal_id,
    snapshot_id, revision, authority_principal_id, expires_at, created_at,
    authorized_at, history_authorized, schema_override
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteRevisionPin :execrows
DELETE FROM revision_pins
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND workload_principal_id = ?;

-- name: DeleteRevisionPinsForEnvironment :execrows
DELETE FROM revision_pins
WHERE org_id = ? AND project_id = ? AND environment_id = ?;

-- name: DeleteRevisionKeyChangesForEnvironment :execrows
DELETE FROM revision_key_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ?;

-- name: CountPendingChangesForProject :one
SELECT COUNT(*) FROM pending_changes
WHERE org_id = ? AND project_id = ?;

-- name: CountPendingChangeForCell :one
SELECT COUNT(*) FROM pending_changes
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND key_id = ? AND owner_id = ?;
