-- The flat value model (#50). Tenant-scoped statements: the reserved chain_*
-- parameters are bound by the store's binding layer from proof fields only -
-- never from caller arguments; the SQL predicate analyzer enforces the
-- conjunct shape.
--
-- `environment_id` is an ordinary column here rather than a chain column (see
-- the migration): every environment-addressed statement below still binds it
-- from the proof's resolved chain, and the two project-scoped statements at
-- the bottom are the ones that must span environments.
--
-- There is no UPDATE. A value write is delete-then-insert with a FRESH row id,
-- because the row id is bound into the ciphertext's AAD and an id bound into
-- an AAD is immutable and never reused (encryption ADR).

-- name: GetValueEntry :one
SELECT id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by
FROM value_entries
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND key_id = ?;

-- ListValueEntries is the delivery-shaped read: one environment's entire set,
-- which is exactly what "a `set` entry delivers, `absent` delivers nothing"
-- means when absence is the absence of a row.
-- name: ListValueEntries :many
SELECT id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by
FROM value_entries
WHERE org_id = ? AND project_id = ? AND environment_id = ?
ORDER BY key_id;

-- name: InsertValueEntry :exec
INSERT INTO value_entries (
    id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteValueEntry :execrows
DELETE FROM value_entries
WHERE org_id = ? AND project_id = ? AND environment_id = ? AND key_id = ?;

-- DeleteValueEntriesForEnvironment cascades an environment's whole set out
-- when the environment itself is deleted: the values cannot outlive the only
-- thing they attach to, and the composite foreign key would refuse the delete
-- while they existed.
-- name: DeleteValueEntriesForEnvironment :execrows
DELETE FROM value_entries
WHERE org_id = ? AND project_id = ? AND environment_id = ?;

-- ListValueEnvironmentsForKey spans the project's environments deliberately:
-- it is the input to the key-delete refusal, which must be able to NAME the
-- environments that still deliver material for the key.
-- name: ListValueEnvironmentsForKey :many
SELECT environment_id FROM value_entries
WHERE org_id = ? AND project_id = ? AND key_id = ?
ORDER BY environment_id;
