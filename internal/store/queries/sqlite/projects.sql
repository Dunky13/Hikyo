-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateProject :exec
INSERT INTO projects (id, org_id, name, created_at)
VALUES (?, ?, ?, ?);

-- name: GetProject :one
SELECT id, org_id, name, created_at FROM projects
WHERE org_id = ? AND id = ?;

-- name: ListProjects :many
SELECT id, org_id, name, created_at FROM projects
WHERE org_id = ? ORDER BY name;

-- name: RenameProject :execrows
UPDATE projects SET name = ?
WHERE org_id = ? AND id = ?;

-- name: DeleteProject :execrows
DELETE FROM projects WHERE org_id = ? AND id = ?;

-- LockProject takes the project row for the length of the transaction, so
-- every environment-set mutation on one project serializes. It is what makes
-- the environment cap and the append position race-free: two creates at cap-1
-- would otherwise both read the same count and both insert.
--
-- On sqlite this statement is a plain read: the write pool is a single
-- connection opened with _txlock=immediate, so write transactions already
-- serialize instance-wide and there is nothing finer to take. The query exists
-- on both engines because the store method must, and because the cross-engine
-- check requires the same query names.
-- name: LockProject :one
SELECT id FROM projects WHERE org_id = ? AND id = ?;
