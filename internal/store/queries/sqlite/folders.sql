-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.
--
-- A folder is addressed WITHIN the project the proof resolved: the chain
-- conjuncts come from the proof, and `id` is an ordinary caller argument like
-- `path` is. The scope lattice has no folder level (permission-model ADR: no
-- folder-scoped grants), so there is no chain field for it to bind from - and
-- it needs none: a folder id from another project simply misses the chain
-- predicate, which is the uniform nonexistent outcome.

-- name: CreateFolder :exec
INSERT INTO folders (id, org_id, project_id, path, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetFolder :one
SELECT id, org_id, project_id, path, created_at FROM folders
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: ListFolders :many
SELECT id, org_id, project_id, path, created_at FROM folders
WHERE org_id = ? AND project_id = ? ORDER BY path;

-- name: RenameFolder :execrows
UPDATE folders SET path = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: DeleteFolder :execrows
DELETE FROM folders WHERE org_id = ? AND project_id = ? AND id = ?;
