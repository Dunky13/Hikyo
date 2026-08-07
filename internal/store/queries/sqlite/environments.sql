-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateEnvironment :exec
INSERT INTO environments (id, org_id, project_id, name, note, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetEnvironment :one
SELECT id, org_id, project_id, name, note, created_at FROM environments
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: UpdateEnvironmentNote :execrows
UPDATE environments SET note = ?
WHERE org_id = ? AND project_id = ? AND id = ?;
