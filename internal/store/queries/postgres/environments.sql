-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateEnvironment :exec
INSERT INTO environments (id, org_id, project_id, name, note, created_at)
VALUES (sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(chain_project_id), sqlc.arg(name), sqlc.arg(note), sqlc.arg(created_at));

-- name: GetEnvironment :one
SELECT id, org_id, project_id, name, note, created_at FROM environments
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);

-- name: UpdateEnvironmentNote :execrows
UPDATE environments SET note = sqlc.arg(note)
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);
