-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateProject :exec
INSERT INTO projects (id, org_id, name, created_at)
VALUES (sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(name), sqlc.arg(created_at));

-- name: GetProject :one
SELECT id, org_id, name, created_at FROM projects
WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(chain_project_id);

-- name: ListProjects :many
SELECT id, org_id, name, created_at FROM projects
WHERE org_id = sqlc.arg(chain_org_id) ORDER BY name;

-- name: RenameProject :execrows
UPDATE projects SET name = sqlc.arg(name)
WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(chain_project_id);

-- name: DeleteProject :execrows
DELETE FROM projects WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(chain_project_id);

-- LockProject takes the project row for the length of the transaction, so
-- every environment-set mutation on one project serializes. It is what makes
-- the environment cap and the append position race-free: two creates at cap-1
-- would otherwise both read the same count and both insert. Postgres needs the
-- explicit row lock; sqlite serializes writes by construction (see its copy).
-- name: LockProject :one
SELECT id FROM projects WHERE org_id = sqlc.arg(chain_org_id) AND id = sqlc.arg(chain_project_id) FOR UPDATE;
