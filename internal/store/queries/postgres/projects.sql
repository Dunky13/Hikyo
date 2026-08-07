-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateProject :exec
INSERT INTO projects (id, org_id, name, created_at)
VALUES (sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(name), sqlc.arg(created_at));
