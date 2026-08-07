-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateProject :exec
INSERT INTO projects (id, org_id, name, created_at)
VALUES (?, ?, ?, ?);
