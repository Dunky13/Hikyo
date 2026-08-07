-- The demonstration Org aggregate's statements are instance-scoped
-- operations (org creation/listing is cross-tenant by definition); each is
-- annotated and content-pinned in the allowlist fixture (tenant-isolation
-- ADR invariant 13).

-- wenv:instance-scoped
-- name: CreateOrg :exec
INSERT INTO orgs (id, name, active, metadata, created_at)
VALUES ($1, $2, $3, $4, $5);

-- wenv:instance-scoped
-- name: GetOrg :one
SELECT id, name, active, metadata, created_at FROM orgs WHERE id = $1;

-- wenv:instance-scoped
-- name: ListOrgs :many
SELECT id, name, active, metadata, created_at FROM orgs ORDER BY name;

-- wenv:instance-scoped
-- name: CountOrgs :one
SELECT COUNT(*) FROM orgs;
