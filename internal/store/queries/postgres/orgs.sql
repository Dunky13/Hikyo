-- name: CreateOrg :exec
INSERT INTO orgs (id, name, active, metadata, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetOrg :one
SELECT id, name, active, metadata, created_at FROM orgs WHERE id = $1;

-- name: ListOrgs :many
SELECT id, name, active, metadata, created_at FROM orgs ORDER BY name;

-- name: CountOrgs :one
SELECT COUNT(*) FROM orgs;
