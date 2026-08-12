-- The Org aggregate. Creation, listing and counting are instance-scoped
-- operations (they are cross-tenant by definition: a create has no parent
-- tenant and an enumeration spans all of them); each is annotated and
-- content-pinned in the allowlist fixture (tenant-isolation ADR invariant 13).
--
-- The by-id statements are NOT annotated: an org row is its own tenant root
-- (scope class org, chain=id), so they carry the chain conjunct like any other
-- tenant statement and the binding layer takes `id` from the proof. That is
-- what makes an org nobody may reach indistinguishable from a missing one
-- (#48, mvp-boundary C1).

-- hikyo:instance-scoped
-- name: CreateOrg :exec
INSERT INTO orgs (id, name, active, metadata, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetOrg :one
SELECT id, name, active, metadata, created_at FROM orgs WHERE id = sqlc.arg(chain_org_id);

-- hikyo:instance-scoped
-- name: ListOrgs :many
SELECT id, name, active, metadata, created_at FROM orgs ORDER BY name;

-- hikyo:instance-scoped
-- name: CountOrgs :one
SELECT COUNT(*) FROM orgs;

-- name: RenameOrg :execrows
UPDATE orgs SET name = sqlc.arg(name) WHERE id = sqlc.arg(chain_org_id);

-- name: DeleteOrg :execrows
DELETE FROM orgs WHERE id = sqlc.arg(chain_org_id);
