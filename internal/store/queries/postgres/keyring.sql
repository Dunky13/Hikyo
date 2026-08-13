-- name: GetActiveMasterKeys :many
SELECT version, root_key_epoch, state, blob, created_at
FROM master_keys WHERE state = 'active' ORDER BY root_key_epoch DESC;

-- name: InsertMasterKey :exec
INSERT INTO master_keys (version, root_key_epoch, state, blob, created_at)
VALUES ($1, $2, 'active', $3, $4);

-- name: GetActiveTier3Key :one
SELECT id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at
FROM tier3_keys WHERE purpose = $1 AND org_id = $2 AND project_id = $3 AND state = 'active';

-- name: InsertTier3Key :exec
INSERT INTO tier3_keys (id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at)
VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8);

-- name: AcquireHierarchyGeneration :one
SELECT generation FROM key_generations WHERE scope = 'hierarchy' FOR UPDATE;

-- name: InsertKeyGeneration :exec
INSERT INTO key_generations (scope, generation) VALUES ($1, 1);

-- RetireTier3Key retires the active key for one scope so a rotation can put a
-- new version in its place. It is an UPDATE rather than a delete: the
-- superseded row's blob is what still opens material written under it, and the
-- one-active-per-scope index is what makes the swap unambiguous.
-- name: RetireTier3Key :execrows
UPDATE tier3_keys SET state = 'retired'
WHERE purpose = sqlc.arg(purpose) AND org_id = sqlc.arg(org_id)
  AND project_id = sqlc.arg(project_id) AND state = 'active';

-- RetireTier3KeyAtVersion is RetireTier3Key as a compare-and-swap: it retires
-- the active key only when it is still the version the caller prepared its
-- successor against. Zero rows means a concurrent rotation won -- the caller
-- must refuse, not stack a second successor on the wrong predecessor.
-- name: RetireTier3KeyAtVersion :execrows
UPDATE tier3_keys SET state = 'retired'
WHERE purpose = sqlc.arg(purpose) AND org_id = sqlc.arg(org_id)
  AND project_id = sqlc.arg(project_id) AND state = 'active'
  AND version = sqlc.arg(version);
