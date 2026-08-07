-- name: GetActiveMasterKey :one
SELECT version, root_key_epoch, state, blob, created_at
FROM master_keys WHERE state = 'active';

-- name: InsertMasterKey :exec
INSERT INTO master_keys (version, root_key_epoch, state, blob, created_at)
VALUES ($1, $2, 'active', $3, $4);

-- name: GetActiveTier3Key :one
SELECT id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at
FROM tier3_keys WHERE purpose = $1 AND org_id = $2 AND project_id = $3 AND state = 'active';

-- name: InsertTier3Key :exec
INSERT INTO tier3_keys (id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at)
VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8);

-- name: TouchHierarchyGeneration :one
SELECT generation FROM key_generations WHERE scope = 'hierarchy' FOR UPDATE;

-- name: InsertKeyGeneration :exec
INSERT INTO key_generations (scope, generation) VALUES ($1, 1);
