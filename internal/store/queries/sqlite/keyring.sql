-- name: GetActiveMasterKey :one
SELECT version, root_key_epoch, state, blob, created_at
FROM master_keys WHERE state = 'active';

-- name: InsertMasterKey :exec
INSERT INTO master_keys (version, root_key_epoch, state, blob, created_at)
VALUES (?, ?, 'active', ?, ?);

-- name: GetActiveTier3Key :one
SELECT id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at
FROM tier3_keys WHERE purpose = ? AND org_id = ? AND project_id = ? AND state = 'active';

-- name: InsertTier3Key :exec
INSERT INTO tier3_keys (id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at)
VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?);

-- name: AcquireHierarchyGeneration :one
SELECT generation FROM key_generations WHERE scope = 'hierarchy';

-- name: InsertKeyGeneration :exec
INSERT INTO key_generations (scope, generation) VALUES (?, 1);
