-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateEnvironment :exec
INSERT INTO environments (id, org_id, project_id, name, note, display_order, created_at)
VALUES (sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(chain_project_id), sqlc.arg(name), sqlc.arg(note), sqlc.arg(display_order), sqlc.arg(created_at));

-- name: GetEnvironment :one
SELECT id, org_id, project_id, name, note, created_at, display_order FROM environments
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);

-- name: ListEnvironments :many
SELECT id, org_id, project_id, name, note, created_at, display_order FROM environments
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) ORDER BY display_order, name;

-- name: CountEnvironments :one
SELECT COUNT(*) FROM environments WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id);

-- NextEnvironmentOrder is the append position: one past the highest order in
-- use, NOT the row count. Deleting an environment deliberately leaves a gap, so
-- a count would hand the next create a position another row already holds.
-- name: NextEnvironmentOrder :one
SELECT CAST(COALESCE(MAX(display_order) + 1, 0) AS BIGINT) FROM environments
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id);

-- name: UpdateEnvironmentNote :execrows
UPDATE environments SET note = sqlc.arg(note)
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);

-- name: RenameEnvironment :execrows
UPDATE environments SET name = sqlc.arg(name)
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);

-- Reorder is authorized at PROJECT depth (it rewrites the project's whole
-- ordered set), so the proof carries no environment id and `id` is an ordinary
-- caller argument - deliberately not spelled chain_env_id, which would name a
-- proof field the proof does not have. The chain conjuncts confine it: an id
-- from another project matches no row, which is the uniform nonexistent
-- outcome the reorder service turns into a refusal.
-- name: SetEnvironmentOrder :execrows
UPDATE environments SET display_order = sqlc.arg(display_order)
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(id);

-- name: DeleteEnvironment :execrows
DELETE FROM environments WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);

-- Protected-environment flag and per-environment reauthentication window
-- (#55, permission ADR - The reveal guard). Both live under
-- `project-settings`; a NULL window means "inherit the instance default".

-- name: GetEnvironmentSettings :one
SELECT protected, reauth_window_seconds FROM environments
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);

-- name: SetEnvironmentSettings :execrows
UPDATE environments SET protected = sqlc.arg(protected), reauth_window_seconds = sqlc.arg(reauth_window_seconds)
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(chain_env_id);
