-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateEnvironment :exec
INSERT INTO environments (id, org_id, project_id, name, note, display_order, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetEnvironment :one
SELECT id, org_id, project_id, name, note, created_at, display_order FROM environments
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: ListEnvironments :many
SELECT id, org_id, project_id, name, note, created_at, display_order FROM environments
WHERE org_id = ? AND project_id = ? ORDER BY display_order, name;

-- name: CountEnvironments :one
SELECT COUNT(*) FROM environments WHERE org_id = ? AND project_id = ?;

-- NextEnvironmentOrder is the append position: one past the highest order in
-- use, NOT the row count. Deleting an environment deliberately leaves a gap, so
-- a count would hand the next create a position another row already holds.
-- The CAST pins the column type; without it sqlc types COALESCE as untyped.
-- name: NextEnvironmentOrder :one
SELECT CAST(COALESCE(MAX(display_order) + 1, 0) AS INTEGER) FROM environments
WHERE org_id = ? AND project_id = ?;

-- name: UpdateEnvironmentNote :execrows
UPDATE environments SET note = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: RenameEnvironment :execrows
UPDATE environments SET name = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- Reorder is authorized at PROJECT depth (it rewrites the project's whole
-- ordered set), so the proof carries no environment id and `id` is an ordinary
-- caller argument. The chain conjuncts confine it: an id from another project
-- matches no row, which is the uniform nonexistent outcome the reorder service
-- turns into a refusal.
-- name: SetEnvironmentOrder :execrows
UPDATE environments SET display_order = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: DeleteEnvironment :execrows
DELETE FROM environments WHERE org_id = ? AND project_id = ? AND id = ?;

-- Protected-environment flag and per-environment reauthentication window
-- (#55, permission-model ADR - The reveal guard). Both live under
-- `project-settings`; a NULL window means "inherit the instance default".

-- name: GetEnvironmentSettings :one
SELECT protected, reauth_window_seconds FROM environments
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: SetEnvironmentSettings :execrows
UPDATE environments SET protected = ?, reauth_window_seconds = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- ListEnvironmentProtection reads every environment's protected flag under a
-- PROJECT proof - the definitions plan/apply path pins the project's protected
-- set and refuses if it grew (#70, permission-model ADR section 84). GetEnvironmentSettings
-- is environment-addressed and cannot serve a project-scoped read.
-- name: ListEnvironmentProtection :many
SELECT id, protected FROM environments
WHERE org_id = ? AND project_id = ? ORDER BY id;
