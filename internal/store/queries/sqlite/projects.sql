-- Tenant-scoped statements. The reserved chain_* parameters are bound by the
-- store's binding layer from proof fields only - never from caller
-- arguments; the SQL predicate analyzer enforces the conjunct shape.

-- name: CreateProject :exec
INSERT INTO projects (id, org_id, name, created_at)
VALUES (?, ?, ?, ?);

-- name: GetProject :one
SELECT id, org_id, name, created_at,
       retention_revision_count, retention_age_seconds, definitions_source,
       machine_reveal
FROM projects
WHERE org_id = ? AND id = ?;

-- name: ListProjects :many
SELECT id, org_id, name, created_at,
       retention_revision_count, retention_age_seconds, definitions_source,
       machine_reveal
FROM projects
WHERE org_id = ? ORDER BY name;

-- ListAllProjects is the multi-instance directory's cross-org enumeration
-- (#71): the served listing is org/project names and counts across the whole
-- instance, so it addresses no tenant and carries no chain conjunct. It is
-- annotated instance-scoped for exactly the reason ListOrgs is - the read is
-- cross-tenant by definition, not by omission. Only (org_id, name) is
-- selected: the directory needs names and counts, and a row shape carrying
-- created_at would be foreign structure nobody asked for.
-- hikyo:instance-scoped
-- name: ListAllProjects :many
SELECT org_id, name FROM projects ORDER BY org_id, name;

-- name: RenameProject :execrows
UPDATE projects SET name = ?
WHERE org_id = ? AND id = ?;

-- name: SetProjectRetention :execrows
UPDATE projects
SET retention_age_seconds = ?, retention_revision_count = ?
WHERE org_id = ? AND id = ?;

-- SetProjectDefinitionsSource flips a project between db- and git-managed
-- definitions (#70). It is a project-settings write, deliberately off the
-- definitions-edit path so a blocked editor cannot disable its own guard.
-- name: SetProjectDefinitionsSource :execrows
UPDATE projects SET definitions_source = ?
WHERE org_id = ? AND id = ?;

-- SetProjectMachineReveal flips the per-project machine-reveal opt-in. It is
-- a project-settings write; the grant writer and the fetch path both read the
-- column live, so flipping it back to 0 withdraws machine secret delivery on
-- the next fetch without touching any grant row.
-- name: SetProjectMachineReveal :execrows
UPDATE projects SET machine_reveal = ?
WHERE org_id = ? AND id = ?;

-- name: DeleteProject :execrows
DELETE FROM projects WHERE org_id = ? AND id = ?;

-- LockProject takes the project row for the length of the transaction, so
-- every environment-set mutation on one project serializes. It is what makes
-- the environment cap and the append position race-free: two creates at cap-1
-- would otherwise both read the same count and both insert.
--
-- On sqlite this statement is a plain read: the write pool is a single
-- connection opened with _txlock=immediate, so write transactions already
-- serialize instance-wide and there is nothing finer to take. The query exists
-- on both engines because the store method must, and because the cross-engine
-- check requires the same query names.
-- name: LockProject :one
SELECT id FROM projects WHERE org_id = ? AND id = ?;
