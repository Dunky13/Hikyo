-- The key catalogue (#49). Tenant-scoped statements: the reserved chain_*
-- parameters are bound by the store's binding layer from proof fields only -
-- never from caller arguments; the SQL predicate analyzer enforces the
-- conjunct shape.
--
-- A key, a group and a presence row are all addressed WITHIN the project the
-- proof resolved. The scope lattice has no key level (permission-model ADR:
-- no key-scoped grants in v1), so `id` is an ordinary caller argument: an id
-- from another project simply misses the chain predicate, which is the uniform
-- nonexistent outcome.

-- name: CreateKeyGroup :exec
INSERT INTO key_groups (id, org_id, project_id, name, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetKeyGroup :one
SELECT id, org_id, project_id, name, created_at FROM key_groups
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: ListKeyGroups :many
SELECT id, org_id, project_id, name, created_at FROM key_groups
WHERE org_id = ? AND project_id = ? ORDER BY name;

-- name: CountKeyGroups :one
SELECT COUNT(*) FROM key_groups WHERE org_id = ? AND project_id = ?;

-- name: RenameKeyGroup :execrows
UPDATE key_groups SET name = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: DeleteKeyGroup :execrows
DELETE FROM key_groups WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: CreateKey :exec
INSERT INTO keys (
    id, org_id, project_id, name, folder_path, classification, description,
    deprecated, deprecation_note, declaration, required_mode, forbidden_mode,
    group_id, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetKey :one
SELECT id, org_id, project_id, name, folder_path, classification, description,
       deprecated, deprecation_note, declaration, required_mode, forbidden_mode,
       group_id, created_at
FROM keys WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: ListKeys :many
SELECT id, org_id, project_id, name, folder_path, classification, description,
       deprecated, deprecation_note, declaration, required_mode, forbidden_mode,
       group_id, created_at
FROM keys WHERE org_id = ? AND project_id = ? ORDER BY name;

-- name: CountKeys :one
SELECT COUNT(*) FROM keys WHERE org_id = ? AND project_id = ?;

-- name: RenameKey :execrows
UPDATE keys SET name = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- UpdateKeyMetadata carries exactly the NON-semantic fields (schema-model ADR
-- section Authorization: description, deprecated, deprecation_note and folder path
-- cannot change what any environment delivers or whether it validates). They
-- are one statement precisely so no caller can smuggle a semantic field in
-- beside them.
-- name: UpdateKeyMetadata :execrows
UPDATE keys SET folder_path = ?, description = ?, deprecated = ?, deprecation_note = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- UpdateKeyDeclaration carries the value-dependent rules and the presence
-- MODES together, because a declaration save replaces both as one unit.
-- name: UpdateKeyDeclaration :execrows
UPDATE keys SET declaration = ?, required_mode = ?, forbidden_mode = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- SetKeyClassification is its own statement because reclassification is its
-- own ceremony: it is never a field of an ordinary update, so it is never a
-- column of one either.
-- name: SetKeyClassification :execrows
UPDATE keys SET classification = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: SetKeyGroup :execrows
UPDATE keys SET group_id = ?
WHERE org_id = ? AND project_id = ? AND id = ?;

-- ClearKeyGroupMembers is the delete cascade: deleting a group takes its
-- members OUT of it rather than deleting them. Zero affected rows is the
-- ordinary case for an empty group, so this is :exec.
-- name: ClearKeyGroupMembers :exec
UPDATE keys SET group_id = NULL
WHERE org_id = ? AND project_id = ? AND group_id = ?;

-- name: DeleteKey :execrows
DELETE FROM keys WHERE org_id = ? AND project_id = ? AND id = ?;

-- name: InsertKeyPresence :exec
INSERT INTO key_presence_environments (org_id, project_id, key_id, environment_id, rule)
VALUES (?, ?, ?, ?, ?);

-- name: ListKeyPresence :many
SELECT org_id, project_id, key_id, environment_id, rule
FROM key_presence_environments
WHERE org_id = ? AND project_id = ? ORDER BY key_id, rule, environment_id;

-- DeleteKeyPresence clears one key's explicit sets so a declaration save can
-- rewrite them whole. Zero rows is the ordinary case (a key whose modes were
-- never `explicit`), so this is :exec.
-- name: DeleteKeyPresence :exec
DELETE FROM key_presence_environments
WHERE org_id = ? AND project_id = ? AND key_id = ?;

-- DeleteEnvironmentPresence is the environment-lifecycle cascade: deleting an
-- environment removes its id from every explicit presence set IN THE SAME
-- TRANSACTION (schema-model ADR section Presence). Zero rows is ordinary.
-- name: DeleteEnvironmentPresence :exec
DELETE FROM key_presence_environments
WHERE org_id = ? AND project_id = ? AND environment_id = ?;

-- InsertProjectSchemaRevision runs inside projects.Create, where the project
-- id is the row being created rather than an address the proof resolved - the
-- same position `CreateProject`'s own `id` is in. The org half IS proof-bound.
-- A new project starts at revision 0, written literally so there is no
-- parameter a caller could set it through.
-- name: InsertProjectSchemaRevision :exec
INSERT INTO project_schema_revisions (org_id, project_id, revision)
VALUES (?, ?, 0);

-- name: GetProjectSchemaRevision :one
SELECT revision FROM project_schema_revisions
WHERE org_id = ? AND project_id = ?;

-- BumpProjectSchemaRevision is the monotonic advance, run inside the same
-- transaction as the declaration change that earned it. :execrows so a missing
-- row - which cannot happen, every project gets one at creation - is reported
-- as the defect it would be rather than silently created.
-- name: BumpProjectSchemaRevision :execrows
UPDATE project_schema_revisions SET revision = revision + 1
WHERE org_id = ? AND project_id = ?;

-- DeleteProjectSchemaRevision runs inside projects.Delete, ahead of the project
-- row it references. A project delete refuses while the project still holds
-- keys or groups (their foreign keys say so); the revision row is not content,
-- it is the project's own counter, so it goes with the project rather than
-- standing in the way of deleting an empty one.
-- name: DeleteProjectSchemaRevision :exec
DELETE FROM project_schema_revisions WHERE org_id = ? AND project_id = ?;
