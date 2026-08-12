-- Permission model, full (#55). The grant table and its origins live on the
-- enumerated resolution surface for the same reason the session lifecycle
-- does: authorize() reads grants to mint a proof, so a grant write cannot be
-- gated behind one. Every query here is annotated and pinned.
-- ASCII only: multibyte characters shift sqlite statement offsets.

-- hikyo:authn-resolution
-- name: ListGrantRowsForPrincipal :many
SELECT id, capability, org_id, project_id, env_id FROM grants
WHERE principal_id = ?;

-- hikyo:authn-resolution
-- name: InsertGrantOrigin :exec
INSERT INTO grant_origins (id, grant_id, kind, subject, created_at)
VALUES (?, ?, ?, ?, ?);

-- Releasing one origin. The grant row survives while another origin holds it;
-- only the last release deletes the row (permission ADR, scim amendment (a)).
-- hikyo:authn-resolution
-- name: DeleteGrantOrigin :execrows
DELETE FROM grant_origins WHERE grant_id = ? AND kind = ? AND subject = ?;

-- hikyo:authn-resolution
-- name: CountGrantOrigins :one
SELECT COUNT(*) FROM grant_origins WHERE grant_id = ?;

-- hikyo:authn-resolution
-- name: DeleteGrantRow :execrows
DELETE FROM grants WHERE id = ?;

-- Membership inspection, per capability line with its origin chips. The JOIN
-- means a grant with no origin cannot appear at all, which is the invariant
-- stated as a query.
-- hikyo:authn-resolution
-- name: ListGrantsWithOriginsForOrg :many
SELECT g.id, g.principal_id, g.capability, g.org_id, g.project_id, g.env_id,
       g.created_at, o.kind, o.subject
FROM grants AS g
INNER JOIN grant_origins AS o ON o.grant_id = g.id
WHERE g.org_id = ?
ORDER BY g.principal_id, g.capability, g.id, o.kind, o.subject;

-- The project-scoped membership surface. A project member manager authorizes
-- for ONE project, so the datastore must return one project's rows: filtering
-- the org's rows in Go afterwards makes the work scale with sibling-project
-- membership, which is a structural oracle, and materializes administrative
-- data from projects the caller was never authorized to see.
-- hikyo:authn-resolution
-- name: ListGrantsWithOriginsForProject :many
SELECT g.id, g.principal_id, g.capability, g.org_id, g.project_id, g.env_id,
       g.created_at, o.kind, o.subject
FROM grants AS g
INNER JOIN grant_origins AS o ON o.grant_id = g.id
WHERE g.org_id = ? AND g.project_id = ?
ORDER BY g.principal_id, g.capability, g.id, o.kind, o.subject;

-- hikyo:authn-resolution
-- name: ListGrantsWithOriginsAtInstance :many
SELECT g.id, g.principal_id, g.capability, g.org_id, g.project_id, g.env_id,
       g.created_at, o.kind, o.subject
FROM grants AS g
INNER JOIN grant_origins AS o ON o.grant_id = g.id
WHERE g.org_id IS NULL
ORDER BY g.principal_id, g.capability, g.id, o.kind, o.subject;

-- The lockout invariant's census. An org's manage-members holders are the
-- principals holding it AT that org or ABOVE it (instance scope inherits
-- downward), which is exactly what the grant evaluation would answer.
--
-- The project_id IS NULL conjunct is load-bearing: a project-scope
-- manage-members grant lives at org_id = ? too, and without it a project
-- member manager would count toward the org census. The permission ADR draws
-- the lockout line at org and instance scope, so a project-scope holder is
-- not one of the org's holders.
-- hikyo:authn-resolution
-- name: ListManageMembersHoldersForOrg :many
SELECT DISTINCT principal_id FROM grants
WHERE capability = 'manage-members'
  AND project_id IS NULL
  AND (org_id = ? OR org_id IS NULL)
ORDER BY principal_id;

-- hikyo:authn-resolution
-- name: ListManageMembersHoldersAtInstance :many
SELECT DISTINCT principal_id FROM grants
WHERE capability = 'manage-members' AND org_id IS NULL
ORDER BY principal_id;

-- The reveal guard reads the environment's own protection state and window.
-- It is a resolution read, not a store read: the reauthentication machinery
-- runs beside session resolution, before any operation proof exists.
-- hikyo:authn-resolution
-- name: EnvironmentReauthSettings :one
SELECT protected, reauth_window_seconds FROM environments WHERE id = ?;

-- The machine allowlists key on the principal's class; kind discriminates
-- human from machine. An unclassified machine principal fails closed in Go.
-- hikyo:authn-resolution
-- name: GetPrincipalClass :one
SELECT kind, class FROM principals WHERE id = ?;

-- The origins holding ONE grant row, for dedup (does this grantor already
-- hold it?) and for revocation (which origins may this surface release?).
-- hikyo:authn-resolution
-- name: ListGrantOriginsForGrant :many
SELECT kind, subject FROM grant_origins WHERE grant_id = ? ORDER BY kind, subject;
