-- SCIM provisioning, authentication-resolution half (#73). See the sqlite
-- dialect for the reasoning behind each statement's placement on this surface.

-- hikyo:authn-resolution
-- name: InsertSCIMCredential :exec
INSERT INTO scim_credentials
    (id, org_id, binding_id, principal_id, verifier, credential_epoch, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- hikyo:authn-resolution
-- name: GetSCIMCredentialByVerifier :one
SELECT id, org_id, binding_id, principal_id, verifier, credential_epoch, created_at,
       expires_at, revoked_at, last_used_at
FROM scim_credentials WHERE verifier = $1;

-- hikyo:authn-resolution
-- name: GetSCIMCredential :one
SELECT id, binding_id, principal_id, credential_epoch, created_at, expires_at,
       revoked_at, last_used_at
FROM scim_credentials WHERE org_id = $1 AND binding_id = $2 AND id = $3;

-- hikyo:authn-resolution
-- name: ListSCIMCredentials :many
SELECT id, binding_id, principal_id, credential_epoch, created_at, expires_at,
       revoked_at, last_used_at
FROM scim_credentials WHERE org_id = $1 AND binding_id = $2 ORDER BY created_at, id;

-- hikyo:authn-resolution
-- name: RevokeSCIMCredential :execrows
UPDATE scim_credentials SET revoked_at = $1
WHERE org_id = $2 AND binding_id = $3 AND id = $4 AND revoked_at IS NULL;

-- hikyo:authn-resolution
-- name: RevokeSCIMCredentialsForBinding :execrows
UPDATE scim_credentials SET revoked_at = $1
WHERE org_id = $2 AND binding_id = $3 AND revoked_at IS NULL;

-- hikyo:authn-resolution
-- name: TouchSCIMCredential :exec
UPDATE scim_credentials SET last_used_at = $1 WHERE id = $2;

-- hikyo:authn-resolution
-- name: DeleteSCIMCredentialsForBinding :exec
DELETE FROM scim_credentials WHERE org_id = $1 AND binding_id = $2;

-- hikyo:authn-resolution
-- name: ListGrantOriginsForPrincipal :many
SELECT g.id, g.capability, g.org_id, g.project_id, g.env_id, o.kind, o.subject
FROM grants AS g
INNER JOIN grant_origins AS o ON o.grant_id = g.id
WHERE g.principal_id = $1
ORDER BY g.id, o.kind, o.subject;

-- Every lockout-retention origin in the instance, with the grant row it holds
-- (ADR section 2.4). The cure sweep is global rather than per-org because an
-- INSTANCE-scope manage-members grant cures every org at once, and a per-org
-- sweep would silently leave those retentions standing. Retention origins are
-- rare by construction -- one per grant the IdP withdrew from the last member
-- manager -- so the whole set is cheap to walk.
-- hikyo:authn-resolution
-- name: ListLockoutRetentionOrigins :many
SELECT g.id, g.principal_id, g.capability, g.org_id, g.project_id, g.env_id, o.subject
FROM grants AS g
INNER JOIN grant_origins AS o ON o.grant_id = g.id
WHERE o.kind = 'lockout-retention'
ORDER BY g.id, o.subject;

-- The cure sweep bounded to ONE org. An org-scope `manage-members` grant cures
-- that org and no other, so loading and locking every retention in the instance
-- to then discard all but one org's is both tenant-triggerable O(instance) work
-- and a cross-tenant timing signal. Only an INSTANCE-scope grant needs the
-- unbounded walk above.
-- hikyo:authn-resolution
-- name: ListLockoutRetentionOriginsInOrg :many
SELECT g.id, g.principal_id, g.capability, g.org_id, g.project_id, g.env_id, o.subject
FROM grants AS g
INNER JOIN grant_origins AS o ON o.grant_id = g.id
WHERE o.kind = 'lockout-retention' AND g.org_id = $1
ORDER BY g.id, o.subject;
