-- SCIM provisioning, authentication-resolution half (#73).
--
-- Two kinds of statement live here and both belong on the enumerated
-- resolution surface rather than the proof-carrying repository surface:
--
--   1. `scim_credentials` is what AUTHENTICATES a SCIM wire request. It is
--      resolved before any operation is authorized - there is no proof yet
--      to bind it to, exactly as `sessions` is. Its administration (mint, list,
--      revoke) runs AFTER the ordinary `manage-members(org)` gate, following
--      the OIDC/SAML provider-administration precedent where the operation
--      registry owns the gate and the storage rides here.
--   2. the grant-origin reads the release algorithm needs. `grants` and
--      `grant_origins` are already this surface (authorize() reads them to
--      mint a proof), so a SCIM-side origin release is the same class of
--      write a human revoke is.
--
-- Every query is annotated and content-pinned.
-- ASCII only: multibyte characters shift sqlite statement offsets.

-- hikyo:authn-resolution
-- name: InsertSCIMCredential :exec
INSERT INTO scim_credentials
    (id, org_id, binding_id, principal_id, verifier, credential_epoch, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- Presentation resolves the verifier, never anything inside the value: kind,
-- binding, expiry and epoch are read from the row (machine-identities ADR).
-- hikyo:authn-resolution
-- name: GetSCIMCredentialByVerifier :one
SELECT id, org_id, binding_id, principal_id, verifier, credential_epoch, created_at,
       expires_at, revoked_at, last_used_at
FROM scim_credentials WHERE verifier = ?;

-- hikyo:authn-resolution
-- name: GetSCIMCredential :one
SELECT id, binding_id, principal_id, credential_epoch, created_at, expires_at,
       revoked_at, last_used_at
FROM scim_credentials WHERE org_id = ? AND binding_id = ? AND id = ?;

-- hikyo:authn-resolution
-- name: ListSCIMCredentials :many
SELECT id, binding_id, principal_id, credential_epoch, created_at, expires_at,
       revoked_at, last_used_at
FROM scim_credentials WHERE org_id = ? AND binding_id = ? ORDER BY created_at, id;

-- Revocation bites at the NEXT request: the row is marked, not deleted, so the
-- verifier stays occupied and the credential id keeps naming a real thing on
-- the administration surface.
-- hikyo:authn-resolution
-- name: RevokeSCIMCredential :execrows
UPDATE scim_credentials SET revoked_at = ?
WHERE org_id = ? AND binding_id = ? AND id = ? AND revoked_at IS NULL;

-- Step (1) of the binding-deletion state machine: every credential dies first,
-- so no new wire transaction can begin.
-- hikyo:authn-resolution
-- name: RevokeSCIMCredentialsForBinding :execrows
UPDATE scim_credentials SET revoked_at = ?
WHERE org_id = ? AND binding_id = ? AND revoked_at IS NULL;

-- hikyo:authn-resolution
-- name: TouchSCIMCredential :exec
UPDATE scim_credentials SET last_used_at = ? WHERE id = ?;

-- hikyo:authn-resolution
-- name: DeleteSCIMCredentialsForBinding :exec
DELETE FROM scim_credentials WHERE org_id = ? AND binding_id = ?;

-- The release algorithm's read: every origin holding every grant row of one
-- principal, in one statement. Walking grant rows and then their origins
-- one-by-one would be the same information at N+1 queries, and a release
-- decision that spans both tables should see them at one instant.
-- hikyo:authn-resolution
-- name: ListGrantOriginsForPrincipal :many
SELECT g.id, g.capability, g.org_id, g.project_id, g.env_id, o.kind, o.subject
FROM grants AS g
INNER JOIN grant_origins AS o ON o.grant_id = g.id
WHERE g.principal_id = ?
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
WHERE o.kind = 'lockout-retention' AND g.org_id = ?
ORDER BY g.id, o.subject;
