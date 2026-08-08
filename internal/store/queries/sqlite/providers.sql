-- OIDC provider administration (#54, human-auth ADR - Login methods). The
-- provider table is class=authn: it decides how a caller may authenticate, and
-- login resolves it proof-free, so every statement touching it lives on the
-- resolution surface. Provider mutations are still authorized at the chokepoint
-- (OpProviderPut/Delete under instance-config) before these run; the write
-- itself rides the resolution surface, like the session lifecycle.

-- wenv:authn-resolution
-- name: CreateOIDCProvider :exec
INSERT INTO oidc_providers
    (id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
     redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
     created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- wenv:authn-resolution
-- name: GetOIDCProviderBySlug :one
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers WHERE slug = ?;

-- wenv:authn-resolution
-- name: ListOIDCProviders :many
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers ORDER BY slug;

-- The issuer is never in the SET list: it is immutable after create (A3), so a
-- reconfiguration cannot silently move the identity space to a new authority.
-- CAS on row_version so a concurrent reconfigure fails closed.
-- wenv:authn-resolution
-- name: UpdateOIDCProviderCAS :execrows
UPDATE oidc_providers
SET display_name = ?, client_id = ?, client_secret = ?, scopes = ?,
    redirect_uri = ?, jit_policy = ?, assurance_policy = ?, enabled = ?,
    dek_version = ?, row_version = row_version + 1, updated_at = ?
WHERE id = ? AND row_version = ?;

-- wenv:authn-resolution
-- name: DeleteOIDCProvider :exec
DELETE FROM oidc_providers WHERE id = ?;
