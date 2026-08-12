-- OIDC provider administration (#54, human-auth ADR - Login methods). The
-- provider table is class=authn: it decides how a caller may authenticate, and
-- login resolves it proof-free, so every statement touching it lives on the
-- resolution surface. Provider mutations are still authorized at the chokepoint
-- (OpProviderPut/Delete under instance-config) before these run; the write
-- itself rides the resolution surface, like the session lifecycle.

-- hikyo:authn-resolution
-- name: CreateOIDCProvider :exec
INSERT INTO oidc_providers
    (id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
     redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
     created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1, $14, $15);

-- hikyo:authn-resolution
-- name: GetOIDCProviderBySlug :one
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers WHERE slug = $1;

-- hikyo:authn-resolution
-- name: ListOIDCProviders :many
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers ORDER BY slug;

-- The issuer is never in the SET list: it is immutable after create (A3), so a
-- reconfiguration cannot silently move the identity space to a new authority.
-- CAS on row_version so a concurrent reconfigure fails closed.
-- hikyo:authn-resolution
-- name: UpdateOIDCProviderCAS :execrows
UPDATE oidc_providers
SET display_name = $1, client_id = $2, client_secret = $3, scopes = $4,
    redirect_uri = $5, jit_policy = $6, assurance_policy = $7, enabled = $8,
    dek_version = $9, row_version = row_version + 1, updated_at = $10
WHERE id = $11 AND row_version = $12;

-- Locks the provider row inside the delete tx so a concurrent Phase-C mint
-- guard serializes behind it. Taken BEFORE the session sweep so the sweep runs
-- with the row held: a mint that already committed is caught by the sweep, and
-- a mint blocked on this lock finds the row gone once the delete commits. FOR
-- UPDATE, so it is a lock, not just a read.
-- hikyo:authn-resolution
-- name: LockOIDCProviderForDelete :one
SELECT id FROM oidc_providers WHERE id = $1 FOR UPDATE;

-- hikyo:authn-resolution
-- name: DeleteOIDCProvider :exec
DELETE FROM oidc_providers WHERE id = $1;

-- A phase-C mint (login/link/reauth) guards the pinned provider row against a
-- concurrent reconfigure: a no-op CAS that takes the row lock. 0 rows affected
-- means the provider was disabled, deleted, re-issued or row_version-bumped
-- since Phase A, so the mint must refuse (the A4 sweep always wins the TOCTOU).
-- A matching row takes the lock, so a concurrent provider-change UPDATE
-- serializes behind it (and vice-versa: whichever commits first, the other's
-- guard sees the bumped row_version and fails). The no-op never bumps
-- row_version, so it never spuriously fails an administrator's reconfigure CAS.
-- hikyo:authn-resolution
-- name: GuardOIDCProviderForMint :execrows
UPDATE oidc_providers SET row_version = row_version
WHERE id = $1 AND row_version = $2 AND issuer = $3 AND enabled = 1;
