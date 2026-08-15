-- OIDC federation (#62). Structurally identical to the sqlite dialect; see
-- that file for the reasoning behind every statement here.

-- hikyo:authn-resolution
-- name: InsertFederationIssuer :exec
INSERT INTO federation_issuers (
    id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
    created_at, created_by, updated_at, updated_by
) VALUES (sqlc.arg(id), sqlc.arg(issuer), sqlc.arg(issuer_type), sqlc.arg(jwks_mode),
          sqlc.arg(static_jwks), sqlc.arg(refused_audiences),
          sqlc.arg(created_at), sqlc.arg(created_by), NULL, NULL);

-- The BYTE-EXACT issuer lookup; see the sqlite dialect for why nothing folds.
-- hikyo:authn-resolution
-- name: FederationIssuerByIssuer :one
SELECT id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
       created_at, created_by, updated_at, updated_by
FROM federation_issuers
WHERE issuer = sqlc.arg(issuer);

-- hikyo:authn-resolution
-- name: FederationIssuerByID :one
SELECT id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
       created_at, created_by, updated_at, updated_by
FROM federation_issuers
WHERE id = sqlc.arg(id);

-- hikyo:authn-resolution
-- name: ListFederationIssuers :many
SELECT id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
       created_at, created_by, updated_at, updated_by
FROM federation_issuers
ORDER BY issuer;

-- The issuer's configuration is mutable; its identity is not.
-- hikyo:authn-resolution
-- name: UpdateFederationIssuer :execrows
UPDATE federation_issuers
SET jwks_mode = sqlc.arg(jwks_mode), static_jwks = sqlc.arg(static_jwks),
    refused_audiences = sqlc.arg(refused_audiences),
    updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id);

-- hikyo:authn-resolution
-- name: DeleteFederationIssuer :execrows
DELETE FROM federation_issuers WHERE id = sqlc.arg(id);

-- Every binding naming an issuer, live or historical; see the sqlite dialect for
-- why the revoked rows count too.
-- hikyo:authn-resolution
-- name: CountBindingsForIssuer :one
SELECT COUNT(*) FROM machine_credentials
WHERE issuer_id = sqlc.arg(issuer_id);

-- Federated authentication's single indexed read, over the live-row partial
-- unique index; see the sqlite dialect.
-- hikyo:authn-resolution
-- name: FederatedBindingByIdentity :one
SELECT id, service_account_id, kind, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at,
       issuer_id, subject, audience, required_claims, reactivated_at
FROM machine_credentials
WHERE issuer_id = sqlc.arg(issuer_id) AND subject = sqlc.arg(subject) AND revoked_at IS NULL;

-- The restore predicate's writer (section Restore); see the sqlite dialect.
-- hikyo:authn-resolution
-- name: ReactivateFederatedBinding :execrows
UPDATE machine_credentials SET reactivated_at = sqlc.arg(reactivated_at)
WHERE id = sqlc.arg(id) AND kind = 'oidc-federation';

-- hikyo:authn-resolution
-- name: GetPinGeneration :one
SELECT generation FROM pin_generations
WHERE principal_id = sqlc.arg(principal_id) AND environment_id = sqlc.arg(environment_id);

-- hikyo:authn-resolution
-- name: SetPinGeneration :exec
INSERT INTO pin_generations (principal_id, environment_id, generation)
VALUES (sqlc.arg(principal_id), sqlc.arg(environment_id), sqlc.arg(generation))
ON CONFLICT (principal_id, environment_id) DO UPDATE SET generation = excluded.generation;

-- hikyo:authn-resolution
-- name: DeletePinGenerationsForPrincipal :exec
DELETE FROM pin_generations WHERE principal_id = sqlc.arg(principal_id);
