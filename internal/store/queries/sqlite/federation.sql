-- OIDC federation (#62, machine-identities ADR section Federation). Issuer
-- configuration is instance-scoped; a federated binding is a row of
-- machine_credentials under the credential-kind discriminator, so its
-- statements live beside the credential ones on the resolution surface for the
-- same reason: a machine credential resolves at the chokepoint that mints the
-- proof, so it cannot be read from behind one.
-- ASCII only: multibyte characters shift sqlite statement offsets.

-- hikyo:authn-resolution
-- name: InsertFederationIssuer :exec
INSERT INTO federation_issuers (
    id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
    created_at, created_by, updated_at, updated_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL);

-- The BYTE-EXACT issuer lookup. There is no LOWER(), no TRIM() and no URL
-- normalization anywhere on this path: `iss` is case-sensitive by
-- specification, so folding it here would merge two distinct external issuers
-- into one configuration -- and the UNIQUE index would enforce the merge
-- rather than catch it.
-- hikyo:authn-resolution
-- name: FederationIssuerByIssuer :one
SELECT id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
       created_at, created_by, updated_at, updated_by
FROM federation_issuers
WHERE issuer = ?;

-- hikyo:authn-resolution
-- name: FederationIssuerByID :one
SELECT id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
       created_at, created_by, updated_at, updated_by
FROM federation_issuers
WHERE id = ?;

-- Every configured issuer, read on the authentication path so a presented
-- token's `iss` can be resolved, and on the administrative path so an operator
-- can see what the instance trusts. One query serves both: the set is small
-- (one row per platform) and bounded by an instance capability.
-- hikyo:authn-resolution
-- name: ListFederationIssuers :many
SELECT id, issuer, issuer_type, jwks_mode, static_jwks, refused_audiences,
       created_at, created_by, updated_at, updated_by
FROM federation_issuers
ORDER BY issuer;

-- The issuer's own configuration is mutable (its JWKS source and the audiences
-- it refuses); its IDENTITY is not. `issuer` and `issuer_type` are absent from
-- the SET list on purpose: changing either would silently re-point every
-- binding underneath at a different external authority, which is a
-- replacement, not an edit.
-- hikyo:authn-resolution
-- name: UpdateFederationIssuer :execrows
UPDATE federation_issuers
SET jwks_mode = ?, static_jwks = ?, refused_audiences = ?, updated_at = ?, updated_by = ?
WHERE id = ?;

-- hikyo:authn-resolution
-- name: DeleteFederationIssuer :execrows
DELETE FROM federation_issuers WHERE id = ?;

-- Every binding naming an issuer, live or historical, counted so a delete that
-- would orphan one is refused rather than cascading.
--
-- It counts REVOKED rows too, and that is deliberate. A cascade would
-- deprovision N workloads under an operation whose name says "configuration".
-- Refusing only on LIVE bindings would leave the historical rows pointing at an
-- issuer that no longer exists, so the trail could no longer answer what a past
-- binding trusted -- and the foreign key would refuse the delete anyway, with a
-- driver message instead of an explanation. An operator who really wants the
-- issuer gone deletes the service accounts, which removes their credential rows.
-- hikyo:authn-resolution
-- name: CountBindingsForIssuer :one
SELECT COUNT(*) FROM machine_credentials
WHERE issuer_id = ?;

-- Federated authentication's single indexed read, over the LIVE-ROW partial
-- unique index. `(issuer_id, subject)` is the whole predicate and the match is
-- byte-exact: no wildcards, no namespace patterns, no path prefixes, no case
-- folding. An unbound identity resolves to nothing, which is not a login.
--
-- Like the verifier read it returns the row unconditionally rather than
-- filtering on liveness beyond the index predicate, so the caller evaluates
-- every remaining predicate after a fixed number of reads.
-- hikyo:authn-resolution
-- name: FederatedBindingByIdentity :one
SELECT id, service_account_id, kind, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at,
       issuer_id, subject, audience, required_claims, reactivated_at
FROM machine_credentials
WHERE issuer_id = ? AND subject = ? AND revoked_at IS NULL;

-- The restore predicate's writer (section Restore). Re-activation is a
-- RE-VALIDATION, not a trust: a restore can resurrect a binding that was
-- removed precisely because that workload was compromised. The re-activation
-- UX is #76's; the column and the refusal it drives land here, because a
-- restore path that arrives later cannot retrofit a predicate onto tokens
-- already accepted.
-- hikyo:authn-resolution
-- name: ReactivateFederatedBinding :execrows
UPDATE machine_credentials SET reactivated_at = ?
WHERE id = ? AND kind = 'oidc-federation';

-- The pin generation the conditional cursor is bound to. An ABSENT row is
-- generation 0 -- the truthful "this principal has never had a pin here" --
-- so the read tolerates no row rather than the caller materialising one.
-- hikyo:authn-resolution
-- name: GetPinGeneration :one
SELECT generation FROM pin_generations
WHERE principal_id = ? AND environment_id = ?;

-- The generation writer. #52 owns pin creation, reassignment and release; this
-- is the counter each of those must advance, and it exists now because the
-- cursor is bound to it now.
-- hikyo:authn-resolution
-- name: SetPinGeneration :exec
INSERT INTO pin_generations (principal_id, environment_id, generation)
VALUES (?, ?, ?)
ON CONFLICT (principal_id, environment_id) DO UPDATE SET generation = excluded.generation;

-- hikyo:authn-resolution
-- name: DeletePinGenerationsForPrincipal :exec
DELETE FROM pin_generations WHERE principal_id = ?;
