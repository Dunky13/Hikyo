-- Machine identities (#61). Structurally identical to the sqlite dialect;
-- see that file for the reasoning.

-- hikyo:authn-resolution
-- name: InsertServiceAccount :exec
INSERT INTO service_accounts (id, principal_id, org_id, project_id, name, kind, created_at, created_by)
VALUES (sqlc.arg(id), sqlc.arg(principal_id), sqlc.arg(org_id), sqlc.arg(project_id),
        sqlc.arg(name), sqlc.arg(kind), sqlc.arg(created_at), sqlc.arg(created_by));

-- hikyo:authn-resolution
-- name: GetServiceAccount :one
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE org_id = sqlc.arg(org_id) AND project_id = sqlc.arg(project_id) AND id = sqlc.arg(id);

-- The authentication read; see the sqlite dialect for why it carries no
-- chain predicate.
-- hikyo:authn-resolution
-- name: GetServiceAccountByID :one
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE id = sqlc.arg(id);

-- The OWNING project of a machine principal; see the sqlite dialect.
-- hikyo:authn-resolution
-- name: GetServiceAccountByPrincipal :one
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE principal_id = sqlc.arg(principal_id);

-- hikyo:authn-resolution
-- name: ListServiceAccounts :many
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE org_id = sqlc.arg(org_id) AND project_id = sqlc.arg(project_id)
ORDER BY name, id;

-- hikyo:authn-resolution
-- name: DeleteServiceAccount :execrows
DELETE FROM service_accounts
WHERE org_id = sqlc.arg(org_id) AND project_id = sqlc.arg(project_id) AND id = sqlc.arg(id);

-- hikyo:authn-resolution
-- name: InsertMachineCredential :exec
INSERT INTO machine_credentials (
    id, service_account_id, kind, verifier, prefix_hint, lifetime, expires_at,
    credential_epoch, created_at, created_by, revoked_at, last_used_at
) VALUES (sqlc.arg(id), sqlc.arg(service_account_id), sqlc.arg(kind), sqlc.arg(verifier),
          sqlc.arg(prefix_hint), sqlc.arg(lifetime), sqlc.arg(expires_at),
          sqlc.arg(credential_epoch), sqlc.arg(created_at), sqlc.arg(created_by), NULL, NULL);

-- Authentication's single indexed read; see the sqlite dialect for why it
-- filters on nothing but the verifier.
-- hikyo:authn-resolution
-- name: MachineCredentialByVerifier :one
SELECT id, service_account_id, kind, verifier, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at
FROM machine_credentials
WHERE verifier = sqlc.arg(verifier);

-- hikyo:authn-resolution
-- name: ListMachineCredentials :many
SELECT id, service_account_id, kind, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at
FROM machine_credentials
WHERE service_account_id = sqlc.arg(service_account_id)
ORDER BY created_at, id;

-- hikyo:authn-resolution
-- name: CountLiveMachineCredentials :one
SELECT COUNT(*) FROM machine_credentials
WHERE service_account_id = sqlc.arg(service_account_id)
  AND revoked_at IS NULL
  AND credential_epoch = sqlc.arg(credential_epoch)
  AND (lifetime = 'indefinite' OR expires_at > sqlc.arg(now));

-- The project's live-credential census; see the sqlite dialect.
-- hikyo:authn-resolution
-- name: CountLiveMachineCredentialsInProject :many
SELECT service_account_id, COUNT(*) AS live FROM machine_credentials
WHERE service_account_id IN (
        SELECT id FROM service_accounts WHERE org_id = sqlc.arg(org_id) AND project_id = sqlc.arg(project_id)
    )
  AND revoked_at IS NULL
  AND credential_epoch = sqlc.arg(credential_epoch)
  AND (lifetime = 'indefinite' OR expires_at > sqlc.arg(now))
GROUP BY service_account_id;

-- hikyo:authn-resolution
-- name: RevokeMachineCredential :execrows
UPDATE machine_credentials SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND service_account_id = sqlc.arg(service_account_id) AND revoked_at IS NULL;

-- hikyo:authn-resolution
-- name: RevokeAllMachineCredentials :execrows
UPDATE machine_credentials SET revoked_at = sqlc.arg(revoked_at)
WHERE service_account_id = sqlc.arg(service_account_id) AND revoked_at IS NULL;

-- hikyo:authn-resolution
-- name: TouchMachineCredential :exec
UPDATE machine_credentials SET last_used_at = sqlc.arg(last_used_at) WHERE id = sqlc.arg(id);

-- hikyo:authn-resolution
-- name: ListCredentialsBeyondCeiling :many
SELECT id, service_account_id, expires_at FROM machine_credentials
WHERE revoked_at IS NULL AND lifetime = 'finite' AND expires_at > sqlc.arg(ceiling)
ORDER BY expires_at, id;

-- hikyo:authn-resolution
-- name: ListIndefiniteCredentials :many
SELECT id, service_account_id FROM machine_credentials
WHERE revoked_at IS NULL AND lifetime = 'indefinite'
ORDER BY id;

-- hikyo:authn-resolution
-- name: ClampCredentialExpiry :execrows
UPDATE machine_credentials SET expires_at = sqlc.arg(ceiling)
WHERE revoked_at IS NULL AND lifetime = 'finite' AND expires_at > sqlc.arg(ceiling);

-- The policy row lock; see the sqlite dialect.
-- hikyo:authn-resolution
-- name: LockCredentialPolicy :one
SELECT id FROM credential_policy WHERE id = 1 FOR UPDATE;

-- The indefinite withdrawal clamp; see the sqlite dialect.
-- hikyo:authn-resolution
-- name: ClampIndefiniteCredentials :execrows
UPDATE machine_credentials SET lifetime = 'finite', expires_at = sqlc.arg(ceiling)
WHERE revoked_at IS NULL AND lifetime = 'indefinite';

-- hikyo:authn-resolution
-- name: GetCredentialPolicy :one
SELECT max_finite_lifetime_seconds, allow_indefinite, max_live_credentials, updated_at, updated_by
FROM credential_policy WHERE id = 1;

-- hikyo:authn-resolution
-- name: SetCredentialPolicy :exec
UPDATE credential_policy
SET max_finite_lifetime_seconds = sqlc.arg(max_finite_lifetime_seconds),
    allow_indefinite = sqlc.arg(allow_indefinite),
    max_live_credentials = sqlc.arg(max_live_credentials),
    updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE id = 1;

-- hikyo:authn-resolution
-- name: DeleteGrantOriginsForPrincipal :execrows
DELETE FROM grant_origins
WHERE grant_id IN (SELECT id FROM grants WHERE principal_id = sqlc.arg(principal_id));

-- hikyo:authn-resolution
-- name: DeleteGrantsForPrincipal :execrows
DELETE FROM grants WHERE principal_id = sqlc.arg(principal_id);

-- hikyo:authn-resolution
-- name: DeletePrincipal :execrows
DELETE FROM principals WHERE id = sqlc.arg(id);

-- hikyo:authn-resolution
-- name: DeleteMachineCredentials :execrows
DELETE FROM machine_credentials WHERE service_account_id = sqlc.arg(service_account_id);

-- The universe the mint and widen reachability computations range over; see
-- the sqlite dialect.
-- hikyo:authn-resolution
-- name: ListEnvironmentIDsInProject :many
SELECT id FROM environments
WHERE org_id = sqlc.arg(org_id) AND project_id = sqlc.arg(project_id)
ORDER BY id;

-- hikyo:authn-resolution
-- name: InsertMachinePrincipal :exec
INSERT INTO principals (id, kind, class, session_generation, created_at)
VALUES (sqlc.arg(id), 'machine', sqlc.arg(class), 1, sqlc.arg(created_at));
