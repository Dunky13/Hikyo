-- Machine identities (#61). Service accounts and their credentials live on
-- the enumerated resolution surface for the same reason the session
-- lifecycle does: a machine credential resolves at the chokepoint that mints
-- the proof, so it cannot be read from behind one. Every query here is
-- annotated and pinned.
-- ASCII only: multibyte characters shift sqlite statement offsets.

-- hikyo:authn-resolution
-- name: InsertServiceAccount :exec
INSERT INTO service_accounts (id, principal_id, org_id, project_id, name, kind, created_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- The management read. It carries the full chain in its predicate even
-- though the annotation exempts it: a caller authorized for one project must
-- not be able to address another project's service account by id.
-- hikyo:authn-resolution
-- name: GetServiceAccount :one
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE org_id = ? AND project_id = ? AND id = ?;

-- The authentication read. It resolves BY ID with no chain predicate, which
-- is the one place that is correct: the id came from the credential row the
-- presented verifier resolved to, not from a caller.
-- hikyo:authn-resolution
-- name: GetServiceAccountByID :one
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE id = ?;

-- The OWNING project of a machine principal, read from the row that records
-- it rather than inferred from the grants it already holds. A freshly created
-- service account holds none, so an inference has nothing to say and would
-- let its FIRST grant name any project in any org.
-- hikyo:authn-resolution
-- name: GetServiceAccountByPrincipal :one
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE principal_id = ?;

-- hikyo:authn-resolution
-- name: ListServiceAccounts :many
SELECT id, principal_id, org_id, project_id, name, kind, created_at, created_by
FROM service_accounts
WHERE org_id = ? AND project_id = ?
ORDER BY name, id;

-- Deleting a service account revokes every credential and every grant in one
-- transaction (#15's atomic revocation); this is the last statement of that
-- sequence, so the FK from machine_credentials is already satisfied.
-- hikyo:authn-resolution
-- name: DeleteServiceAccount :execrows
DELETE FROM service_accounts WHERE org_id = ? AND project_id = ? AND id = ?;

-- hikyo:authn-resolution
-- name: InsertMachineCredential :exec
INSERT INTO machine_credentials (
    id, service_account_id, kind, verifier, prefix_hint, lifetime, expires_at,
    credential_epoch, created_at, created_by, revoked_at, last_used_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL);

-- Authentication's single indexed read. It returns the row unconditionally --
-- revoked, expired and epoch-superseded rows included -- because the caller
-- evaluates every predicate together after a FIXED number of reads. Filtering
-- here would make an unknown credential cost one query and a revoked one
-- two, which is a query-count oracle for which credentials exist.
-- hikyo:authn-resolution
-- name: MachineCredentialByVerifier :one
SELECT id, service_account_id, kind, verifier, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at
FROM machine_credentials
WHERE verifier = ?;

-- hikyo:authn-resolution
-- name: ListMachineCredentials :many
SELECT id, service_account_id, kind, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at
FROM machine_credentials
WHERE service_account_id = ?
ORDER BY created_at, id;

-- The concurrent-credential cap's census: live means not revoked, at the
-- current epoch, and either indefinite or not yet expired.
-- hikyo:authn-resolution
-- name: CountLiveMachineCredentials :one
SELECT COUNT(*) FROM machine_credentials
WHERE service_account_id = ?
  AND revoked_at IS NULL
  AND credential_epoch = ?
  AND (lifetime = 'indefinite' OR expires_at > ?);

-- Revocation is idempotent by predicate, not by read-then-write: the
-- revoked_at IS NULL guard means two concurrent revokes cannot both report
-- having performed one.
-- The project's live-credential census in ONE query. Listing service
-- accounts otherwise costs a count per account, which makes an
-- administrative list scale with the fleet it is describing.
--
-- The IN-subquery is the analyzer's rejected shape, so this rides the
-- resolution surface's annotation like every other query here, and it
-- carries the full chain predicate anyway.
-- hikyo:authn-resolution
-- name: CountLiveMachineCredentialsInProject :many
SELECT service_account_id, COUNT(*) AS live FROM machine_credentials
WHERE service_account_id IN (
        SELECT id FROM service_accounts WHERE org_id = ? AND project_id = ?
    )
  AND revoked_at IS NULL
  AND credential_epoch = ?
  AND (lifetime = 'indefinite' OR expires_at > ?)
GROUP BY service_account_id;

-- hikyo:authn-resolution
-- name: RevokeMachineCredential :execrows
UPDATE machine_credentials SET revoked_at = ?
WHERE id = ? AND service_account_id = ? AND revoked_at IS NULL;

-- hikyo:authn-resolution
-- name: RevokeAllMachineCredentials :execrows
UPDATE machine_credentials SET revoked_at = ?
WHERE service_account_id = ? AND revoked_at IS NULL;

-- last_used_at is observability, not authorization: nothing reads it to
-- decide anything, so it is the one machine-credential write that is not
-- part of a decision.
-- hikyo:authn-resolution
-- name: TouchMachineCredential :exec
UPDATE machine_credentials SET last_used_at = ? WHERE id = ?;

-- The clamp's enumeration: every live finite credential whose expiry is
-- beyond a proposed ceiling, listed to the actor BEFORE the change commits.
-- hikyo:authn-resolution
-- name: ListCredentialsBeyondCeiling :many
SELECT id, service_account_id, expires_at FROM machine_credentials
WHERE revoked_at IS NULL AND lifetime = 'finite' AND expires_at > ?
ORDER BY expires_at, id;

-- hikyo:authn-resolution
-- name: ListIndefiniteCredentials :many
SELECT id, service_account_id FROM machine_credentials
WHERE revoked_at IS NULL AND lifetime = 'indefinite'
ORDER BY id;

-- The clamp itself. It moves expiry DOWN to the new ceiling and never up: a
-- credential already inside the ceiling is untouched.
-- hikyo:authn-resolution
-- name: ClampCredentialExpiry :execrows
UPDATE machine_credentials SET expires_at = ?
WHERE revoked_at IS NULL AND lifetime = 'finite' AND expires_at > ?;

-- The policy row lock. A mint reads the ceiling and the cap and then
-- inserts; a tightening reads the affected set and then clamps. Without a
-- shared lock the two interleave and a credential is written under a
-- ceiling that no longer exists. sqlite's single writer serializes;
-- postgres takes FOR UPDATE.
-- hikyo:authn-resolution
-- name: LockCredentialPolicy :one
SELECT id FROM credential_policy WHERE id = 1;

-- Withdrawing the indefinite opt-in CLAMPS, it does not merely enumerate:
-- an unbounded credential surviving a withdrawal is the control not being
-- withdrawn. The typed lifetime moves with the instant, so the pair stays
-- total and the row is an ordinary finite credential afterwards.
-- hikyo:authn-resolution
-- name: ClampIndefiniteCredentials :execrows
UPDATE machine_credentials SET lifetime = 'finite', expires_at = ?
WHERE revoked_at IS NULL AND lifetime = 'indefinite';

-- hikyo:authn-resolution
-- name: GetCredentialPolicy :one
SELECT max_finite_lifetime_seconds, allow_indefinite, max_live_credentials, updated_at, updated_by
FROM credential_policy WHERE id = 1;

-- hikyo:authn-resolution
-- name: SetCredentialPolicy :exec
UPDATE credential_policy
SET max_finite_lifetime_seconds = ?, allow_indefinite = ?, max_live_credentials = ?,
    updated_at = ?, updated_by = ?
WHERE id = 1;

-- Deleting a service account releases its grants in the same transaction.
-- The origin rows go first (the FK is RESTRICT, deliberately), then the
-- grants themselves.
-- hikyo:authn-resolution
-- name: DeleteGrantOriginsForPrincipal :execrows
DELETE FROM grant_origins WHERE grant_id IN (SELECT id FROM grants WHERE principal_id = ?);

-- hikyo:authn-resolution
-- name: DeleteGrantsForPrincipal :execrows
DELETE FROM grants WHERE principal_id = ?;

-- hikyo:authn-resolution
-- name: DeletePrincipal :execrows
DELETE FROM principals WHERE id = ?;

-- The deleted service account's credential rows. The revoke ran first, so
-- the trail records the transition before the rows stop existing.
-- hikyo:authn-resolution
-- name: DeleteMachineCredentials :execrows
DELETE FROM machine_credentials WHERE service_account_id = ?;

-- The universe the mint and widen reachability computations range over. A
-- service account's grants are confined to its owning project's subtree, so
-- this project's environments ARE every environment its credentials reach.
-- hikyo:authn-resolution
-- name: ListEnvironmentIDsInProject :many
SELECT id FROM environments WHERE org_id = ? AND project_id = ? ORDER BY id;

-- Born reconciled to the current restore epoch, for the reason
-- InsertPrincipal states (#76).
-- hikyo:authn-resolution
-- name: InsertMachinePrincipal :exec
INSERT INTO principals (id, kind, class, session_generation, created_at, reconciled_epoch)
VALUES (?, 'machine', ?, 1, ?, (SELECT restore_epoch FROM auth_instance_state WHERE auth_instance_state.id = 1));
