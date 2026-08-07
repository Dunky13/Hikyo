-- The authorization package's enumerated resolution surface (tenant-isolation
-- ADR bootstrap carve-out): the only statements that read chain tables with
-- request-supplied identifiers, because authorize() runs them to mint the
-- proof everything else requires. Each is annotated and content-pinned in the
-- allowlist fixture - drift fails the build until re-reviewed.

-- Chain resolution is one query, one round trip, regardless of which level
-- is missing: the denormalized chain columns plus composite ancestry FKs make
-- the addressed row's own chain authoritative, so no per-level walk exists.

-- wenv:authn-resolution
-- name: ResolveOrgChain :one
SELECT id FROM orgs WHERE id = ?;

-- wenv:authn-resolution
-- name: ResolveProjectChain :one
SELECT org_id, id FROM projects WHERE org_id = ? AND id = ?;

-- wenv:authn-resolution
-- name: ResolveEnvChain :one
SELECT org_id, project_id, id FROM environments
WHERE org_id = ? AND project_id = ? AND id = ?;

-- wenv:authn-resolution
-- name: ListGrantsForPrincipal :many
SELECT capability, org_id, project_id, env_id FROM grants
WHERE principal_id = ?;

-- The denial writer's actor-class lookup (#45, audit-model ADR amendment
-- part 4): the flush transaction resolves the denied principal's kind for
-- the event's actor class. Runs only inside authn.WriteDenial.

-- wenv:authn-resolution
-- name: GetPrincipalKind :one
SELECT kind FROM principals WHERE id = ?;

-- Human authentication (#47, human-auth ADR). These live in the resolution
-- surface for the same reason chain resolution does: deciding WHO a caller is
-- cannot run under a proof, because the proof is what the answer produces.
-- The write paths below are enumerated and pinned; anything else that mutates
-- inside this surface fails the sole-writer analyzer.

-- wenv:authn-resolution
-- name: GetCredentialEpoch :one
SELECT credential_epoch FROM auth_instance_state WHERE id = 1;

-- wenv:authn-resolution
-- name: GetAccountByUsername :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE username = ?;

-- wenv:authn-resolution
-- name: GetAccountByID :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE id = ?;

-- wenv:authn-resolution
-- name: CountAccounts :one
SELECT COUNT(*) FROM accounts;

-- wenv:authn-resolution
-- name: GetPasswordCredential :one
SELECT account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
       dek_version, credential_epoch, row_version, updated_at
FROM password_credentials WHERE account_id = ?;

-- wenv:authn-resolution
-- name: GetPrincipalGeneration :one
SELECT session_generation FROM principals WHERE id = ?;

-- wenv:authn-resolution
-- name: GetSessionByVerifier :one
SELECT id, principal_id, artifact, session_generation, credential_epoch,
       auth_method, factors, authenticated_at, ceremony_id, created_at,
       last_seen_at, idle_expires_at, absolute_expires_at
FROM sessions WHERE verifier = ?;

-- wenv:authn-resolution
-- name: GetCredentialAuthorityByVerifier :one
SELECT id, account_id, purpose, issued_by, credential_epoch, expires_at,
       consumed_at, created_at
FROM credential_authorities WHERE verifier = ?;

-- Enumerated writers.

-- wenv:authn-resolution
-- name: InsertPrincipal :exec
INSERT INTO principals (id, kind, created_at, session_generation)
VALUES (?, ?, ?, 1);

-- wenv:authn-resolution
-- name: InsertAccount :exec
INSERT INTO accounts (id, principal_id, username, display_name, created_at)
VALUES (?, ?, ?, ?, ?);

-- wenv:authn-resolution
-- name: InsertGrant :exec
INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- wenv:authn-resolution
-- name: InsertCredentialAuthority :exec
INSERT INTO credential_authorities
    (id, verifier, account_id, purpose, issued_by, credential_epoch, expires_at, consumed_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?);

-- Single-use consumption: the NULL guard is the atomic claim, so two
-- concurrent presentations cannot both establish a credential.
-- wenv:authn-resolution
-- name: ConsumeCredentialAuthority :execrows
UPDATE credential_authorities SET consumed_at = ?
WHERE id = ? AND consumed_at IS NULL;

-- wenv:authn-resolution
-- name: InsertPasswordCredential :exec
INSERT INTO password_credentials
    (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
     dek_version, credential_epoch, row_version, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?);

-- Compare-and-swap on row_version: a resumable, lock-free `reencrypt` racing
-- a password reset would otherwise write the stale verifier back under the
-- new DEK version and silently resurrect a superseded password.
-- wenv:authn-resolution
-- name: UpdatePasswordCredentialCAS :execrows
UPDATE password_credentials
SET verifier = ?, kdf_memory_kib = ?, kdf_time = ?, kdf_parallelism = ?,
    dek_version = ?, credential_epoch = ?, row_version = row_version + 1,
    updated_at = ?
WHERE account_id = ? AND row_version = ?;

-- wenv:authn-resolution
-- name: InsertSession :exec
INSERT INTO sessions
    (id, principal_id, verifier, artifact, session_generation, credential_epoch,
     auth_method, factors, authenticated_at, ceremony_id, created_at,
     last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- wenv:authn-resolution
-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?;

-- wenv:authn-resolution
-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;

-- Every session of the principal dies, atomically and without reaching the
-- client  -  the invalidation that token rotation structurally cannot do.
-- wenv:authn-resolution
-- name: DeleteSessionsForPrincipal :exec
DELETE FROM sessions WHERE principal_id = ?;

-- wenv:authn-resolution
-- name: AdvancePrincipalGeneration :exec
UPDATE principals SET session_generation = session_generation + 1 WHERE id = ?;
