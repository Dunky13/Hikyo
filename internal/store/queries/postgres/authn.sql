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
SELECT id FROM orgs WHERE id = $1;

-- wenv:authn-resolution
-- name: ResolveProjectChain :one
SELECT org_id, id FROM projects WHERE org_id = $1 AND id = $2;

-- wenv:authn-resolution
-- name: ResolveEnvChain :one
SELECT org_id, project_id, id FROM environments
WHERE org_id = $1 AND project_id = $2 AND id = $3;

-- wenv:authn-resolution
-- name: ListGrantsForPrincipal :many
SELECT capability, org_id, project_id, env_id FROM grants
WHERE principal_id = $1;

-- The denial writer's actor-class lookup (#45, audit-model ADR amendment
-- part 4): the flush transaction resolves the denied principal's kind for
-- the event's actor class. Runs only inside authn.WriteDenial.

-- wenv:authn-resolution
-- name: GetPrincipalKind :one
SELECT kind FROM principals WHERE id = $1;

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
WHERE username = $1;

-- wenv:authn-resolution
-- name: GetAccountByID :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE id = $1;

-- wenv:authn-resolution
-- name: GetAccountByPrincipal :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE principal_id = $1;

-- wenv:authn-resolution
-- name: CountAccounts :one
SELECT COUNT(*) FROM accounts;

-- wenv:authn-resolution
-- name: GetPasswordCredential :one
SELECT account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
       dek_version, credential_epoch, row_version, updated_at
FROM password_credentials WHERE account_id = $1;

-- wenv:authn-resolution
-- name: GetPrincipalGeneration :one
SELECT session_generation FROM principals WHERE id = $1;

-- wenv:authn-resolution
-- name: GetSessionByVerifier :one
SELECT id, principal_id, artifact, session_generation, credential_epoch,
       auth_method, factors, authenticated_at, ceremony_id, created_at,
       last_seen_at, idle_expires_at, absolute_expires_at
FROM sessions WHERE verifier = $1;

-- wenv:authn-resolution
-- name: GetCredentialAuthorityByVerifier :one
SELECT id, account_id, purpose, issued_by, credential_epoch, expires_at,
       consumed_at, created_at
FROM credential_authorities WHERE verifier = $1;

-- Enumerated writers.

-- wenv:authn-resolution
-- name: InsertPrincipal :exec
INSERT INTO principals (id, kind, created_at, session_generation)
VALUES ($1, $2, $3, 1);

-- wenv:authn-resolution
-- name: InsertAccount :exec
INSERT INTO accounts (id, principal_id, username, display_name, created_at)
VALUES ($1, $2, $3, $4, $5);

-- wenv:authn-resolution
-- name: InsertGrant :exec
INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- wenv:authn-resolution
-- name: InsertCredentialAuthority :exec
INSERT INTO credential_authorities
    (id, verifier, account_id, purpose, issued_by, credential_epoch, expires_at, consumed_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8);

-- Single-use consumption: the NULL guard is the atomic claim, so two
-- concurrent presentations cannot both establish a credential.
-- wenv:authn-resolution
-- name: ConsumeCredentialAuthority :execrows
UPDATE credential_authorities SET consumed_at = $1
WHERE id = $2 AND consumed_at IS NULL;

-- wenv:authn-resolution
-- name: InsertPasswordCredential :exec
INSERT INTO password_credentials
    (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
     dek_version, credential_epoch, row_version, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8);

-- Compare-and-swap on row_version: a resumable, lock-free `reencrypt` racing
-- a password reset would otherwise write the stale verifier back under the
-- new DEK version and silently resurrect a superseded password.
-- wenv:authn-resolution
-- name: UpdatePasswordCredentialCAS :execrows
UPDATE password_credentials
SET verifier = $1, kdf_memory_kib = $2, kdf_time = $3, kdf_parallelism = $4,
    dek_version = $5, credential_epoch = $6, row_version = row_version + 1,
    updated_at = $7
WHERE account_id = $8 AND row_version = $9;

-- wenv:authn-resolution
-- name: InsertSession :exec
INSERT INTO sessions
    (id, principal_id, verifier, artifact, session_generation, credential_epoch,
     auth_method, factors, authenticated_at, ceremony_id, created_at,
     last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16);

-- wenv:authn-resolution
-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = $1, idle_expires_at = $2 WHERE id = $3;

-- wenv:authn-resolution
-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- Every session of the principal dies, atomically and without reaching the
-- client  -  the invalidation that token rotation structurally cannot do.
-- wenv:authn-resolution
-- name: DeleteSessionsForPrincipal :exec
DELETE FROM sessions WHERE principal_id = $1;

-- wenv:authn-resolution
-- name: AdvancePrincipalGeneration :exec
UPDATE principals SET session_generation = session_generation + 1 WHERE id = $1;

-- Factors (#54, human-auth ADR). TOTP, recovery codes and the session-rotation
-- writers join the enumerated resolution surface for the same reason the login
-- writers did: they mutate the artifacts that decide how strongly a caller
-- authenticated, which is resolved rather than authorized.

-- wenv:authn-resolution
-- name: GetConfirmedTOTPForAccount :one
SELECT id, account_id, seed, dek_version, credential_epoch, row_version,
       last_step, created_step, confirmed_at, created_at
FROM totp_credentials WHERE account_id = $1 AND confirmed_at IS NOT NULL;

-- wenv:authn-resolution
-- name: GetPendingTOTPForAccount :one
SELECT id, account_id, seed, dek_version, credential_epoch, row_version,
       last_step, created_step, confirmed_at, created_at
FROM totp_credentials WHERE account_id = $1 AND confirmed_at IS NULL;

-- wenv:authn-resolution
-- name: InsertTOTP :exec
INSERT INTO totp_credentials
    (id, account_id, seed, dek_version, credential_epoch, row_version,
     last_step, created_step, confirmed_at, created_at)
VALUES ($1, $2, $3, $4, $5, 1, $6, $7, NULL, $8);

-- Confirmation is the account-security mutation's write: it promotes the
-- pending seed and consumes the confirming step in one CAS.
-- wenv:authn-resolution
-- name: ConfirmTOTP :execrows
UPDATE totp_credentials
SET confirmed_at = $1, last_step = $2, row_version = row_version + 1
WHERE id = $3 AND row_version = $4 AND confirmed_at IS NULL AND last_step < $5;

-- Single-use per (account, step): a code is consumed only if its step is
-- strictly beyond the last one, which the CAS enforces atomically.
-- wenv:authn-resolution
-- name: AdvanceTOTPStep :execrows
UPDATE totp_credentials SET last_step = $1, row_version = row_version + 1
WHERE id = $2 AND row_version = $3 AND last_step < $4;

-- wenv:authn-resolution
-- name: DeleteTOTPForAccount :exec
DELETE FROM totp_credentials WHERE account_id = $1;

-- wenv:authn-resolution
-- name: DeletePendingTOTPForAccount :exec
DELETE FROM totp_credentials WHERE account_id = $1 AND confirmed_at IS NULL;

-- wenv:authn-resolution
-- name: GetRecoveryCodes :one
SELECT account_id, batch, dek_version, credential_epoch, row_version, generated_at
FROM recovery_codes WHERE account_id = $1;

-- wenv:authn-resolution
-- name: InsertRecoveryCodes :exec
INSERT INTO recovery_codes
    (account_id, batch, dek_version, credential_epoch, row_version, generated_at)
VALUES ($1, $2, $3, $4, 1, $5);

-- Regeneration and consumption both rewrite the batch under a CAS, so a
-- concurrent second presentation of the same code loses and fails closed.
-- wenv:authn-resolution
-- name: UpdateRecoveryCodesCAS :execrows
UPDATE recovery_codes
SET batch = $1, dek_version = $2, credential_epoch = $3,
    row_version = row_version + 1, generated_at = $4
WHERE account_id = $5 AND row_version = $6;

-- Step-up rotates the session token and rewrites its factor set; the original
-- authenticated_at and ceremony_id are preserved so absolute-age attribution
-- cannot be reset by repeated step-ups.
-- wenv:authn-resolution
-- name: RotateSessionFactors :exec
UPDATE sessions SET verifier = $1, factors = $2 WHERE id = $3;

-- Minting an establishment authority for an account consumes every other
-- outstanding one, so a second live reset token cannot linger past the point
-- the operator believes the flow completed.
-- wenv:authn-resolution
-- name: ConsumeOutstandingAuthoritiesForAccount :exec
UPDATE credential_authorities SET consumed_at = $1
WHERE account_id = $2 AND consumed_at IS NULL;
