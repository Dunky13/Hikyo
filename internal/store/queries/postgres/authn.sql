-- The authorization package's enumerated resolution surface (tenant-isolation
-- ADR bootstrap carve-out): the only statements that read chain tables with
-- request-supplied identifiers, because authorize() runs them to mint the
-- proof everything else requires. Each is annotated and content-pinned in the
-- allowlist fixture - drift fails the build until re-reviewed.

-- Chain resolution is one query, one round trip, regardless of which level
-- is missing: the denormalized chain columns plus composite ancestry FKs make
-- the addressed row's own chain authoritative, so no per-level walk exists.

-- hikyo:authn-resolution
-- name: ResolveOrgChain :one
SELECT id FROM orgs WHERE id = $1;

-- hikyo:authn-resolution
-- name: ResolveProjectChain :one
SELECT org_id, id FROM projects WHERE org_id = $1 AND id = $2;

-- hikyo:authn-resolution
-- name: ResolveEnvChain :one
SELECT org_id, project_id, id FROM environments
WHERE org_id = $1 AND project_id = $2 AND id = $3;

-- hikyo:authn-resolution
-- name: ListGrantsForPrincipal :many
SELECT capability, org_id, project_id, env_id FROM grants
WHERE principal_id = $1;

-- The denial writer's actor-class lookup (#45, audit-model ADR amendment
-- part 4): the flush transaction resolves the denied principal's kind for
-- the event's actor class. Runs only inside authn.WriteDenial.

-- hikyo:authn-resolution
-- name: GetPrincipalKind :one
SELECT kind FROM principals WHERE id = $1;

-- Human authentication (#47, human-auth ADR). These live in the resolution
-- surface for the same reason chain resolution does: deciding WHO a caller is
-- cannot run under a proof, because the proof is what the answer produces.
-- The write paths below are enumerated and pinned; anything else that mutates
-- inside this surface fails the sole-writer analyzer.

-- hikyo:authn-resolution
-- name: GetCredentialEpoch :one
SELECT credential_epoch FROM auth_instance_state WHERE id = 1;

-- hikyo:authn-resolution
-- name: GetAccountByUsername :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE username = $1;

-- hikyo:authn-resolution
-- name: GetAccountByID :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE id = $1;

-- hikyo:authn-resolution
-- name: GetAccountByPrincipal :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE principal_id = $1;

-- hikyo:authn-resolution
-- name: CountAccounts :one
SELECT COUNT(*) FROM accounts;

-- hikyo:authn-resolution
-- name: GetPasswordCredential :one
SELECT account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
       dek_version, credential_epoch, row_version, updated_at
FROM password_credentials WHERE account_id = $1;

-- hikyo:authn-resolution
-- name: GetPrincipalGeneration :one
SELECT session_generation FROM principals WHERE id = $1;

-- hikyo:authn-resolution
-- name: GetSessionByVerifier :one
SELECT id, principal_id, verifier, artifact, session_generation, credential_epoch,
       auth_method, factors, authenticated_at, ceremony_id, created_at,
       last_seen_at, idle_expires_at, absolute_expires_at, csrf_verifier
FROM sessions WHERE verifier = $1;

-- hikyo:authn-resolution
-- name: GetSessionByID :one
SELECT id, principal_id, artifact, session_generation, credential_epoch,
       auth_method, factors, authenticated_at, ceremony_id, created_at,
       last_seen_at, idle_expires_at, absolute_expires_at, csrf_verifier
FROM sessions WHERE id = $1;

-- hikyo:authn-resolution
-- name: GetCredentialAuthorityByVerifier :one
SELECT id, account_id, verifier, purpose, issued_by, credential_epoch, expires_at,
       consumed_at, created_at
FROM credential_authorities WHERE verifier = $1;

-- Enumerated writers.

-- hikyo:authn-resolution
-- name: InsertPrincipal :exec
INSERT INTO principals (id, kind, created_at, session_generation)
VALUES ($1, $2, $3, 1);

-- hikyo:authn-resolution
-- name: InsertAccount :exec
INSERT INTO accounts (id, principal_id, username, display_name, created_at)
VALUES ($1, $2, $3, $4, $5);

-- hikyo:authn-resolution
-- name: InsertGrant :exec
INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- hikyo:authn-resolution
-- name: InsertCredentialAuthority :exec
INSERT INTO credential_authorities
    (id, verifier, account_id, purpose, issued_by, credential_epoch, expires_at, consumed_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8);

-- Single-use consumption: the NULL guard is the atomic claim, so two
-- concurrent presentations cannot both establish a credential.
-- hikyo:authn-resolution
-- name: ConsumeCredentialAuthority :execrows
UPDATE credential_authorities SET consumed_at = $1
WHERE id = $2 AND consumed_at IS NULL;

-- hikyo:authn-resolution
-- name: InsertPasswordCredential :exec
INSERT INTO password_credentials
    (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
     dek_version, credential_epoch, row_version, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8);

-- Compare-and-swap on row_version: a resumable, lock-free `reencrypt` racing
-- a password reset would otherwise write the stale verifier back under the
-- new DEK version and silently resurrect a superseded password.
-- hikyo:authn-resolution
-- name: UpdatePasswordCredentialCAS :execrows
UPDATE password_credentials
SET verifier = $1, kdf_memory_kib = $2, kdf_time = $3, kdf_parallelism = $4,
    dek_version = $5, credential_epoch = $6, row_version = row_version + 1,
    updated_at = $7
WHERE account_id = $8 AND row_version = $9;

-- hikyo:authn-resolution
-- name: InsertSession :exec
INSERT INTO sessions
    (id, principal_id, verifier, artifact, session_generation, credential_epoch,
     auth_method, factors, authenticated_at, ceremony_id, created_at,
     last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent,
     provider_id, csrf_verifier)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18);

-- hikyo:authn-resolution
-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = $1, idle_expires_at = $2 WHERE id = $3;

-- hikyo:authn-resolution
-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- Every session of the principal dies, atomically and without reaching the
-- client  -  the invalidation that token rotation structurally cannot do.
-- hikyo:authn-resolution
-- name: DeleteSessionsForPrincipal :exec
DELETE FROM sessions WHERE principal_id = $1;

-- hikyo:authn-resolution
-- name: AdvancePrincipalGeneration :exec
UPDATE principals SET session_generation = session_generation + 1 WHERE id = $1;

-- Factors (#54, human-auth ADR). TOTP, recovery codes and the session-rotation
-- writers join the enumerated resolution surface for the same reason the login
-- writers did: they mutate the artifacts that decide how strongly a caller
-- authenticated, which is resolved rather than authorized.

-- hikyo:authn-resolution
-- name: GetConfirmedTOTPForAccount :one
SELECT id, account_id, seed, dek_version, credential_epoch, row_version,
       last_step, created_step, confirmed_at, created_at
FROM totp_credentials WHERE account_id = $1 AND confirmed_at IS NOT NULL;

-- hikyo:authn-resolution
-- name: GetPendingTOTPForAccount :one
SELECT id, account_id, seed, dek_version, credential_epoch, row_version,
       last_step, created_step, confirmed_at, created_at
FROM totp_credentials WHERE account_id = $1 AND confirmed_at IS NULL;

-- hikyo:authn-resolution
-- name: InsertTOTP :exec
INSERT INTO totp_credentials
    (id, account_id, seed, dek_version, credential_epoch, row_version,
     last_step, created_step, confirmed_at, created_at)
VALUES ($1, $2, $3, $4, $5, 1, $6, $7, NULL, $8);

-- Confirmation is the account-security mutation's write: it promotes the
-- pending seed and consumes the confirming step in one CAS.
-- hikyo:authn-resolution
-- name: ConfirmTOTP :execrows
UPDATE totp_credentials
SET confirmed_at = $1, last_step = $2, row_version = row_version + 1
WHERE id = $3 AND row_version = $4 AND confirmed_at IS NULL AND last_step < $5;

-- Single-use per (account, step): a code is consumed only if its step is
-- strictly beyond the last one, which the CAS enforces atomically.
-- hikyo:authn-resolution
-- name: AdvanceTOTPStep :execrows
UPDATE totp_credentials SET last_step = $1, row_version = row_version + 1
WHERE id = $2 AND row_version = $3 AND last_step < $4;

-- hikyo:authn-resolution
-- name: DeleteTOTPForAccount :exec
DELETE FROM totp_credentials WHERE account_id = $1;

-- hikyo:authn-resolution
-- name: DeletePendingTOTPForAccount :exec
DELETE FROM totp_credentials WHERE account_id = $1 AND confirmed_at IS NULL;

-- hikyo:authn-resolution
-- name: GetRecoveryCodes :one
SELECT account_id, batch, dek_version, credential_epoch, row_version, generated_at
FROM recovery_codes WHERE account_id = $1;

-- hikyo:authn-resolution
-- name: InsertRecoveryCodes :exec
INSERT INTO recovery_codes
    (account_id, batch, dek_version, credential_epoch, row_version, generated_at)
VALUES ($1, $2, $3, $4, 1, $5);

-- Regeneration and consumption both rewrite the batch under a CAS, so a
-- concurrent second presentation of the same code loses and fails closed.
-- hikyo:authn-resolution
-- name: UpdateRecoveryCodesCAS :execrows
UPDATE recovery_codes
SET batch = $1, dek_version = $2, credential_epoch = $3,
    row_version = row_version + 1, generated_at = $4
WHERE account_id = $5 AND row_version = $6;

-- Step-up rotates the session token and rewrites its factor set; the original
-- authenticated_at and ceremony_id are preserved so absolute-age attribution
-- cannot be reset by repeated step-ups.
-- hikyo:authn-resolution
-- name: RotateSessionFactors :exec
UPDATE sessions SET verifier = $1, factors = $2 WHERE id = $3;

-- Minting an establishment authority for an account consumes every other
-- outstanding one, so a second live reset token cannot linger past the point
-- the operator believes the flow completed.
-- hikyo:authn-resolution
-- name: ConsumeOutstandingAuthoritiesForAccount :exec
UPDATE credential_authorities SET consumed_at = $1
WHERE account_id = $2 AND consumed_at IS NULL;

-- OIDC login/link/reauth resolution (#54, human-auth ADR -- The OIDC
-- transaction). These read providers, transactions and external identities
-- with request-supplied identifiers, and write the transaction/identity/session
-- rows that decide who a caller is: the resolution surface, proof-free, for the
-- same reason the login writers are.

-- hikyo:authn-resolution
-- name: GetEnabledProviderByIssuer :one
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers WHERE kind = $1 AND issuer = $2 AND enabled = 1;

-- The recorded provider a callback exchanges at (A11): loaded by the id the
-- transaction pinned, so the exchange happens only at that provider.
-- hikyo:authn-resolution
-- name: GetProviderForCallback :one
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers WHERE id = $1;

-- hikyo:authn-resolution
-- name: InsertOIDCTransaction :exec
INSERT INTO oidc_transactions
    (id, state_verifier, nonce, pkce_verifier, provider_id, issuer, redirect_uri,
     purpose, binding_kind, initiating_session_id, browser_binding_verifier,
     account_id, environment_id, ceremony_id, credential_epoch, created_at,
     expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NULL);

-- hikyo:authn-resolution
-- name: GetOIDCTransactionByState :one
SELECT id, state_verifier, nonce, pkce_verifier, provider_id, issuer, redirect_uri,
       purpose, binding_kind, initiating_session_id, browser_binding_verifier,
       account_id, environment_id, ceremony_id, credential_epoch, created_at,
       expires_at, consumed_at
FROM oidc_transactions WHERE state_verifier = $1;

-- Single-use consumption: the NULL guard is the atomic claim, so a callback
-- cannot be replayed and two concurrent callbacks cannot both consume one tx.
-- hikyo:authn-resolution
-- name: ConsumeOIDCTransaction :execrows
UPDATE oidc_transactions SET consumed_at = $1
WHERE id = $2 AND consumed_at IS NULL;

-- hikyo:authn-resolution
-- name: GetExternalIdentity :one
SELECT id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at
FROM external_identities WHERE kind = $1 AND issuer = $2 AND subject = $3;

-- hikyo:authn-resolution
-- name: GetExternalIdentityByID :one
SELECT id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at
FROM external_identities WHERE id = $1;

-- hikyo:authn-resolution
-- name: ListExternalIdentitiesForAccount :many
SELECT id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at
FROM external_identities WHERE account_id = $1 ORDER BY created_at;

-- hikyo:authn-resolution
-- name: InsertExternalIdentity :exec
INSERT INTO external_identities
    (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- Re-adding the same byte-exact SAML entity creates a new provider row while
-- preserving the human link. The old provider id is a provenance CAS guard:
-- only the identity just verified by that entity may move to the live row.
-- hikyo:authn-resolution
-- name: RebindSAMLExternalIdentityProvider :execrows
UPDATE external_identities
SET provider_id = sqlc.arg(new_provider_id)
WHERE id = sqlc.arg(id)
  AND kind = 'saml'
  AND provider_id = sqlc.arg(expected_provider_id);

-- hikyo:authn-resolution
-- name: DeleteExternalIdentity :exec
DELETE FROM external_identities WHERE id = $1;

-- The federated-session sweep (A4): every session minted through a provider
-- dies when the provider's issuer/client/assurance policy changes or the
-- provider is disabled or deleted. reauth_windows cascade from the session.
-- hikyo:authn-resolution
-- name: DeleteSessionsForProvider :execrows
DELETE FROM sessions WHERE provider_id = $1;

-- A FRESH CEREMONY SUPERSEDES THE PAIR'S PREVIOUS WINDOW (#58).
--
-- The table holds AT MOST ONE window per (session, environment) and that
-- invariant is unchanged; what changes is that a fresh ceremony REPLACES the
-- pair's row instead of colliding with it. Without this the unique constraint
-- quietly meant "one window EVER per session and environment", which breaks the
-- reveal guard's own headline case: a protected environment is capped at 0, so
-- its disclosures are "a passkey ceremony per disclosure" (ceremony, disclose,
-- ceremony again) and the second ceremony hit the first window's spent row.
--
-- It is ONE atomic statement rather than a delete followed by an insert,
-- because two tabs finishing ceremonies at the same time are a real shape: on
-- postgres both deletes can miss the other transaction's not-yet-visible row
-- and the second insert then hits the unique constraint, turning a legitimate
-- supersede into an intermittent failure. `ON CONFLICT DO UPDATE` makes the
-- loser update instead of fail.
--
-- consumed_at resets to NULL because the row now describes the NEW ceremony,
-- which nothing has spent.
-- hikyo:authn-resolution
-- name: InsertReauthWindow :exec
INSERT INTO reauth_windows
    (id, session_id, environment_id, ceremony_id, factor_class, single_decision,
     authenticated_at, window_expires_at, hard_expires_at, credential_epoch,
     consumed_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11)
ON CONFLICT (session_id, environment_id) DO UPDATE SET
    id = excluded.id,
    ceremony_id = excluded.ceremony_id,
    factor_class = excluded.factor_class,
    single_decision = excluded.single_decision,
    authenticated_at = excluded.authenticated_at,
    window_expires_at = excluded.window_expires_at,
    hard_expires_at = excluded.hard_expires_at,
    credential_epoch = excluded.credential_epoch,
    consumed_at = NULL,
    created_at = excluded.created_at;



-- Start resolves the provider by slug for an enabled provider only: a login,
-- link or reauth may only begin against a provider that is currently serving.
-- hikyo:authn-resolution
-- name: GetEnabledProviderBySlug :one
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers WHERE slug = $1 AND enabled = 1;

-- Reauth-window consumption at disclosure (#54, human-auth ADR - Reauthentication).
-- A disclosure on environment E requires a live window for (session, E). These
-- read the window, slide its sliding clock (never past the hard cap the service
-- enforces), and claim a single_decision window exactly once via the consumed_at
-- NULL guard. There is no reveal operation to call these yet (#50/#58); they ship
-- as the library those verticals consume, exercised directly by fixtures.
-- hikyo:authn-resolution
-- name: GetReauthWindow :one
SELECT id, session_id, environment_id, ceremony_id, factor_class, single_decision,
       authenticated_at, window_expires_at, hard_expires_at, credential_epoch,
       consumed_at, created_at
FROM reauth_windows WHERE session_id = $1 AND environment_id = $2;

-- Slide the idle window clock on a sliding (non single-decision) window. The hard
-- cap is enforced by the service, which passes min(now+window, hard_expires_at);
-- the NULL guard keeps a concurrently-claimed window from sliding.
-- hikyo:authn-resolution
-- name: SlideReauthWindow :execrows
UPDATE reauth_windows SET window_expires_at = $1
WHERE id = $2 AND single_decision = 0 AND consumed_at IS NULL;

-- Claim a single_decision window exactly once: the NULL guard is the atomic
-- claim, so a second disclosure loses and is refused (B11 double-spend).
-- hikyo:authn-resolution
-- name: ConsumeSingleDecisionWindow :execrows
UPDATE reauth_windows SET consumed_at = $1
WHERE id = $2 AND single_decision = 1 AND consumed_at IS NULL;

-- Invalidate every open window on one environment: the first of LowerEffective
-- Window's five ADR items on the effective-window transition (#54 B6).
-- hikyo:authn-resolution
-- name: DeleteReauthWindowsForEnvironment :execrows
DELETE FROM reauth_windows WHERE environment_id = $1;

-- Stranded-principal enumeration for LowerEffectiveWindow (#54 B6): principals
-- holding reveal/reveal-history covering environment E (a grant at E, its project,
-- its org, or the instance) who have no enabled WebAuthn authenticator, so a 0
-- effective window fails their disclosure closed until they enrol one.
-- hikyo:authn-resolution
-- name: StrandedRevealPrincipalsForEnvironment :many
SELECT DISTINCT g.principal_id
FROM grants g
WHERE g.capability IN ('reveal', 'reveal-history')
  AND (g.org_id IS NULL
       OR (g.org_id = sqlc.arg(org) AND g.project_id IS NULL)
       OR (g.org_id = sqlc.arg(org) AND g.project_id = sqlc.arg(project) AND g.env_id IS NULL)
       OR (g.org_id = sqlc.arg(org) AND g.project_id = sqlc.arg(project) AND g.env_id = sqlc.arg(env)))
  AND NOT EXISTS (
      SELECT 1 FROM webauthn_credentials w
      JOIN accounts a ON a.id = w.account_id
      WHERE a.principal_id = g.principal_id AND w.disabled_at IS NULL);

-- The target principal's grant set, for the credential-reset org-bounded test
-- (#54 credential-reset, ADR - Recovery): reset reaches only a target whose grants
-- lie entirely within one org and who holds no instance capability.
-- hikyo:authn-resolution
-- name: ListGrantsForResetTarget :many
SELECT capability, org_id, project_id, env_id FROM grants
WHERE principal_id = $1;

-- Principal row lock (#54 B14): every grant writer takes it so the credential-
-- reset org-bounded test serializes against a concurrent grant landing. sqlite's
-- single writer serializes trivially; postgres takes FOR UPDATE. The grant-lock
-- analyzer pins that this sits inside every grant writer.
-- hikyo:authn-resolution
-- name: LockPrincipalRow :one
SELECT id FROM principals WHERE id = $1 FOR UPDATE;

-- Resolve an environment's chain from its id alone, for LowerEffectiveWindow's
-- stranded-principal query (#54 B6): the denormalized chain columns make the row
-- self-describing, so the grant-coverage predicate can be built from an env id.
-- hikyo:authn-resolution
-- name: EnvironmentChainByID :one
SELECT org_id, project_id, id FROM environments WHERE id = $1;

-- The org rail's identity lookup (#56). The caller's own org set is projected
-- from their own grant rows, so there is no scope to authorize against and no
-- proof to bind: the projection IS the authorization, and it can name only
-- organisations the caller already holds a grant in. Identity only - an org's
-- metadata and active flag are operator-set state and are read through the
-- proof-gated GetOrg.
--
-- Not annotated, and it does not need to be: orgs is class=org chain=id, and
-- the id equality is that chain as a top-level conjunct.
-- name: GetOrgIdentity :one
SELECT id, name FROM orgs WHERE id = $1;
