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
SELECT id FROM orgs WHERE id = ?;

-- hikyo:authn-resolution
-- name: ResolveProjectChain :one
SELECT org_id, id FROM projects WHERE org_id = ? AND id = ?;

-- hikyo:authn-resolution
-- name: ResolveEnvChain :one
SELECT org_id, project_id, id FROM environments
WHERE org_id = ? AND project_id = ? AND id = ?;

-- The grant lookup authorize() makes, carrying the restore-reconciliation
-- gate (#76): after a restore, a principal's grants do not authorize until an
-- operator reconciles that principal up to the restore epoch. The gate is a
-- conjunct of the SAME query rather than a second read, so no caller can
-- forget it and the pinned query count is unchanged. Never restored means
-- restore_epoch = 0, which every principal's default already satisfies.
-- hikyo:authn-resolution
-- name: ListGrantsForPrincipal :many
SELECT g.capability, g.org_id, g.project_id, g.env_id FROM grants AS g
JOIN principals AS p ON p.id = g.principal_id
WHERE g.principal_id = ?
  AND p.reconciled_epoch >= (SELECT restore_epoch FROM auth_instance_state WHERE auth_instance_state.id = 1);

-- The denial writer's actor-class lookup (#45, audit-model ADR amendment
-- part 4): the flush transaction resolves the denied principal's kind for
-- the event's actor class. Runs only inside authn.WriteDenial.

-- hikyo:authn-resolution
-- name: GetPrincipalKind :one
SELECT kind FROM principals WHERE id = ?;

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
WHERE username = ?;

-- hikyo:authn-resolution
-- name: GetAccountByID :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE id = ?;

-- hikyo:authn-resolution
-- name: GetAccountByPrincipal :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE principal_id = ?;

-- hikyo:authn-resolution
-- name: CountAccounts :one
SELECT COUNT(*) FROM accounts;

-- hikyo:authn-resolution
-- name: GetPasswordCredential :one
SELECT account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
       dek_version, credential_epoch, row_version, updated_at
FROM password_credentials WHERE account_id = ?;

-- hikyo:authn-resolution
-- name: GetPrincipalGeneration :one
SELECT session_generation FROM principals WHERE id = ?;

-- hikyo:authn-resolution
-- name: GetSessionByVerifier :one
SELECT id, principal_id, verifier, artifact, session_generation, credential_epoch,
       auth_method, factors, authenticated_at, ceremony_id, created_at,
       last_seen_at, idle_expires_at, absolute_expires_at, csrf_verifier,
       requesting_origin
FROM sessions WHERE verifier = ?;

-- hikyo:authn-resolution
-- name: GetSessionByID :one
SELECT id, principal_id, artifact, session_generation, credential_epoch,
       auth_method, factors, authenticated_at, ceremony_id, created_at,
       last_seen_at, idle_expires_at, absolute_expires_at, csrf_verifier,
       requesting_origin
FROM sessions WHERE id = ?;

-- hikyo:authn-resolution
-- name: GetCredentialAuthorityByVerifier :one
SELECT id, account_id, verifier, purpose, issued_by, credential_epoch, expires_at,
       consumed_at, created_at
FROM credential_authorities WHERE verifier = ?;

-- Enumerated writers.

-- A principal is born reconciled to the CURRENT restore epoch (#76): it
-- postdates the restore, so there is nothing about it to reconcile, and a
-- literal default of zero would make every principal created after a restore
-- inert until somebody reconciled a principal that never existed before it.
-- hikyo:authn-resolution
-- name: InsertPrincipal :exec
INSERT INTO principals (id, kind, created_at, session_generation, reconciled_epoch)
VALUES (?, ?, ?, 1, (SELECT restore_epoch FROM auth_instance_state WHERE auth_instance_state.id = 1));

-- hikyo:authn-resolution
-- name: InsertAccount :exec
INSERT INTO accounts (id, principal_id, username, display_name, created_at)
VALUES (?, ?, ?, ?, ?);

-- hikyo:authn-resolution
-- name: InsertGrant :exec
INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- hikyo:authn-resolution
-- name: InsertCredentialAuthority :exec
INSERT INTO credential_authorities
    (id, verifier, account_id, purpose, issued_by, credential_epoch, expires_at, consumed_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?);

-- Single-use consumption: the NULL guard is the atomic claim, so two
-- concurrent presentations cannot both establish a credential.
-- hikyo:authn-resolution
-- name: ConsumeCredentialAuthority :execrows
UPDATE credential_authorities SET consumed_at = ?
WHERE id = ? AND consumed_at IS NULL;

-- hikyo:authn-resolution
-- name: InsertPasswordCredential :exec
INSERT INTO password_credentials
    (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism,
     dek_version, credential_epoch, row_version, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?);

-- Compare-and-swap on row_version: a resumable, lock-free `reencrypt` racing
-- a password reset would otherwise write the stale verifier back under the
-- new DEK version and silently resurrect a superseded password.
-- hikyo:authn-resolution
-- name: UpdatePasswordCredentialCAS :execrows
UPDATE password_credentials
SET verifier = ?, kdf_memory_kib = ?, kdf_time = ?, kdf_parallelism = ?,
    dek_version = ?, credential_epoch = ?, row_version = row_version + 1,
    updated_at = ?
WHERE account_id = ? AND row_version = ?;

-- One insert for every session artifact, including the workspace session
-- (#71). requesting_origin and handoff_id are NULL for cli and browser rows
-- and NOT NULL for a workspace row; the table CHECK ties them to the artifact,
-- so a second insert statement for the workspace case would buy nothing but a
-- second place for the pairing to drift.
-- hikyo:authn-resolution
-- name: InsertSession :exec
INSERT INTO sessions
    (id, principal_id, verifier, artifact, session_generation, credential_epoch,
     auth_method, factors, authenticated_at, ceremony_id, created_at,
     last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent,
     provider_id, csrf_verifier, requesting_origin, handoff_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- The active-session listing (#71 criterion 5). A workspace session appears
-- here as its own artifact type, beside the cli and browser rows, which is the
-- ADR's requirement and the reason it is a `sessions` row at all. Metadata
-- only: no verifier is selected, here or anywhere.
-- hikyo:authn-resolution
-- name: ListSessionsForPrincipal :many
SELECT id, artifact, auth_method, factors, authenticated_at, created_at,
       last_seen_at, idle_expires_at, absolute_expires_at, source_ip,
       user_agent, requesting_origin, handoff_id
FROM sessions WHERE principal_id = ? ORDER BY created_at, id;

-- Self-scoped revocation: the principal conjunct is what makes one caller
-- unable to revoke another's session by guessing an id, and it is why the
-- statement reports rows affected rather than succeeding silently.
-- hikyo:authn-resolution
-- name: DeleteSessionForPrincipal :execrows
DELETE FROM sessions WHERE id = ? AND principal_id = ?;

-- The origin kill switch (#71). Removing an origin from the allowlist
-- atomically revokes every workspace session bound to it -- ONE statement over
-- one indexed column, in the same transaction as the allowlist delete, which
-- is what makes de-allowlisting a real kill switch rather than a headers
-- change. Only workspace rows carry a requesting_origin, so no cli or browser
-- session can be caught by it.
-- hikyo:authn-resolution
-- name: DeleteSessionsForOrigin :execrows
DELETE FROM sessions WHERE requesting_origin = ?;

-- hikyo:authn-resolution
-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?;

-- hikyo:authn-resolution
-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = ?;

-- Every session of the principal dies, atomically and without reaching the
-- client  -  the invalidation that token rotation structurally cannot do.
-- hikyo:authn-resolution
-- name: DeleteSessionsForPrincipal :exec
DELETE FROM sessions WHERE principal_id = ?;

-- hikyo:authn-resolution
-- name: AdvancePrincipalGeneration :exec
UPDATE principals SET session_generation = session_generation + 1 WHERE id = ?;

-- Factors (#54, human-auth ADR). TOTP, recovery codes and the session-rotation
-- writers join the enumerated resolution surface for the same reason the login
-- writers did: they mutate the artifacts that decide how strongly a caller
-- authenticated, which is resolved rather than authorized.

-- hikyo:authn-resolution
-- name: GetConfirmedTOTPForAccount :one
SELECT id, account_id, seed, dek_version, credential_epoch, row_version,
       last_step, created_step, confirmed_at, created_at
FROM totp_credentials WHERE account_id = ? AND confirmed_at IS NOT NULL;

-- hikyo:authn-resolution
-- name: GetPendingTOTPForAccount :one
SELECT id, account_id, seed, dek_version, credential_epoch, row_version,
       last_step, created_step, confirmed_at, created_at
FROM totp_credentials WHERE account_id = ? AND confirmed_at IS NULL;

-- hikyo:authn-resolution
-- name: InsertTOTP :exec
INSERT INTO totp_credentials
    (id, account_id, seed, dek_version, credential_epoch, row_version,
     last_step, created_step, confirmed_at, created_at)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, NULL, ?);

-- Confirmation is the account-security mutation's write: it promotes the
-- pending seed and consumes the confirming step in one CAS.
-- hikyo:authn-resolution
-- name: ConfirmTOTP :execrows
UPDATE totp_credentials
SET confirmed_at = ?, last_step = ?, row_version = row_version + 1
WHERE id = ? AND row_version = ? AND confirmed_at IS NULL AND last_step < ?;

-- Single-use per (account, step): a code is consumed only if its step is
-- strictly beyond the last one, which the CAS enforces atomically.
-- hikyo:authn-resolution
-- name: AdvanceTOTPStep :execrows
UPDATE totp_credentials SET last_step = ?, row_version = row_version + 1
WHERE id = ? AND row_version = ? AND last_step < ?;

-- hikyo:authn-resolution
-- name: DeleteTOTPForAccount :exec
DELETE FROM totp_credentials WHERE account_id = ?;

-- hikyo:authn-resolution
-- name: DeletePendingTOTPForAccount :exec
DELETE FROM totp_credentials WHERE account_id = ? AND confirmed_at IS NULL;

-- hikyo:authn-resolution
-- name: GetRecoveryCodes :one
SELECT account_id, batch, dek_version, credential_epoch, row_version, generated_at
FROM recovery_codes WHERE account_id = ?;

-- hikyo:authn-resolution
-- name: InsertRecoveryCodes :exec
INSERT INTO recovery_codes
    (account_id, batch, dek_version, credential_epoch, row_version, generated_at)
VALUES (?, ?, ?, ?, 1, ?);

-- Regeneration and consumption both rewrite the batch under a CAS, so a
-- concurrent second presentation of the same code loses and fails closed.
-- hikyo:authn-resolution
-- name: UpdateRecoveryCodesCAS :execrows
UPDATE recovery_codes
SET batch = ?, dek_version = ?, credential_epoch = ?,
    row_version = row_version + 1, generated_at = ?
WHERE account_id = ? AND row_version = ?;

-- Step-up rotates the session token and rewrites its factor set; the original
-- authenticated_at and ceremony_id are preserved so absolute-age attribution
-- cannot be reset by repeated step-ups.
-- hikyo:authn-resolution
-- name: RotateSessionFactors :exec
UPDATE sessions SET verifier = ?, factors = ? WHERE id = ?;

-- Minting an establishment authority for an account consumes every other
-- outstanding one, so a second live reset token cannot linger past the point
-- the operator believes the flow completed.
-- hikyo:authn-resolution
-- name: ConsumeOutstandingAuthoritiesForAccount :exec
UPDATE credential_authorities SET consumed_at = ?
WHERE account_id = ? AND consumed_at IS NULL;

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
FROM oidc_providers WHERE kind = ? AND issuer = ? AND enabled = 1;

-- The recorded provider a callback exchanges at (A11): loaded by the id the
-- transaction pinned, so the exchange happens only at that provider.
-- hikyo:authn-resolution
-- name: GetProviderForCallback :one
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers WHERE id = ?;

-- hikyo:authn-resolution
-- name: InsertOIDCTransaction :exec
INSERT INTO oidc_transactions
    (id, state_verifier, nonce, pkce_verifier, provider_id, issuer, redirect_uri,
     purpose, binding_kind, initiating_session_id, browser_binding_verifier,
     account_id, environment_id, ceremony_id, credential_epoch, created_at,
     expires_at, consumed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);

-- hikyo:authn-resolution
-- name: GetOIDCTransactionByState :one
SELECT id, state_verifier, nonce, pkce_verifier, provider_id, issuer, redirect_uri,
       purpose, binding_kind, initiating_session_id, browser_binding_verifier,
       account_id, environment_id, ceremony_id, credential_epoch, created_at,
       expires_at, consumed_at
FROM oidc_transactions WHERE state_verifier = ?;

-- Single-use consumption: the NULL guard is the atomic claim, so a callback
-- cannot be replayed and two concurrent callbacks cannot both consume one tx.
-- hikyo:authn-resolution
-- name: ConsumeOIDCTransaction :execrows
UPDATE oidc_transactions SET consumed_at = ?
WHERE id = ? AND consumed_at IS NULL;

-- hikyo:authn-resolution
-- name: GetExternalIdentity :one
SELECT id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at
FROM external_identities WHERE kind = ? AND issuer = ? AND subject = ?;

-- hikyo:authn-resolution
-- name: GetExternalIdentityByID :one
SELECT id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at
FROM external_identities WHERE id = ?;

-- hikyo:authn-resolution
-- name: ListExternalIdentitiesForAccount :many
SELECT id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at
FROM external_identities WHERE account_id = ? ORDER BY created_at;

-- hikyo:authn-resolution
-- name: InsertExternalIdentity :exec
INSERT INTO external_identities
    (id, account_id, kind, issuer, subject, provider_id, credential_epoch, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

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
DELETE FROM external_identities WHERE id = ?;

-- The federated-session sweep (A4): every session minted through a provider
-- dies when the provider's issuer/client/assurance policy changes or the
-- provider is disabled or deleted. reauth_windows cascade from the session.
-- hikyo:authn-resolution
-- name: DeleteSessionsForProvider :execrows
DELETE FROM sessions WHERE provider_id = ?;

-- A FRESH CEREMONY SUPERSEDES THE PAIR'S PREVIOUS WINDOW (#58).
--
-- The table holds AT MOST ONE window per (session, environment) and that
-- invariant is unchanged; what changes is that a fresh ceremony REPLACES the
-- pair's row instead of colliding with it. Without this the unique constraint
-- quietly meant "one window EVER per session and environment", which breaks the
-- reveal guard's own headline case: a protected environment is capped at 0, so
-- its disclosures are "a passkey ceremony per disclosure" (ceremony, disclose,
-- ceremony again) and the second ceremony hit the first window's spent row.
-- The same fault bit every opener, including a workspace step-up (#71)
-- repeated on one environment, so the fix is shared by all of them.
--
-- It is ONE atomic statement rather than a delete followed by an insert,
-- because two tabs finishing ceremonies at the same time are a real shape: on
-- postgres both deletes can miss the other transaction's not-yet-visible row
-- and the second insert then hits the unique constraint, turning a legitimate
-- supersede into an intermittent failure. `ON CONFLICT DO UPDATE` makes the
-- loser update instead of fail.
--
-- consumed_at resets to NULL because the row now describes the NEW ceremony,
-- which nothing has spent. bound_operation and bound_key_set (#71) carry a
-- workspace step-up's exact-consent binding; the human openers write NULLs.
-- hikyo:authn-resolution
-- name: InsertReauthWindow :exec
INSERT INTO reauth_windows
    (id, session_id, environment_id, ceremony_id, factor_class, single_decision,
     authenticated_at, window_expires_at, hard_expires_at, credential_epoch,
     consumed_at, created_at, bound_operation, bound_key_set, bound_purpose,
     bound_environment_set)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
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
    created_at = excluded.created_at,
    bound_operation = excluded.bound_operation,
    bound_key_set = excluded.bound_key_set,
    bound_purpose = excluded.bound_purpose,
    bound_environment_set = excluded.bound_environment_set;

-- Start resolves the provider by slug for an enabled provider only: a login,
-- link or reauth may only begin against a provider that is currently serving.
-- hikyo:authn-resolution
-- name: GetEnabledProviderBySlug :one
SELECT id, slug, display_name, kind, issuer, client_id, client_secret, scopes,
       redirect_uri, jit_policy, assurance_policy, enabled, dek_version, row_version,
       created_at, updated_at
FROM oidc_providers WHERE slug = ? AND enabled = 1;

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
       consumed_at, created_at, bound_operation, bound_key_set, bound_purpose,
       bound_environment_set
FROM reauth_windows WHERE session_id = ? AND environment_id = ?;

-- Slide the idle window clock on a sliding (non single-decision) window. The hard
-- cap is enforced by the service, which passes min(now+window, hard_expires_at);
-- the NULL guard keeps a concurrently-claimed window from sliding.
-- hikyo:authn-resolution
-- name: SlideReauthWindow :execrows
UPDATE reauth_windows SET window_expires_at = ?
WHERE id = ? AND single_decision = 0 AND consumed_at IS NULL;

-- Claim a single_decision window exactly once: the NULL guard is the atomic
-- claim, so a second disclosure loses and is refused (B11 double-spend).
-- hikyo:authn-resolution
-- name: ConsumeSingleDecisionWindow :execrows
UPDATE reauth_windows SET consumed_at = ?
WHERE id = ? AND single_decision = 1 AND consumed_at IS NULL;

-- Invalidate every open window on one environment: the first of LowerEffective
-- Window's five ADR items on the effective-window transition (#54 B6).
-- hikyo:authn-resolution
-- name: DeleteReauthWindowsForEnvironment :execrows
DELETE FROM reauth_windows WHERE environment_id = ?;

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
WHERE principal_id = ?;

-- Principal row lock (#54 B14): every grant writer takes it so the credential-
-- reset org-bounded test serializes against a concurrent grant landing. sqlite's
-- single writer serializes trivially; postgres takes FOR UPDATE. The grant-lock
-- analyzer pins that this sits inside every grant writer.
-- hikyo:authn-resolution
-- name: LockPrincipalRow :one
SELECT id FROM principals WHERE id = ?;

-- Resolve an environment's chain from its id alone, for LowerEffectiveWindow's
-- stranded-principal query (#54 B6): the denormalized chain columns make the row
-- self-describing, so the grant-coverage predicate can be built from an env id.
-- hikyo:authn-resolution
-- name: EnvironmentChainByID :one
SELECT org_id, project_id, id FROM environments WHERE id = ?;

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
SELECT id, name FROM orgs WHERE id = ?;

-- Restore reconciliation (#76, ops spec section  11). All four run under local host
-- authority: after a restore every session is dead and every grant inert, so
-- there is no principal who could authorize a network call to undo that.

-- hikyo:authn-resolution
-- name: GetRestoreState :one
SELECT credential_epoch, restore_epoch, reactivated_at FROM auth_instance_state WHERE id = 1;

-- The largest credential epoch appearing ANYWHERE in the datastore - the
-- instance row and every epoch-stamped artifact table. Restore derives its
-- new epoch as this value + 1 rather than trusting the archive's own
-- counter: an archive is attacker-forgeable by anyone holding the PUBLIC
-- recipient, and a forged archive that understates the instance epoch while
-- stamping its planted credentials one higher would otherwise come back to
-- life on the bump (K2: restored verifiers never trusted - including their
-- epoch stamps).
-- hikyo:authn-resolution
-- name: MaxKnownCredentialEpoch :one
SELECT MAX(e) AS max_epoch FROM (
    SELECT credential_epoch AS e FROM auth_instance_state WHERE id = 1
    UNION ALL SELECT restore_epoch FROM auth_instance_state WHERE id = 1
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM credential_authorities
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM external_identities
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM instance_connections
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM machine_credentials
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM oidc_transactions
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM password_credentials
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM reauth_windows
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM recovery_codes
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM saml_transactions
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM scim_credentials
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM sessions
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM totp_challenges
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM totp_credentials
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM webauthn_ceremonies
    UNION ALL SELECT COALESCE(MAX(credential_epoch), 0) FROM webauthn_credentials
);

-- Sets the credential epoch and marks the epoch reached BY RESTORING. The
-- caller supplies the value (MaxKnownCredentialEpoch + 1) so the new epoch is
-- strictly greater than every epoch stamp the archive carried.
-- hikyo:authn-resolution
-- name: AdvanceRestoreEpoch :exec
UPDATE auth_instance_state
SET credential_epoch = ?,
    restore_epoch = ?,
    reactivated_at = ?,
    updated_at = ?
WHERE id = 1;

-- Restore strips every reconciliation stamp: reconciled_epoch is archive data
-- like everything else, and a forged archive could stamp its principals
-- "already reconciled" against any future restore epoch. Zero is always below
-- the post-restore restore_epoch, so every restored principal starts inert.
-- hikyo:authn-resolution
-- name: MarkAllPrincipalsUnreconciled :exec
UPDATE principals SET reconciled_epoch = 0;

-- Restored provider PATs are never trusted: unlike Hikyo authentication
-- artifacts they carry no local epoch the provider checks, so restore must
-- destroy custody and require operator re-entry.
-- hikyo:authn-resolution
-- name: InvalidateRestoredAdapterCredentials :exec
UPDATE adapters SET credential_ciphertext = NULL, credential_set_at = NULL;

-- The operator's commit covers `manual` origins ONLY (#73, scim-provisioning
-- ADR section 9.1). A restored `scim` origin is a claim about what an identity
-- provider asserted BEFORE the backup was taken, and the whole point of the
-- rule is that the restore must not re-activate it: the IdP's own next
-- re-assertion recreates SCIM origins from live truth, so a user it no longer
-- asserts is never re-authorized, not even for a window.
--
-- `structural` and `lockout-retention` survive deliberately. A structural
-- origin holds a provisioning connection's own grant and is created with the
-- binding, not by the identity provider, so nothing would ever recreate it; a
-- retention exists precisely to keep an org administrable, and dropping it at
-- restore would lock out the org the moment it most needs administering.
--
-- ARCHIVED, not merely `scim`. The reconciliation commit refuses archived
-- truth; it does not get to destroy LIVE truth. A restore leaves every
-- principal inert, but the operator reconciles the binding's provisioning
-- connection first (that is the only way the wire comes back), so the identity
-- provider's next cycle can assert something new about a user who is still
-- unreconciled. Those origins are current truth. Filtering on kind and
-- principal alone dropped them with the archived ones, and the originless
-- cleanup below then deleted grants the IdP was asserting right then --
-- access lost until the next cycle, roughly forty minutes later, for a user
-- whose authority never lapsed.
--
-- Provenance is `created_at` against `auth_instance_state.reactivated_at`, the
-- instant the restored instance came back. It is #76's own anchor, used the
-- same way the machine-identities ADR uses it for the federated `iat` floor: a
-- row stamped at or before the restore came out of the archive, a row stamped
-- after it was written by this instance since. NULL means this datastore was
-- never restored, the comparison is NULL, and the statement matches nothing --
-- which is right, because a reconciliation with no restore behind it has no
-- archived rows to refuse. The boundary is `<=` rather than `<` so an
-- ambiguous stamp is treated as ARCHIVED: dropping a live origin costs one
-- IdP cycle, re-activating an archived one is the security failure this rule
-- exists to prevent.
-- hikyo:authn-resolution
-- name: DropRestoredSCIMOrigins :execrows
DELETE FROM grant_origins
WHERE grant_origins.kind = 'scim'
  AND grant_origins.grant_id IN (SELECT g.id FROM grants AS g WHERE g.principal_id = ?)
  AND grant_origins.created_at <= (
    SELECT s.reactivated_at FROM auth_instance_state AS s WHERE s.id = 1
  );

-- A row whose only restored origins were `scim` is not re-activated: with its
-- last origin gone the grant row goes too, which is the same arithmetic every
-- other origin release performs. A row that also carried a `manual` origin
-- survives on that origin alone, which is what "the commit covers manual
-- origins only" means in the affirmative.
-- hikyo:authn-resolution
-- name: DeleteOriginlessGrantsForPrincipal :execrows
DELETE FROM grants
WHERE grants.principal_id = ?
  AND NOT EXISTS (SELECT 1 FROM grant_origins AS o WHERE o.grant_id = grants.id);

-- One principal, named explicitly. There is deliberately no statement here
-- that reconciles a set: per-principal reconciliation is an informed
-- assertion about one identity, and a bulk form would make it a keystroke.
-- hikyo:authn-resolution
-- name: ReconcilePrincipal :execrows
UPDATE principals
SET reconciled_epoch = (SELECT restore_epoch FROM auth_instance_state WHERE auth_instance_state.id = 1)
WHERE principals.id = ?;

-- Reading the outstanding set is not accepting it: the operator has to know
-- who is waiting in order to reconcile them one at a time.
-- hikyo:authn-resolution
-- name: ListUnreconciledPrincipals :many
SELECT principals.id, principals.kind FROM principals
WHERE principals.reconciled_epoch < (SELECT restore_epoch FROM auth_instance_state WHERE auth_instance_state.id = 1)
ORDER BY principals.id;

-- hikyo:authn-resolution
-- name: InsertCLIReauthHandoff :exec
INSERT INTO cli_reauth_handoffs (id,state_verifier,session_id,principal_id,operation,environment_set,pkce_challenge,redirect_uri,created_at,expires_at)
VALUES (?,?,?,?,?,?,?,?,?,?);

-- hikyo:authn-resolution
-- name: CLIReauthHandoffByState :one
SELECT * FROM cli_reauth_handoffs WHERE state_verifier = ?;

-- hikyo:authn-resolution
-- name: CLIReauthHandoffByCode :one
SELECT * FROM cli_reauth_handoffs WHERE code_verifier = ?;

-- hikyo:authn-resolution
-- name: ApproveCLIReauthHandoff :execrows
UPDATE cli_reauth_handoffs SET code_verifier=?,approved_windows=? WHERE id=? AND code_verifier IS NULL AND consumed_at IS NULL;

-- hikyo:authn-resolution
-- name: ConsumeCLIReauthHandoff :execrows
UPDATE cli_reauth_handoffs SET consumed_at=? WHERE id=? AND code_verifier IS NOT NULL AND consumed_at IS NULL;

-- Reencrypt walk (#75/#187): page instance credential ciphertext and re-seal in
-- place under the active DEK version, CAS on row_version (anti-resurrection),
-- stamping the new dek_version. class=authn: no tenant chain.
-- hikyo:authn-resolution
-- name: ListPasswordCredsForReencrypt :many
SELECT account_id, verifier, dek_version, row_version FROM password_credentials WHERE account_id > ? ORDER BY account_id LIMIT ?;
-- hikyo:authn-resolution
-- name: ReencryptPasswordCred :execrows
UPDATE password_credentials SET verifier=sqlc.arg(ct), dek_version=sqlc.arg(dek_version), row_version=row_version+1 WHERE account_id=sqlc.arg(account_id) AND row_version=sqlc.arg(row_version);

-- hikyo:authn-resolution
-- name: ListTotpCredsForReencrypt :many
SELECT id, seed, dek_version, row_version FROM totp_credentials WHERE id > ? ORDER BY id LIMIT ?;
-- hikyo:authn-resolution
-- name: ReencryptTotpCred :execrows
UPDATE totp_credentials SET seed=sqlc.arg(ct), dek_version=sqlc.arg(dek_version), row_version=row_version+1 WHERE id=sqlc.arg(id) AND row_version=sqlc.arg(row_version);

-- hikyo:authn-resolution
-- name: ListRecoveryCodesForReencrypt :many
SELECT account_id, batch, dek_version, row_version FROM recovery_codes WHERE account_id > ? ORDER BY account_id LIMIT ?;
-- hikyo:authn-resolution
-- name: ReencryptRecoveryCodes :execrows
UPDATE recovery_codes SET batch=sqlc.arg(ct), dek_version=sqlc.arg(dek_version), row_version=row_version+1 WHERE account_id=sqlc.arg(account_id) AND row_version=sqlc.arg(row_version);

-- hikyo:authn-resolution
-- name: ListOidcProvidersForReencrypt :many
SELECT id, client_secret, dek_version, row_version FROM oidc_providers WHERE id > ? ORDER BY id LIMIT ?;
-- hikyo:authn-resolution
-- name: ReencryptOidcProvider :execrows
UPDATE oidc_providers SET client_secret=sqlc.arg(ct), dek_version=sqlc.arg(dek_version), row_version=row_version+1 WHERE id=sqlc.arg(id) AND row_version=sqlc.arg(row_version);
