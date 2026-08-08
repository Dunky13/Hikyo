-- WebAuthn / passkeys (#54, human-auth ADR -- WebAuthn relying-party policy,
-- Passkey login). These read and write the credential, ceremony and user-handle
-- rows that decide who a caller is and how strongly they authenticated: the
-- resolution surface, proof-free, for the same reason the OIDC and factor
-- writers are. Every write below is enumerated in lint.ResolutionSurfaceWriters.

-- The discoverable-login resolver: an assertion carries only the opaque user
-- handle, which resolves to exactly one account (partial UNIQUE index).
-- wenv:authn-resolution
-- name: GetAccountByWebAuthnUserHandle :one
SELECT id, principal_id, username, display_name, created_at FROM accounts
WHERE webauthn_user_handle = ?;

-- wenv:authn-resolution
-- name: GetWebAuthnUserHandle :one
SELECT webauthn_user_handle FROM accounts WHERE id = ?;

-- Set the opaque handle once, on first enrolment. The NULL guard keeps a second
-- enrolment from rotating a handle other credentials already use.
-- wenv:authn-resolution
-- name: SetWebAuthnUserHandle :execrows
UPDATE accounts SET webauthn_user_handle = ?
WHERE id = ? AND webauthn_user_handle IS NULL;

-- wenv:authn-resolution
-- name: GetWebAuthnCredentialByID :one
SELECT id, account_id, credential_id, public_key, aaguid, sign_count, transports,
       discoverable, backup_eligible, backup_state, label, credential_epoch,
       row_version, disabled_at, created_at, last_used_at
FROM webauthn_credentials WHERE id = ?;

-- The assertion resolver: the authenticator-chosen credential id maps to one row.
-- wenv:authn-resolution
-- name: GetWebAuthnCredentialByCredentialID :one
SELECT id, account_id, credential_id, public_key, aaguid, sign_count, transports,
       discoverable, backup_eligible, backup_state, label, credential_epoch,
       row_version, disabled_at, created_at, last_used_at
FROM webauthn_credentials WHERE credential_id = ?;

-- wenv:authn-resolution
-- name: ListWebAuthnCredentialsForAccount :many
SELECT id, account_id, credential_id, public_key, aaguid, sign_count, transports,
       discoverable, backup_eligible, backup_state, label, credential_epoch,
       row_version, disabled_at, created_at, last_used_at
FROM webauthn_credentials WHERE account_id = ? ORDER BY created_at;

-- wenv:authn-resolution
-- name: InsertWebAuthnCredential :exec
INSERT INTO webauthn_credentials
    (id, account_id, credential_id, public_key, aaguid, sign_count, transports,
     discoverable, backup_eligible, backup_state, label, credential_epoch,
     row_version, disabled_at, created_at, last_used_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, NULL);

-- Sign-count advance under a row_version CAS (B9): the presented counter is
-- written only if the row has not moved, so two concurrent assertions cannot
-- both advance it and a stale read cannot rewind it.
-- wenv:authn-resolution
-- name: AdvanceWebAuthnSignCount :execrows
UPDATE webauthn_credentials
SET sign_count = ?, last_used_at = ?, row_version = row_version + 1
WHERE id = ? AND row_version = ? AND disabled_at IS NULL;

-- The clone response (B9): a real sign-count regression on a non-backup
-- credential disables it. Re-enable is an account-security mutation.
-- wenv:authn-resolution
-- name: DisableWebAuthnCredential :execrows
UPDATE webauthn_credentials
SET disabled_at = ?, row_version = row_version + 1
WHERE id = ? AND row_version = ? AND disabled_at IS NULL;

-- De-enrolment under an account_id predicate (defence in depth): even if the
-- service-layer ownership check regresses, the DELETE cannot touch a row another
-- account owns, and zero affected rows is the caller's fail-closed refusal.
-- wenv:authn-resolution
-- name: DeleteWebAuthnCredential :execrows
DELETE FROM webauthn_credentials WHERE id = ? AND account_id = ?;

-- The clone session sweep (B9): every session a passkey login minted through a
-- given credential dies when that credential is found cloned. A session traces
-- to its credential through the ceremony it was minted from (sessions.ceremony_id
-- -> webauthn_ceremonies.credential_id).
-- wenv:authn-resolution
-- name: DeleteSessionsForWebAuthnCredential :execrows
DELETE FROM sessions WHERE ceremony_id IN (
    SELECT id FROM webauthn_ceremonies WHERE credential_id = ?
);

-- wenv:authn-resolution
-- name: InsertWebAuthnCeremony :exec
INSERT INTO webauthn_ceremonies
    (id, challenge_verifier, session_data, account_id, session_id, purpose,
     operation_binding, environment_id, credential_id, credential_epoch,
     expires_at, consumed_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, ?);

-- wenv:authn-resolution
-- name: GetWebAuthnCeremonyByChallenge :one
SELECT id, challenge_verifier, session_data, account_id, session_id, purpose,
       operation_binding, environment_id, credential_id, credential_epoch,
       expires_at, consumed_at, created_at
FROM webauthn_ceremonies WHERE challenge_verifier = ?;

-- Single-use consumption: the NULL guard is the atomic claim. credential_id is
-- stamped here (the passkey that answered), so the ceremony row keeps resolving
-- a minted session to the credential that authored it after consume.
-- wenv:authn-resolution
-- name: ConsumeWebAuthnCeremony :execrows
UPDATE webauthn_ceremonies SET consumed_at = ?, credential_id = ?
WHERE id = ? AND consumed_at IS NULL;
