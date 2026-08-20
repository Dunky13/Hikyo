-- SAML SP resolution and lifecycle (#72, saml-sp ADR). These rows decide who
-- a caller is and how strongly they authenticated, so they live on the same
-- proof-free, enumerated authn resolution surface as OIDC.

-- hikyo:authn-resolution
-- name: InsertSAMLProvider :exec
INSERT INTO saml_providers
    (id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
     signing_certificates, assurance_policy, allow_email_nameid,
     force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
     metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
     created_at, updated_at)
VALUES (?, ?, ?, 'saml', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- hikyo:authn-resolution
-- name: GetSAMLProviderBySlug :one
SELECT id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
       signing_certificates, assurance_policy, allow_email_nameid,
       force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
       metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
       created_at, updated_at
FROM saml_providers WHERE slug = ?;

-- hikyo:authn-resolution
-- name: GetSAMLProviderForCallback :one
SELECT id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
       signing_certificates, assurance_policy, allow_email_nameid,
       force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
       metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
       created_at, updated_at
FROM saml_providers WHERE id = ?;

-- hikyo:authn-resolution
-- name: ListSAMLProviders :many
SELECT id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
       signing_certificates, assurance_policy, allow_email_nameid,
       force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
       metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
       created_at, updated_at
FROM saml_providers ORDER BY slug;

-- entity_id and slug are immutable. Every policy/trust-anchor change bumps the
-- version so callback minting can detect reconfiguration and fail closed.
-- hikyo:authn-resolution
-- name: UpdateSAMLProviderCAS :execrows
UPDATE saml_providers
SET display_name = ?, acs_url = ?, sso_redirect_url = ?,
    signing_certificates = ?, assurance_policy = ?, allow_email_nameid = ?,
    force_sign_requests = ?, metadata_want_authn_requests_signed = ?, metadata_source = ?, metadata_url = ?,
    metadata_signed = ?, metadata_signing_fingerprint = ?,
    metadata_valid_until = ?, enabled = ?, row_version = row_version + 1,
    updated_at = ?
WHERE id = ? AND row_version = ?;

-- SQLite write transactions already serialize; this existence read mirrors
-- PostgreSQL's row lock and preserves one cross-engine delete sequence.
-- hikyo:authn-resolution
-- name: LockSAMLProviderForDelete :one
SELECT id FROM saml_providers WHERE id = ?;

-- hikyo:authn-resolution
-- name: DeleteSAMLProvider :exec
DELETE FROM saml_providers WHERE id = ?;

-- hikyo:authn-resolution
-- name: GuardSAMLProviderForMint :execrows
UPDATE saml_providers SET row_version = row_version
WHERE id = ? AND row_version = ? AND entity_id = ? AND enabled = 1;

-- hikyo:authn-resolution
-- name: InsertSAMLTransaction :exec
INSERT INTO saml_transactions
    (id, request_id, relay_state_verifier, initiator_verifier, provider_id,
     entity_id, acs_url, purpose, initiating_session_id, account_id,
     environment_id, ceremony_id, credential_epoch,
     created_at, expires_at, consumed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);

-- RelayState is the pre-validation lookup key: it resolves the expected
-- request/provider before the signed response is parsed and validated once.
-- hikyo:authn-resolution
-- name: GetSAMLTransactionByRelayState :one
SELECT id, request_id, relay_state_verifier, initiator_verifier, provider_id,
       entity_id, acs_url, purpose, initiating_session_id, account_id,
       environment_id, ceremony_id, credential_epoch,
       created_at, expires_at, consumed_at
FROM saml_transactions WHERE relay_state_verifier = ?;

-- hikyo:authn-resolution
-- name: ConsumeSAMLTransaction :execrows
UPDATE saml_transactions SET consumed_at = ?
WHERE id = ? AND consumed_at IS NULL;

-- ON CONFLICT is the atomic replay claim: exactly one concurrent presentation
-- inserts, all others observe zero affected rows.
-- hikyo:authn-resolution
-- name: InsertSAMLReplay :execrows
INSERT INTO saml_replay (issuer, assertion_id, expires_at, created_at)
VALUES (?, ?, ?, ?)
ON CONFLICT (issuer, assertion_id) DO NOTHING;

-- hikyo:authn-resolution
-- name: DeleteExpiredSAMLReplay :execrows
DELETE FROM saml_replay WHERE expires_at <= ?;

-- hikyo:authn-resolution
-- name: InsertSAMLSPKey :exec
INSERT INTO saml_sp_keys
    (id, state, encrypted_private_key, certificate_der, fingerprint,
     dek_version, row_version, created_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?);

-- hikyo:authn-resolution
-- name: GetActiveSAMLSPKey :one
SELECT id, state, encrypted_private_key, certificate_der, fingerprint,
       dek_version, row_version, created_at
FROM saml_sp_keys WHERE state = 'active';

-- hikyo:authn-resolution
-- name: ListSAMLSPKeys :many
SELECT id, state, encrypted_private_key, certificate_der, fingerprint,
       dek_version, row_version, created_at
FROM saml_sp_keys ORDER BY created_at, id;

-- hikyo:authn-resolution
-- name: MarkSAMLSPKeyRetiringCAS :execrows
UPDATE saml_sp_keys
SET state = 'retiring', row_version = row_version + 1
WHERE id = ? AND row_version = ? AND state = 'active';

-- Erasing a retired key deletes both ciphertext and certificate row.
-- hikyo:authn-resolution
-- name: DeleteRetiringSAMLSPKey :execrows
DELETE FROM saml_sp_keys WHERE id = ? AND state = 'retiring';

-- Bind provider provenance before the surrounding session-mint transaction
-- commits. The existing OIDC provider column must be empty.
-- hikyo:authn-resolution
-- name: BindSessionToSAMLProvider :execrows
UPDATE sessions SET saml_provider_id = ?
WHERE id = ? AND provider_id IS NULL AND saml_provider_id IS NULL;

-- hikyo:authn-resolution
-- name: DeleteSessionsForSAMLProvider :execrows
DELETE FROM sessions WHERE saml_provider_id = ?;

-- Reencrypt walk (#75/#187): saml_sp_keys, class=authn.
-- hikyo:authn-resolution
-- name: ListSamlKeysForReencrypt :many
SELECT id, encrypted_private_key, dek_version, row_version FROM saml_sp_keys WHERE id > ? ORDER BY id LIMIT ?;
-- hikyo:authn-resolution
-- name: ReencryptSamlKey :execrows
UPDATE saml_sp_keys SET encrypted_private_key=sqlc.arg(ct), dek_version=sqlc.arg(dek_version), row_version=row_version+1 WHERE id=sqlc.arg(id) AND row_version=sqlc.arg(row_version);
