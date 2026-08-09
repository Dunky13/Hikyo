-- SAML SP resolution and lifecycle (#72, saml-sp ADR).

-- wenv:authn-resolution
-- name: InsertSAMLProvider :exec
INSERT INTO saml_providers
    (id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
     signing_certificates, assurance_policy, allow_email_nameid,
     force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
     metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
     created_at, updated_at)
VALUES ($1, $2, $3, 'saml', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 1, $18, $19);

-- wenv:authn-resolution
-- name: GetSAMLProviderBySlug :one
SELECT id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
       signing_certificates, assurance_policy, allow_email_nameid,
       force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
       metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
       created_at, updated_at
FROM saml_providers WHERE slug = $1;

-- wenv:authn-resolution
-- name: GetSAMLProviderForCallback :one
SELECT id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
       signing_certificates, assurance_policy, allow_email_nameid,
       force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
       metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
       created_at, updated_at
FROM saml_providers WHERE id = $1;

-- wenv:authn-resolution
-- name: ListSAMLProviders :many
SELECT id, slug, display_name, kind, entity_id, acs_url, sso_redirect_url,
       signing_certificates, assurance_policy, allow_email_nameid,
       force_sign_requests, metadata_want_authn_requests_signed, metadata_source, metadata_url, metadata_signed,
       metadata_signing_fingerprint, metadata_valid_until, enabled, row_version,
       created_at, updated_at
FROM saml_providers ORDER BY slug;

-- wenv:authn-resolution
-- name: UpdateSAMLProviderCAS :execrows
UPDATE saml_providers
SET display_name = $1, acs_url = $2, sso_redirect_url = $3,
    signing_certificates = $4, assurance_policy = $5, allow_email_nameid = $6,
    force_sign_requests = $7, metadata_want_authn_requests_signed = $8,
    metadata_source = $9, metadata_url = $10,
    metadata_signed = $11, metadata_signing_fingerprint = $12,
    metadata_valid_until = $13, enabled = $14, row_version = row_version + 1,
    updated_at = $15
WHERE id = $16 AND row_version = $17;

-- wenv:authn-resolution
-- name: LockSAMLProviderForDelete :one
SELECT id FROM saml_providers WHERE id = $1 FOR UPDATE;

-- wenv:authn-resolution
-- name: DeleteSAMLProvider :exec
DELETE FROM saml_providers WHERE id = $1;

-- wenv:authn-resolution
-- name: GuardSAMLProviderForMint :execrows
UPDATE saml_providers SET row_version = row_version
WHERE id = $1 AND row_version = $2 AND entity_id = $3 AND enabled = 1;

-- wenv:authn-resolution
-- name: InsertSAMLTransaction :exec
INSERT INTO saml_transactions
    (id, request_id, relay_state_verifier, initiator_verifier, provider_id,
     entity_id, acs_url, purpose, initiating_session_id, account_id,
     environment_id, ceremony_id, credential_epoch,
     created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NULL);

-- RelayState resolves the expected request/provider before the response's
-- single parse and signature-validation pass.
-- wenv:authn-resolution
-- name: GetSAMLTransactionByRelayState :one
SELECT id, request_id, relay_state_verifier, initiator_verifier, provider_id,
       entity_id, acs_url, purpose, initiating_session_id, account_id,
       environment_id, ceremony_id, credential_epoch,
       created_at, expires_at, consumed_at
FROM saml_transactions WHERE relay_state_verifier = $1;

-- wenv:authn-resolution
-- name: ConsumeSAMLTransaction :execrows
UPDATE saml_transactions SET consumed_at = $1
WHERE id = $2 AND consumed_at IS NULL;

-- wenv:authn-resolution
-- name: InsertSAMLReplay :execrows
INSERT INTO saml_replay (issuer, assertion_id, expires_at, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (issuer, assertion_id) DO NOTHING;

-- wenv:authn-resolution
-- name: DeleteExpiredSAMLReplay :execrows
DELETE FROM saml_replay WHERE expires_at <= $1;

-- wenv:authn-resolution
-- name: InsertSAMLSPKey :exec
INSERT INTO saml_sp_keys
    (id, state, encrypted_private_key, certificate_der, fingerprint,
     dek_version, row_version, created_at)
VALUES ($1, $2, $3, $4, $5, $6, 1, $7);

-- wenv:authn-resolution
-- name: GetActiveSAMLSPKey :one
SELECT id, state, encrypted_private_key, certificate_der, fingerprint,
       dek_version, row_version, created_at
FROM saml_sp_keys WHERE state = 'active';

-- wenv:authn-resolution
-- name: ListSAMLSPKeys :many
SELECT id, state, encrypted_private_key, certificate_der, fingerprint,
       dek_version, row_version, created_at
FROM saml_sp_keys ORDER BY created_at, id;

-- wenv:authn-resolution
-- name: MarkSAMLSPKeyRetiringCAS :execrows
UPDATE saml_sp_keys
SET state = 'retiring', row_version = row_version + 1
WHERE id = $1 AND row_version = $2 AND state = 'active';

-- wenv:authn-resolution
-- name: DeleteRetiringSAMLSPKey :execrows
DELETE FROM saml_sp_keys WHERE id = $1 AND state = 'retiring';

-- wenv:authn-resolution
-- name: BindSessionToSAMLProvider :execrows
UPDATE sessions SET saml_provider_id = $1
WHERE id = $2 AND provider_id IS NULL AND saml_provider_id IS NULL;

-- wenv:authn-resolution
-- name: DeleteSessionsForSAMLProvider :execrows
DELETE FROM sessions WHERE saml_provider_id = $1;
