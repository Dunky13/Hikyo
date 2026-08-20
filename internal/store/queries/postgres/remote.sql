-- Multi-instance (#71, multi-instance ADR). The serving side's instance
-- connections live here; the viewing side's remotes and snapshots land with
-- the directory service.
--
-- Every statement below is authn-resolution: the instance-connection
-- credential resolves at the SAME chokepoint as authorize(), inside the
-- authorizing transaction and uncached, exactly as a machine credential does.
-- Resolution cannot itself run under a proof, because the proof is what the
-- answer produces.

-- The authentication read. One indexed lookup on the unsalted SHA-256
-- verifier, like every other bearer artifact in the system; the caller
-- constant-time compares the returned verifier and runs the miss path's decoy
-- work, so unknown / revoked / expired / live are work-shape uniform.
--
-- The predicates that decide LIVENESS are deliberately not in this WHERE
-- clause. Filtering here would make an unknown credential cost one row and a
-- revoked one zero, which is a query-count oracle for which credentials exist.
-- hikyo:authn-resolution
-- name: InstanceConnectionByVerifier :one
SELECT id, principal_id, label, kind, verifier, prefix_hint, lifetime,
       expires_at, credential_epoch, created_at, created_by, revoked_at,
       last_used_at
FROM instance_connections
WHERE verifier = sqlc.arg(verifier);

-- Metadata only, and never the value: the ADR inherits #17's list/get rule
-- unchanged. There is no statement anywhere that reads `verifier` back out for
-- display, because a credential is display-once at mint and write-only after.
-- hikyo:authn-resolution
-- name: ListInstanceConnections :many
SELECT id, principal_id, label, kind, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at
FROM instance_connections
ORDER BY created_at, id;

-- hikyo:authn-resolution
-- name: GetInstanceConnection :one
SELECT id, principal_id, label, kind, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at
FROM instance_connections
WHERE id = sqlc.arg(id);

-- Principal and credential are minted as one unit with a stable immutable id.
-- hikyo:authn-resolution
-- name: CreateInstanceConnection :exec
INSERT INTO instance_connections (
    id, principal_id, label, kind, verifier, prefix_hint, lifetime,
    expires_at, credential_epoch, created_at, created_by, revoked_at,
    last_used_at
) VALUES (sqlc.arg(id), sqlc.arg(principal_id), sqlc.arg(label), sqlc.arg(kind), sqlc.arg(verifier), sqlc.arg(prefix_hint), sqlc.arg(lifetime), sqlc.arg(expires_at), sqlc.arg(credential_epoch), sqlc.arg(created_at), sqlc.arg(created_by), NULL, NULL);

-- Revocation kills the credential and retires the principal with it, so no
-- orphan principals accumulate and no revoked principal is re-armed.
--
-- `revoked_at` is set in place and the row survives, exactly as
-- machine_credentials does: the audit trail's credential id must keep resolving
-- to a describable row after an incident. The verifier is deliberately LEFT
-- ALONE -- Live() already refuses a revoked row, the kind CHECK requires a
-- bearer credential to have one, and a 256-bit random re-mint cannot collide
-- with it. Revocation bites at the next presentation, read in the
-- authenticating transaction, uncached.
-- hikyo:authn-resolution
-- name: RevokeInstanceConnection :execrows
UPDATE instance_connections
SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- The last-used stamp, written on a successful directory serve. It is the
-- operator's answer to "is this connection still in use" before revoking it.
-- hikyo:authn-resolution
-- name: TouchInstanceConnection :exec
UPDATE instance_connections SET last_used_at = sqlc.arg(last_used_at) WHERE id = sqlc.arg(id);

-- The instance's own opaque identity, minted by migration 00019. Read on every
-- directory serve (it is the listing's first field) and on every fetch the
-- viewing side performs, which is what makes self-connection detectable.
-- hikyo:instance-scoped
-- name: InstanceIdentity :one
SELECT identity FROM instance_identity WHERE id = 1;

-- ---------------------------------------------------------------------------
-- SERVING SIDE, continued: the origin allowlist and the handoff transaction.
--
-- Both are authn-resolution. The allowlist is consulted at handoff issuance,
-- which is pre-authentication; the handoff transaction resolves the caller the
-- same way a session verifier does, at the same chokepoint, and a proof cannot
-- gate it because the proof is what the answer produces.
-- ---------------------------------------------------------------------------

-- hikyo:authn-resolution
-- name: ListWorkspaceOrigins :many
SELECT origin, created_at, created_by FROM workspace_origins ORDER BY origin;

-- Exact match, no wildcards and no subdomain logic: the primary key IS the
-- origin string, so an inexact entry is unrepresentable rather than merely
-- discouraged. This is the read CORS and handoff issuance both consult.
-- hikyo:authn-resolution
-- name: GetWorkspaceOrigin :one
SELECT origin, created_at, created_by FROM workspace_origins WHERE origin = sqlc.arg(origin);

-- hikyo:authn-resolution
-- name: InsertWorkspaceOrigin :exec
INSERT INTO workspace_origins (origin, created_at, created_by)
VALUES (sqlc.arg(origin), sqlc.arg(created_at), sqlc.arg(created_by));

-- Removal is the kill switch's first half; DeleteSessionsForOrigin is the
-- second, and the two run in ONE transaction so no window exists in which the
-- origin is de-allowlisted but its sessions still authenticate.
-- hikyo:authn-resolution
-- name: DeleteWorkspaceOrigin :execrows
DELETE FROM workspace_origins WHERE origin = sqlc.arg(origin);

-- The handoff transaction. state_verifier and code_verifier are stored as
-- VERIFIERS and never as values, for the reason every other bearer in this
-- schema is: both cross a redirect. code_verifier is NULL until approval,
-- because a transaction nobody has approved has issued no code.
-- hikyo:authn-resolution
-- name: InsertWorkspaceHandoff :exec
INSERT INTO workspace_handoffs (
    id, state_verifier, code_verifier, origin, redirect_uri, pkce_challenge,
    purpose, session_id, operation, env_id, key_set, principal_id, created_at,
    expires_at, consumed_at
) VALUES (
    sqlc.arg(id), sqlc.arg(state_verifier), NULL, sqlc.arg(origin),
    sqlc.arg(redirect_uri), sqlc.arg(pkce_challenge), sqlc.arg(purpose),
    sqlc.arg(session_id), sqlc.arg(operation), sqlc.arg(env_id),
    sqlc.arg(key_set), NULL, sqlc.arg(created_at), sqlc.arg(expires_at), NULL
);

-- Liveness is deliberately NOT in this WHERE clause, for the reason the
-- credential read states: filtering here would make an unknown state cost one
-- row and a consumed one zero, which is an existence oracle. The caller
-- decides expiry and single-use against the row it got.
-- hikyo:authn-resolution
-- name: WorkspaceHandoffByState :one
SELECT id, state_verifier, code_verifier, origin, redirect_uri, pkce_challenge,
       purpose, session_id, operation, env_id, key_set, principal_id,
       created_at, expires_at, consumed_at, factors, factor_class
FROM workspace_handoffs WHERE state_verifier = sqlc.arg(state_verifier);

-- hikyo:authn-resolution
-- name: WorkspaceHandoffByCode :one
SELECT id, state_verifier, code_verifier, origin, redirect_uri, pkce_challenge,
       purpose, session_id, operation, env_id, key_set, principal_id,
       created_at, expires_at, consumed_at, factors, factor_class
FROM workspace_handoffs WHERE code_verifier = sqlc.arg(code_verifier);

-- Approval binds the authenticated human and mints the code. The NULL guard on
-- code_verifier is the atomic claim: two concurrent approvals of one
-- transaction cannot both issue a code.
-- hikyo:authn-resolution
-- name: ApproveWorkspaceHandoff :execrows
UPDATE workspace_handoffs
SET code_verifier = sqlc.arg(code_verifier), principal_id = sqlc.arg(principal_id),
    factors = sqlc.arg(factors), factor_class = sqlc.arg(factor_class)
WHERE id = sqlc.arg(id) AND code_verifier IS NULL AND consumed_at IS NULL;

-- Single-use consumption. The NULL guard is the atomic claim, exactly as
-- ConsumeCredentialAuthority does it: two concurrent redemptions of one code
-- cannot both yield a session.
-- hikyo:authn-resolution
-- name: ConsumeWorkspaceHandoff :execrows
UPDATE workspace_handoffs SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id) AND consumed_at IS NULL;

-- Expired transactions are swept opportunistically at issuance rather than by
-- a poller: the ADR forbids a background job framework, and a transaction that
-- has expired is refused by the caller's own clock check whether or not the
-- row is still there. This keeps the table from growing without bound.
-- hikyo:authn-resolution
-- name: DeleteExpiredWorkspaceHandoffs :execrows
DELETE FROM workspace_handoffs WHERE expires_at < sqlc.arg(expires_at);

-- ---------------------------------------------------------------------------
-- VIEWING SIDE: the remote entries and their last-known snapshots.
--
-- These are class=instance, NOT authn-resolution: they are instance-scope
-- configuration and foreign structure at rest, read only through proofs
-- evaluated on instance-directory or instance-config. They are annotated
-- instance-scoped for the reason ListOrgs is - they address no tenant by
-- design, not by omission.
-- ---------------------------------------------------------------------------

-- URL and pin are immutable per entry: there is deliberately no UPDATE
-- statement anywhere naming either column. Re-pointing a stored credential at
-- a different host is the credential-redirect attack, so re-pointing is
-- remove + add, which re-runs the full ceremony including the human
-- fingerprint confirmation.
-- hikyo:instance-scoped
-- name: CreateRemote :exec
INSERT INTO remotes (id, name, url, spki_pin, credential_sealed, created_at, created_by)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(url), sqlc.arg(spki_pin),
        sqlc.arg(credential_sealed), sqlc.arg(created_at), sqlc.arg(created_by));

-- credential_sealed is deliberately NOT selected: it is write-only after
-- storage and leaves the process only inside TLS to the pinned remote. The one
-- statement that reads it is SealedRemoteCredential, below, and it exists so
-- the fetch path can present it - never so a surface can display it.
-- hikyo:instance-scoped
-- name: ListRemotes :many
SELECT id, name, url, spki_pin, created_at, created_by FROM remotes ORDER BY name;

-- hikyo:instance-scoped
-- name: GetRemote :one
SELECT id, name, url, spki_pin, created_at, created_by FROM remotes WHERE id = sqlc.arg(id);

-- hikyo:instance-scoped
-- name: GetRemoteByName :one
SELECT id, name, url, spki_pin, created_at, created_by FROM remotes WHERE name = sqlc.arg(name);

-- The only reader of the sealed credential. It is separate from GetRemote so
-- that reaching the credential is a distinct, greppable act rather than a
-- field every caller of the ordinary read happens to receive.
-- hikyo:instance-scoped
-- name: SealedRemoteCredential :one
SELECT credential_sealed FROM remotes WHERE id = sqlc.arg(id);

-- hikyo:instance-scoped
-- name: CountRemotes :one
SELECT COUNT(*) FROM remotes;

-- The display name is the one mutable field the ADR admits.
-- hikyo:instance-scoped
-- name: RenameRemote :execrows
UPDATE remotes SET name = sqlc.arg(name) WHERE id = sqlc.arg(id);

-- Removal destroys the credential and the snapshot with the entry (the
-- snapshot by ON DELETE CASCADE). It does NOT revoke anything on the serving
-- side, and the CLI says so every time.
-- hikyo:instance-scoped
-- name: DeleteRemote :execrows
DELETE FROM remotes WHERE id = sqlc.arg(id);

-- The snapshot is upserted whole. last_attempt_at/last_outcome record the most
-- recent FETCH; observed_at and the listing columns record the most recent
-- SUCCESS, and a failing fetch leaves them alone - that split is the entire
-- freshness model, and it is why a failure writes through the second statement
-- rather than this one.
-- hikyo:instance-scoped
-- name: WriteRemoteSnapshot :exec
INSERT INTO remote_snapshots (
    remote_id, last_attempt_at, last_outcome, observed_at, instance_identity,
    version, org_count, project_count, listing
) VALUES (
    sqlc.arg(remote_id), sqlc.arg(last_attempt_at), sqlc.arg(last_outcome),
    sqlc.arg(observed_at), sqlc.arg(instance_identity), sqlc.arg(version),
    sqlc.arg(org_count), sqlc.arg(project_count), sqlc.arg(listing)
)
ON CONFLICT (remote_id) DO UPDATE SET
    last_attempt_at = excluded.last_attempt_at,
    last_outcome = excluded.last_outcome,
    observed_at = excluded.observed_at,
    instance_identity = excluded.instance_identity,
    version = excluded.version,
    org_count = excluded.org_count,
    project_count = excluded.project_count,
    listing = excluded.listing;

-- A failed fetch records the attempt and its outcome and PRESERVES the last
-- known listing, which is what makes "unreachable 2h - last known state shown"
-- possible. Writing NULLs here would discard the genuinely useful signal.
-- hikyo:instance-scoped
-- name: RecordRemoteFetchFailure :exec
INSERT INTO remote_snapshots (remote_id, last_attempt_at, last_outcome)
VALUES (sqlc.arg(remote_id), sqlc.arg(last_attempt_at), sqlc.arg(last_outcome))
ON CONFLICT (remote_id) DO UPDATE SET
    last_attempt_at = excluded.last_attempt_at,
    last_outcome = excluded.last_outcome;

-- hikyo:instance-scoped
-- name: ListRemoteSnapshots :many
SELECT remote_id, last_attempt_at, last_outcome, observed_at, instance_identity,
       version, org_count, project_count, listing
FROM remote_snapshots ORDER BY remote_id;

-- hikyo:instance-scoped
-- name: GetRemoteSnapshot :one
SELECT remote_id, last_attempt_at, last_outcome, observed_at, instance_identity,
       version, org_count, project_count, listing
FROM remote_snapshots WHERE remote_id = sqlc.arg(remote_id);

-- Row locks that serialize a read-then-write decision. Postgres runs READ
-- COMMITTED, so a transaction alone does NOT serialize "check, then write" --
-- two concurrent transactions each read the pre-state and each commit. sqlite's
-- single writer serializes trivially; postgres takes FOR UPDATE. The shape
-- mirrors LockPrincipalRow, which #54 added for exactly this class of race.
--
-- LockInstanceIdentityRow locks the instance-owned singleton `instance_identity`
-- has been since migration 00019. It is the natural mutex for a decision about
-- THIS INSTANCE AS A WHOLE -- the remote-count cap and the duplicate-identity
-- refusal are both instance-wide census questions, and there is no per-remote
-- row to lock because the row being decided about does not exist yet.
--
-- LockWorkspaceOrigin locks one allowlist entry so a redemption's membership
-- check and the session it then mints cannot straddle a concurrent removal.
-- Zero rows means the origin is gone, and the caller refuses.
-- hikyo:instance-scoped
-- name: LockInstanceIdentityRow :one
SELECT id FROM instance_identity WHERE id = 1 FOR UPDATE;

-- hikyo:authn-resolution
-- name: LockWorkspaceOrigin :one
SELECT origin FROM workspace_origins WHERE origin = $1 FOR UPDATE;

-- Reencrypt walk (#75/#187): remotes.credential_sealed has no dek_version, so
-- the walk header-parses the envelope for the version and CASes on the blob.
-- hikyo:instance-scoped
-- name: ListRemotesForReencrypt :many
SELECT id, credential_sealed FROM remotes WHERE id > sqlc.arg(cursor) ORDER BY id LIMIT sqlc.arg(page_limit);
-- hikyo:instance-scoped
-- name: ReencryptRemote :execrows
UPDATE remotes SET credential_sealed=sqlc.arg(new_ct) WHERE id=sqlc.arg(id) AND credential_sealed=sqlc.arg(old_ct);
