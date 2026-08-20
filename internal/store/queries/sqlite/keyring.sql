-- name: GetActiveMasterKeys :many
SELECT version, root_key_epoch, state, blob, created_at
FROM master_keys WHERE state = 'active' ORDER BY root_key_epoch DESC;

-- name: InsertMasterKey :exec
INSERT INTO master_keys (version, root_key_epoch, state, blob, created_at)
VALUES (?, ?, 'active', ?, ?);

-- name: GetActiveTier3Key :one
SELECT id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at
FROM tier3_keys WHERE purpose = ? AND org_id = ? AND project_id = ? AND state = 'active';

-- GetTier3Versions returns every still-openable version of one scope's key --
-- the 'active' version new writes use plus every 'retiring' version whose
-- ciphertext a reencrypt has not yet moved. 'retired' rows are excluded: a
-- version reaches that state only when zero ciphertexts reference it, so
-- loading it would unwrap key material nothing can open. Newest version first.
-- name: GetTier3Versions :many
SELECT id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at
FROM tier3_keys
WHERE purpose = ? AND org_id = ? AND project_id = ? AND state IN ('active', 'retiring')
ORDER BY version DESC;

-- name: InsertTier3Key :exec
INSERT INTO tier3_keys (id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at)
VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?);

-- AllOpenableTier3 returns every still-openable tier-3 key across every scope
-- (active + retiring), for `rotate-master-key` to re-wrap under a new master.
-- Retired rows are excluded: they hold zero live ciphertext, so their key
-- material is never unwrapped and re-wrapping it would be work with no reader.
-- name: AllOpenableTier3 :many
SELECT id, purpose, org_id, project_id, version, master_key_version, state, blob, created_at
FROM tier3_keys WHERE state IN ('active', 'retiring') ORDER BY purpose, org_id, project_id, version;

-- UpdateTier3Wrapping re-points one tier-3 key at a new master: same key
-- material, re-sealed blob, new master_key_version. Addressed by (id, version)
-- because a scope has one row per version and the id is unique.
-- name: UpdateTier3Wrapping :execrows
UPDATE tier3_keys SET blob = ?, master_key_version = ?
WHERE id = ? AND version = ?;

-- CountOpenableTier3NotAtMaster is rotate-master-key's zero-reference check,
-- run INSIDE the hierarchy fence: after re-wrapping, no still-openable tier-3
-- key may reference a master other than the new version. A non-zero count means
-- a tier-3 key was created or version-appended in the window before the fence,
-- under the old master, and is not in the re-wrapped set -- the rotation must
-- refuse and be retried rather than strand that key under the retired master.
-- name: CountOpenableTier3NotAtMaster :one
SELECT COUNT(*) FROM tier3_keys
WHERE state IN ('active', 'retiring') AND master_key_version != ?;

-- RetireMasterAtVersion retires the single active master as a compare-and-swap:
-- zero rows means a concurrent master rotation already moved it. Refused while
-- the root is dual-wrapped (two active masters) by the count check in the store.
-- name: RetireMasterAtVersion :execrows
UPDATE master_keys SET state = 'retired' WHERE version = ? AND state = 'active';

-- RetireMasterWrapperAtEpoch retires one wrapper of the dual-wrapped master by
-- its epoch (rotate-root-key --finalize dropping the old root's wrapper). The
-- other wrapper (same version, new epoch) stays active, so after finalize only
-- the new root boots and the old root fails with a root-mismatch.
-- name: RetireMasterWrapperAtEpoch :execrows
UPDATE master_keys SET state = 'retired'
WHERE version = ? AND root_key_epoch = ? AND state = 'active';

-- name: AcquireHierarchyGeneration :one
SELECT generation FROM key_generations WHERE scope = 'hierarchy';

-- AcquireScopeGeneration takes the per-scope fence a version append or a
-- retirement runs inside. On sqlite the single write connection already
-- serializes it; the row read keeps the call shape and proves the row exists.
-- name: AcquireScopeGeneration :one
SELECT generation FROM key_generations WHERE scope = ?;

-- AssertActiveTier3Version is the writer fence: a ciphertext write reads the
-- state of the exact DEK version it sealed under, in its own transaction, and
-- proceeds only if that version is still 'active'. A stale sealer (built before
-- a rotate-dek, sealing under a now-retiring or retired version) is refused, so
-- no write lands under a version reencrypt is about to retire. On sqlite the
-- single write connection serializes this against the demote/retire; postgres
-- adds FOR SHARE (see its twin) so those block until in-flight writers commit.
-- name: AssertActiveTier3Version :one
SELECT state FROM tier3_keys
WHERE purpose = ? AND org_id = ? AND project_id = ? AND version = ?;

-- DemoteActiveTier3ToRetiring is `rotate-dek`'s first half: the outgoing active
-- version steps down to 'retiring' -- no longer written, still openable until
-- reencrypt moves its ciphertext -- so the new active can take the one-active
-- index slot. Compare-and-swap on the predecessor version: zero rows means a
-- concurrent rotation already moved the active, and the caller must refuse.
-- name: DemoteActiveTier3ToRetiring :execrows
UPDATE tier3_keys SET state = 'retiring'
WHERE purpose = ? AND org_id = ? AND project_id = ? AND state = 'active'
  AND version = ?;

-- name: InsertKeyGeneration :exec
INSERT INTO key_generations (scope, generation) VALUES (?, 1);

-- RetireTier3Key retires the active key for one scope so a rotation can put a
-- new version in its place. It is an UPDATE rather than a delete: the
-- superseded row's blob is what still opens material written under it, and the
-- one-active-per-scope index is what makes the swap unambiguous.
-- name: RetireTier3Key :execrows
UPDATE tier3_keys SET state = 'retired'
WHERE purpose = ? AND org_id = ? AND project_id = ? AND state = 'active';

-- RetireTier3KeyAtVersion is RetireTier3Key as a compare-and-swap: it retires
-- the active key only when it is still the version the caller prepared its
-- successor against. Zero rows means a concurrent rotation won -- the caller
-- must refuse, not stack a second successor on the wrong predecessor.
-- name: RetireTier3KeyAtVersion :execrows
UPDATE tier3_keys SET state = 'retired'
WHERE purpose = ? AND org_id = ? AND project_id = ? AND state = 'active'
  AND version = ?;

-- RetireRetiringTier3ForScope completes a reencrypt: once the walk has moved
-- every ciphertext in the scope onto the active version, its retiring versions
-- reference nothing and are retired. Run inside the scope fence, which the
-- writer fence's FOR SHARE blocks against, so no write lands under a version
-- between the walk finishing and this retiring it.
-- name: RetireRetiringTier3ForScope :execrows
UPDATE tier3_keys SET state = 'retired'
WHERE purpose = ? AND org_id = ? AND project_id = ? AND state = 'retiring';
