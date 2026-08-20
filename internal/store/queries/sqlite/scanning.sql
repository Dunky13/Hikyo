-- Secret-scanning dismissal rows (#74, secret-scanning ADR section 4). ASCII
-- ONLY: sqlc's sqlite path silently mis-slices statements containing non-ASCII.
--
-- Tenant-scoped statements bind org_id and project_id from the proof's resolved
-- chain, never from caller arguments; environment_id is bound from the proof on
-- the environment-addressed statements. The (key identity, rule digest, value
-- fingerprint) triple is caller data: the finding's own coordinates.

-- name: InsertScanningDismissal :exec
INSERT INTO scanning_dismissals (
    id, org_id, project_id, environment_id, key_id, rule_digest, value_fingerprint, created_at, created_by
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- GetScanningDismissal is the sticky-match lookup: a row for this exact
-- (env, key, rule digest, fingerprint) means the value was accepted as-is and
-- the warn must not re-fire. The WHERE names the full UNIQUE tuple, so at most
-- one row matches: no LIMIT needed, and a nested SELECT EXISTS is rejected by
-- the predicate analyzer anyway. Absence is sql.ErrNoRows.
-- name: GetScanningDismissal :one
SELECT id FROM scanning_dismissals
WHERE org_id = ? AND project_id = ? AND environment_id = ?
  AND key_id = ? AND rule_digest = ? AND value_fingerprint = ?;

-- DeleteScanningDismissalsForKey drops one key's dismissals across every
-- environment: reclassification to secret makes them moot, and key deletion
-- needs them gone before the composite FK will let the key row go.
-- name: DeleteScanningDismissalsForKey :execrows
DELETE FROM scanning_dismissals
WHERE org_id = ? AND project_id = ? AND key_id = ?;

-- DeleteScanningDismissalsForProject removes a project's dismissals: the ADR's
-- literal "project deletion removes the project's dismissal rows".
-- name: DeleteScanningDismissalsForProject :execrows
DELETE FROM scanning_dismissals
WHERE org_id = ? AND project_id = ?;

-- DeleteAllScanningDismissals drops every dismissal instance-wide: fingerprint
-- rotation replaces the scanning key, so every stored fingerprint is now
-- unrecomputable and must die (re-fire, the safe direction). Cross-tenant by
-- definition: the operator rotation surface, annotated and pinned.
-- hikyo:instance-scoped
-- name: DeleteAllScanningDismissals :execrows
DELETE FROM scanning_dismissals;
