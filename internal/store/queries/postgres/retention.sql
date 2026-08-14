-- Retention/GC (#53). Scheduler statements are cross-tenant by definition and
-- run only under the scheduler system-proof site. Tenant policy and pin reads
-- carry the ordinary proof-bound chain conjuncts.

-- hikyo:instance-scoped
-- name: ListEligibleSnapshotPayloads :many
WITH ranked AS (
    SELECT s.id, s.org_id, s.project_id, s.environment_id, s.revision,
           s.published_at, s.payload_present,
           COALESCE(p.retention_age_seconds, o.retention_age_seconds) AS age_seconds,
           COALESCE(p.retention_revision_count, o.retention_revision_count) AS revision_count,
           CASE
               WHEN p.retention_age_seconds IS NOT NULL THEN FALSE
               ELSE o.retention_mode = 'unlimited'
           END AS is_unlimited,
           s.published_at < sqlc.arg(now)::timestamptz -
               COALESCE(p.retention_age_seconds, o.retention_age_seconds) * INTERVAL '1 second' AS age_expired,
           ROW_NUMBER() OVER (
               PARTITION BY s.org_id, s.project_id, s.environment_id
               ORDER BY s.revision DESC
           ) AS newest_rank
    FROM snapshots AS s
    JOIN projects AS p ON p.org_id = s.org_id AND p.id = s.project_id
    JOIN orgs AS o ON o.id = s.org_id
)
SELECT ranked.id, ranked.org_id, ranked.project_id, ranked.environment_id,
       ranked.revision, ranked.age_seconds, ranked.revision_count
FROM ranked
WHERE NOT ranked.is_unlimited
  AND ranked.payload_present
  AND ranked.age_expired
  AND ranked.newest_rank > ranked.revision_count
  AND NOT EXISTS (
      SELECT 1 FROM revision_pins
      WHERE revision_pins.snapshot_id = ranked.id
        AND revision_pins.expires_at > sqlc.arg(now)::timestamptz
  )
ORDER BY ranked.org_id, ranked.project_id, ranked.environment_id, ranked.revision
LIMIT sqlc.arg(batch_limit);

-- hikyo:instance-scoped
-- name: MarkSnapshotCollected :execrows
UPDATE snapshots
SET payload_present = FALSE,
    collected_at = sqlc.arg(collected_at),
    collected_policy = sqlc.arg(collected_policy)
WHERE snapshots.id = sqlc.arg(snapshot_id) AND snapshots.payload_present
  AND NOT EXISTS (
      SELECT 1 FROM revision_pins
      WHERE revision_pins.snapshot_id = snapshots.id
        AND revision_pins.expires_at > sqlc.arg(now)::timestamptz
  );

-- hikyo:instance-scoped
-- name: DeleteCollectedSnapshotEntries :execrows
DELETE FROM snapshot_entries
WHERE snapshot_id = sqlc.arg(snapshot_id)
  AND EXISTS (
      SELECT 1 FROM snapshots
      WHERE snapshots.id = snapshot_entries.snapshot_id
        AND NOT snapshots.payload_present
  );

-- hikyo:instance-scoped
-- name: GetLastPruneSuccess :one
SELECT last_prune_success FROM retention_runtime WHERE id = 1;

-- hikyo:instance-scoped
-- name: SetLastPruneSuccess :exec
INSERT INTO retention_runtime (id, last_prune_success)
VALUES (1, sqlc.arg(last_prune_success))
ON CONFLICT (id) DO UPDATE
SET last_prune_success = EXCLUDED.last_prune_success;
