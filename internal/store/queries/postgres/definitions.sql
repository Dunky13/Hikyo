-- Definitions plan ledger (#70). Tenant-scoped statements: the reserved chain_*
-- parameters are bound by the store's binding layer from proof fields only,
-- never from caller arguments; the SQL predicate analyzer enforces the conjunct
-- shape.

-- name: CreatePlan :exec
INSERT INTO definitions_plans (
    id, org_id, project_id, created_by, created_at, expires_at,
    bundle, digest, base_schema_revision, env_revisions, protected_envs, diff, additive, scan_snapshot
) VALUES (
    sqlc.arg(id), sqlc.arg(chain_org_id), sqlc.arg(chain_project_id), sqlc.arg(created_by),
    sqlc.arg(created_at), sqlc.arg(expires_at), sqlc.arg(bundle), sqlc.arg(digest),
    sqlc.arg(base_schema_revision), sqlc.arg(env_revisions), sqlc.arg(protected_envs),
    sqlc.arg(diff), sqlc.arg(additive), sqlc.arg(scan_snapshot)
);

-- name: GetPlan :one
SELECT id, org_id, project_id, created_by, created_at, expires_at,
       bundle, digest, base_schema_revision, env_revisions, protected_envs, diff, additive, applied,
       applied_at, applied_by, provenance_commit, provenance_ref, provenance_actor, scan_snapshot
FROM definitions_plans
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id) AND id = sqlc.arg(id);

-- GetLatestAppliedPlan is the last-applied provenance record the settings view
-- reads: the most recently applied plan for the project, or no row when none has
-- ever been applied.
-- name: GetLatestAppliedPlan :one
SELECT id, org_id, project_id, created_by, created_at, expires_at,
       bundle, digest, base_schema_revision, env_revisions, protected_envs, diff, additive, applied,
       applied_at, applied_by, provenance_commit, provenance_ref, provenance_actor, scan_snapshot
FROM definitions_plans
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
      AND applied = sqlc.arg(applied)
ORDER BY applied_at DESC
LIMIT 1;

-- CountOpenPlans is the open-plan quota's input: a plan is open when it is
-- unapplied and unexpired. Read inside the create transaction it bounds.
-- name: CountOpenPlans :one
SELECT COUNT(*) FROM definitions_plans
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
      AND applied = sqlc.arg(applied) AND expires_at > sqlc.arg(now);

-- MarkPlanApplied stamps the one-shot apply record. The applied = false
-- guard makes a second apply of the same plan affect zero rows, which the
-- service maps to the already-applied conflict.
-- name: MarkPlanApplied :execrows
UPDATE definitions_plans
SET applied = TRUE, applied_at = sqlc.arg(applied_at), applied_by = sqlc.arg(applied_by),
    provenance_commit = sqlc.narg(provenance_commit), provenance_ref = sqlc.narg(provenance_ref),
    provenance_actor = sqlc.narg(provenance_actor)
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
      AND id = sqlc.arg(id) AND applied = sqlc.arg(applied);

-- PruneExpiredPlans deletes expired, unapplied plans across the instance, run
-- by the hourly retention GC. Applied plans are kept as provenance records and
-- never pruned.
-- hikyo:instance-scoped
-- name: PruneExpiredPlans :execrows
DELETE FROM definitions_plans WHERE applied = FALSE AND expires_at <= sqlc.arg(now);
