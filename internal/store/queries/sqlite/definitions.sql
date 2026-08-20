-- Definitions plan ledger (#70). Tenant-scoped statements: the chain conjunct
-- is bound by the store's binding layer from proof fields only, never from
-- caller arguments. A plan is immutable except for the one-shot apply stamp.

-- name: CreatePlan :exec
INSERT INTO definitions_plans (
    id, org_id, project_id, created_by, created_at, expires_at,
    bundle, digest, base_schema_revision, env_revisions, protected_envs, diff, additive
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetPlan :one
SELECT id, org_id, project_id, created_by, created_at, expires_at,
       bundle, digest, base_schema_revision, env_revisions, protected_envs, diff, additive, applied,
       applied_at, applied_by, provenance_commit, provenance_ref, provenance_actor
FROM definitions_plans
WHERE org_id = ? AND project_id = ? AND id = ?;

-- GetLatestAppliedPlan is the last-applied provenance record the settings view
-- reads: the most recently applied plan for the project, or no row when none has
-- ever been applied.
-- name: GetLatestAppliedPlan :one
SELECT id, org_id, project_id, created_by, created_at, expires_at,
       bundle, digest, base_schema_revision, env_revisions, protected_envs, diff, additive, applied,
       applied_at, applied_by, provenance_commit, provenance_ref, provenance_actor
FROM definitions_plans
WHERE org_id = ? AND project_id = ? AND applied = ?
ORDER BY applied_at DESC
LIMIT 1;

-- CountOpenPlans is the open-plan quota's input: a plan is open when it is
-- unapplied and unexpired. Read inside the create transaction it bounds.
-- name: CountOpenPlans :one
SELECT COUNT(*) FROM definitions_plans
WHERE org_id = ? AND project_id = ? AND applied = ? AND expires_at > ?;

-- MarkPlanApplied stamps the one-shot apply record. The applied = 0
-- guard makes a second apply of the same plan affect zero rows, which the
-- service maps to the already-applied conflict.
-- name: MarkPlanApplied :execrows
UPDATE definitions_plans
SET applied = 1, applied_at = ?, applied_by = ?,
    provenance_commit = ?, provenance_ref = ?, provenance_actor = ?
WHERE org_id = ? AND project_id = ? AND id = ? AND applied = ?;

-- PruneExpiredPlans deletes expired, unapplied plans across the instance, run
-- by the hourly retention GC. Applied plans are kept as provenance records and
-- never pruned.
-- hikyo:instance-scoped
-- name: PruneExpiredPlans :execrows
DELETE FROM definitions_plans WHERE applied = 0 AND expires_at <= ?;
