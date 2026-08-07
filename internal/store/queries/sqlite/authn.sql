-- The authorization package's enumerated resolution surface (tenant-isolation
-- ADR bootstrap carve-out): the only statements that read chain tables with
-- request-supplied identifiers, because authorize() runs them to mint the
-- proof everything else requires. Each is annotated and content-pinned in the
-- allowlist fixture - drift fails the build until re-reviewed.

-- Chain resolution is one query, one round trip, regardless of which level
-- is missing: the denormalized chain columns plus composite ancestry FKs make
-- the addressed row's own chain authoritative, so no per-level walk exists.

-- wenv:authn-resolution
-- name: ResolveOrgChain :one
SELECT id FROM orgs WHERE id = ?;

-- wenv:authn-resolution
-- name: ResolveProjectChain :one
SELECT org_id, id FROM projects WHERE org_id = ? AND id = ?;

-- wenv:authn-resolution
-- name: ResolveEnvChain :one
SELECT org_id, project_id, id FROM environments
WHERE org_id = ? AND project_id = ? AND id = ?;

-- wenv:authn-resolution
-- name: ListGrantsForPrincipal :many
SELECT capability, org_id, project_id, env_id FROM grants
WHERE principal_id = ?;

-- The denial writer's actor-class lookup (#45, audit-model ADR amendment
-- part 4): the flush transaction resolves the denied principal's kind for
-- the event's actor class. Runs only inside authn.WriteDenial.

-- wenv:authn-resolution
-- name: GetPrincipalKind :one
SELECT kind FROM principals WHERE id = ?;
