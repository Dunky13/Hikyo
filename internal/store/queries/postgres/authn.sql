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
SELECT id FROM orgs WHERE id = $1;

-- wenv:authn-resolution
-- name: ResolveProjectChain :one
SELECT org_id, id FROM projects WHERE org_id = $1 AND id = $2;

-- wenv:authn-resolution
-- name: ResolveEnvChain :one
SELECT org_id, project_id, id FROM environments
WHERE org_id = $1 AND project_id = $2 AND id = $3;

-- wenv:authn-resolution
-- name: ListGrantsForPrincipal :many
SELECT capability, org_id, project_id, env_id FROM grants
WHERE principal_id = $1;
