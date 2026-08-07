-- +goose Up
-- Tenant chain + authorization data (#44, tenant-isolation ADR).
-- Composite ancestry FKs: parents expose composite unique keys and children
-- reference the composite, so a row's chain is consistent by constraint —
-- independent single-column FKs would accept an inconsistent chain.
-- Roll-forward only: no Down section by policy (system-architecture ADR).
--
-- Scope-class declarations (tenant-isolation ADR: "every table declares its
-- scope class in migration metadata"). The SQL predicate analyzer and the
-- invariant tests derive the tenant-table registry from these directives; a
-- table with no directive fails the build. `chain` names the tenant-chain
-- columns the analyzer requires as top-level conjuncts (`-` = none).
--
-- wenv:table orgs class=org chain=id
-- wenv:table projects class=project chain=org_id
-- wenv:table environments class=environment chain=org_id,project_id
-- wenv:table principals class=instance chain=-
-- wenv:table grants class=authn chain=-

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (org_id, id),
    UNIQUE (org_id, name)
);

CREATE TABLE environments (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, name)
);

CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('human', 'machine')),
    created_at TIMESTAMPTZ NOT NULL
);

-- A grant is the permission ADR's (principal, capability, scope) triple.
-- Scope is the chain to the granted level; the CHECK forbids gaps, and the
-- composite FKs (MATCH SIMPLE: enforced only when all their columns are
-- non-null) keep a non-instance scope consistent with the chain tables.
CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals (id),
    capability TEXT NOT NULL,
    org_id TEXT,
    project_id TEXT,
    env_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (
        (org_id IS NULL AND project_id IS NULL AND env_id IS NULL)
        OR (org_id IS NOT NULL AND project_id IS NULL AND env_id IS NULL)
        OR (org_id IS NOT NULL AND project_id IS NOT NULL AND env_id IS NULL)
        OR (org_id IS NOT NULL AND project_id IS NOT NULL AND env_id IS NOT NULL)
    ),
    FOREIGN KEY (org_id) REFERENCES orgs (id),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    FOREIGN KEY (org_id, project_id, env_id) REFERENCES environments (org_id, project_id, id)
);
-- No uniqueness over (principal, capability, scope): NULL scope columns make
-- UNIQUE semantics diverge between engines (sqlite: NULLs distinct; postgres
-- would need NULLS NOT DISTINCT). Duplicate-grant refusal is the grant API's
-- job (#55); evaluation is set-shaped, so duplicates change nothing here.
