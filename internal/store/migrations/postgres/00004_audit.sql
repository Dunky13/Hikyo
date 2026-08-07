-- +goose Up
-- Audit trails (#45, audit-model ADR). Two append-only tables, because the
-- trail spans two scope classes: the tenant trail is org-owned, the instance
-- trail holds instance-, system- and unauthenticated-class events including
-- unresolvable denials. Application layer holds INSERT and SELECT only
-- (append-only CI invariant); no UPDATE/DELETE statement exists until the
-- retention-pruning job and the org-deletion cascade land their two
-- content-pinned deletion queries.
--
-- The audit tables carry the chain as immutable denormalized ids and are
-- DELIBERATELY WITHOUT ancestry FKs (the composite-FK rule's single declared
-- exception, audit-model ADR amendment part 5): an audit event must outlive
-- its subject - a deleted key, a revoked credential, a deleted environment -
-- so referential integrity to live parent rows is structurally wrong here.
--
-- seq is unique and strictly increasing at allocation, per table. On
-- postgres, sequence allocation precedes commit and commit order can differ:
-- seq is NOT a commit-order total, and neither seq nor recorded_at is a
-- forensic total order under concurrency (audit-model ADR, stated).
-- Gaplessness is promised nowhere.
--
-- wenv:table audit_tenant_events class=org chain=org_id
-- wenv:table audit_instance_events class=instance chain=-

CREATE TABLE audit_tenant_events (
    seq BIGSERIAL PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    occurred_asserted BOOLEAN NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    actor_id TEXT,
    actor_class TEXT NOT NULL CHECK (
        actor_class IN ('human', 'machine', 'system', 'break-glass', 'unauthenticated')
    ),
    actor_credential_id TEXT,
    authority_id TEXT,
    scope_class TEXT NOT NULL CHECK (scope_class IN ('org', 'project', 'env')),
    org_id TEXT NOT NULL,
    project_id TEXT,
    env_id TEXT,
    object_type TEXT,
    object_id TEXT,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('intent', 'success', 'denied', 'failure', 'unknown', 'disconnected')
    ),
    correlation_id TEXT,
    source_ip TEXT,
    user_agent TEXT,
    origin TEXT NOT NULL CHECK (
        origin IN ('web', 'cli', 'api', 'operator-fetch', 'adapter-job', 'offline-reconciled', 'system')
    ),
    payload TEXT NOT NULL,
    CHECK (
        (scope_class = 'org' AND project_id IS NULL AND env_id IS NULL)
        OR (scope_class = 'project' AND project_id IS NOT NULL AND env_id IS NULL)
        OR (scope_class = 'env' AND project_id IS NOT NULL AND env_id IS NOT NULL)
    )
);

CREATE INDEX audit_tenant_events_org_seq ON audit_tenant_events (org_id, seq);

CREATE TABLE audit_instance_events (
    seq BIGSERIAL PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    occurred_asserted BOOLEAN NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    actor_id TEXT,
    actor_class TEXT NOT NULL CHECK (
        actor_class IN ('human', 'machine', 'system', 'break-glass', 'unauthenticated')
    ),
    actor_credential_id TEXT,
    authority_id TEXT,
    object_type TEXT,
    object_id TEXT,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('intent', 'success', 'denied', 'failure', 'unknown', 'disconnected')
    ),
    correlation_id TEXT,
    source_ip TEXT,
    user_agent TEXT,
    origin TEXT NOT NULL CHECK (
        origin IN ('web', 'cli', 'api', 'operator-fetch', 'adapter-job', 'offline-reconciled', 'system')
    ),
    payload TEXT NOT NULL
);
