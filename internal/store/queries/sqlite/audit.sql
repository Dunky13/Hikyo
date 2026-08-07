-- Audit trails (#45): the application layer holds INSERT and SELECT only on
-- both audit tables - the append-only CI invariant scans this file. Chain
-- parameters are bound by the store's binding layer (and, for the denial
-- writer, by the authorization package's enumerated surface) from resolved
-- chains only - never from caller arguments.
--
-- Page order is seq (allocation order); the cursor is `seq > ?`. Timestamps
-- are fixed-width UTC microsecond text on this engine, so recorded_at range
-- predicates compare correctly.

-- name: InsertTenantAuditEvent :exec
INSERT INTO audit_tenant_events (
    id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertInstanceAuditEvent :exec
INSERT INTO audit_instance_events (
    id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: PageTenantAuditOrg :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_tenant_events
WHERE org_id = ? AND seq > ? AND recorded_at >= ? AND recorded_at <= ?
ORDER BY seq LIMIT ?;

-- name: PageTenantAuditProject :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_tenant_events
WHERE org_id = ? AND project_id = ? AND seq > ? AND recorded_at >= ? AND recorded_at <= ?
ORDER BY seq LIMIT ?;

-- name: PageTenantAuditEnv :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_tenant_events
WHERE org_id = ? AND project_id = ? AND env_id = ? AND seq > ? AND recorded_at >= ? AND recorded_at <= ?
ORDER BY seq LIMIT ?;

-- name: PageInstanceAudit :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_instance_events
WHERE seq > ? AND recorded_at >= ? AND recorded_at <= ?
ORDER BY seq LIMIT ?;
