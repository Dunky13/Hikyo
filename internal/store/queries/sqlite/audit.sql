-- Audit trails (#45): the application layer holds INSERT and SELECT only on
-- both audit tables - the append-only CI invariant scans this file. Chain
-- parameters are bound by the store's binding layer (and, for the denial
-- writer, by the authorization package's enumerated surface) from resolved
-- chains only - never from caller arguments.
--
-- Interactive and export page order is seq (allocation equals commit order on
-- sqlite). Export queries use the same seq column for their selection floor
-- and internal page cursor. Timestamps are fixed-width UTC microsecond text,
-- so recorded_at range predicates compare correctly.

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

-- Export query names mirror postgres for the predicate-confinement parity
-- invariant. sqlite's single writer makes commit order equal seq order.

-- name: PageTenantAuditExportOrg :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id)
    AND seq > sqlc.arg(after_seq) AND seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);

-- name: PageTenantAuditExportProject :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
    AND seq > sqlc.arg(after_seq) AND seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);

-- name: PageTenantAuditExportEnv :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
    AND env_id = sqlc.arg(chain_env_id)
    AND seq > sqlc.arg(after_seq) AND seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);

-- name: PageInstanceAuditExport :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
FROM audit_instance_events
WHERE seq > sqlc.arg(after_seq) AND seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);
