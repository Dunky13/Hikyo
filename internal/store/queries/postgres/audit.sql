-- Audit trails (#45): the application layer holds INSERT and SELECT only on
-- both audit tables - the append-only CI invariant scans this file. The
-- reserved chain_* parameters are bound by the store's binding layer (and,
-- for the denial writer, by the authorization package's enumerated surface)
-- from resolved chains only - never from caller arguments.
--
-- Query page order is seq (allocation order). Export pages use commit_seq,
-- assigned by the deferred commit appender in migration 00010; the public
-- after_seq filter remains a seq lower bound.

-- name: InsertTenantAuditEvent :exec
INSERT INTO audit_tenant_events (
    id, type, schema_version, occurred_at, occurred_asserted,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
) VALUES (
    sqlc.arg(id), sqlc.arg(type), sqlc.arg(schema_version), sqlc.arg(occurred_at),
    sqlc.arg(occurred_asserted),
    sqlc.arg(actor_id), sqlc.arg(actor_class), sqlc.arg(actor_credential_id), sqlc.arg(authority_id),
    sqlc.arg(scope_class), sqlc.arg(chain_org_id), sqlc.arg(project_id), sqlc.arg(env_id),
    sqlc.arg(object_type), sqlc.arg(object_id), sqlc.arg(outcome), sqlc.arg(correlation_id),
    sqlc.arg(source_ip), sqlc.arg(user_agent), sqlc.arg(origin), sqlc.arg(payload)
);

-- name: InsertInstanceAuditEvent :exec
INSERT INTO audit_instance_events (
    id, type, schema_version, occurred_at, occurred_asserted,
    actor_id, actor_class, actor_credential_id, authority_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload
) VALUES (
    sqlc.arg(id), sqlc.arg(type), sqlc.arg(schema_version), sqlc.arg(occurred_at),
    sqlc.arg(occurred_asserted),
    sqlc.arg(actor_id), sqlc.arg(actor_class), sqlc.arg(actor_credential_id), sqlc.arg(authority_id),
    sqlc.arg(object_type), sqlc.arg(object_id), sqlc.arg(outcome), sqlc.arg(correlation_id),
    sqlc.arg(source_ip), sqlc.arg(user_agent), sqlc.arg(origin), sqlc.arg(payload)
);

-- hikyo:authn-resolution
-- name: ClaimOfflineRecord :execrows
INSERT INTO offline_records (principal_id, record_id, created_at)
VALUES (sqlc.arg(principal_id), sqlc.arg(record_id), sqlc.arg(created_at))
ON CONFLICT (principal_id, record_id) DO NOTHING;

-- name: PageTenantAuditOrg :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id) AND seq > sqlc.arg(after_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);

-- name: PageTenantAuditProject :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
    AND seq > sqlc.arg(after_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);

-- name: PageTenantAuditEnv :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
    AND env_id = sqlc.arg(chain_env_id) AND seq > sqlc.arg(after_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);

-- name: PageInstanceAudit :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_instance_events
WHERE seq > sqlc.arg(after_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY seq LIMIT sqlc.arg(page_limit);

-- name: PageTenantAuditExportOrg :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id)
    AND seq > sqlc.arg(after_seq) AND commit_seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY commit_seq LIMIT sqlc.arg(page_limit);

-- name: PageTenantAuditExportProject :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
    AND seq > sqlc.arg(after_seq) AND commit_seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY commit_seq LIMIT sqlc.arg(page_limit);

-- name: PageTenantAuditExportEnv :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    scope_class, org_id, project_id, env_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_tenant_events
WHERE org_id = sqlc.arg(chain_org_id) AND project_id = sqlc.arg(chain_project_id)
    AND env_id = sqlc.arg(chain_env_id)
    AND seq > sqlc.arg(after_seq) AND commit_seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY commit_seq LIMIT sqlc.arg(page_limit);

-- name: PageInstanceAuditExport :many
SELECT seq, id, type, schema_version, occurred_at, occurred_asserted, recorded_at,
    actor_id, actor_class, actor_credential_id, authority_id,
    object_type, object_id, outcome, correlation_id,
    source_ip, user_agent, origin, payload, commit_seq
FROM audit_instance_events
WHERE seq > sqlc.arg(after_seq) AND commit_seq > sqlc.arg(after_commit_seq)
    AND recorded_at >= sqlc.arg(from_time) AND recorded_at <= sqlc.arg(to_time)
ORDER BY commit_seq LIMIT sqlc.arg(page_limit);
