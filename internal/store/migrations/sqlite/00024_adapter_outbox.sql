-- +goose Up
-- Deployment adapter outbox + Forgejo reference adapter (#65).
-- Roll-forward only; no Down migrations.
-- hikyo:table adapters class=project chain=org_id,project_id
-- hikyo:table adapter_targets class=environment chain=org_id,project_id
-- hikyo:table adapter_target_keys class=environment chain=org_id,project_id
-- hikyo:table adapter_ledger class=environment chain=org_id,project_id
-- hikyo:table adapter_conflicts class=environment chain=org_id,project_id
-- hikyo:table adapter_outbox class=environment chain=org_id,project_id
-- hikyo:table adapter_effects class=environment chain=org_id,project_id
-- hikyo:table adapter_route_moves class=project chain=org_id,project_id
-- hikyo:table adapter_route_move_targets class=environment chain=org_id,project_id
-- hikyo:table adapter_route_move_keys class=environment chain=org_id,project_id
-- hikyo:table adapter_route_move_claims class=environment chain=org_id,project_id

-- Adapter ceremonies are purpose-, operation-, and environment-set-bound.
-- Existing reveal/workspace windows remain unbound through empty defaults.
ALTER TABLE reauth_windows ADD COLUMN bound_purpose TEXT NOT NULL DEFAULT '';
ALTER TABLE reauth_windows ADD COLUMN bound_environment_set TEXT NOT NULL DEFAULT '';

-- A CLI adapter reauthentication handoff. State and code are verifier-only;
-- PKCE binds redemption to the initiating shell, and consumed_at is the
-- atomic single-use claim. approved_windows contains metadata only, never a
-- bearer or provider credential.
-- hikyo:table cli_reauth_handoffs class=authn chain=-
CREATE TABLE cli_reauth_handoffs (
    id TEXT PRIMARY KEY,
    state_verifier BLOB NOT NULL UNIQUE,
    code_verifier BLOB UNIQUE,
    session_id TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals (id),
    operation TEXT NOT NULL CHECK (operation IN ('adapter.configure','adapter.credential-set','adapter.adopt','adapter.sync')),
    environment_set TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    approved_windows TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(approved_windows)),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE TABLE adapters (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'forgejo'),
    origin TEXT NOT NULL,
    credential_ciphertext BLOB,
    credential_set_at TEXT,
    authority_principal_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'moving', 'tombstoned')),
    created_at TEXT NOT NULL,
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, origin),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    FOREIGN KEY (authority_principal_id) REFERENCES principals (id)
);

CREATE TABLE adapter_targets (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('repository', 'organization')),
    destination_owner TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    destination_id INTEGER NOT NULL CHECK (destination_id > 0),
    name_prefix TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL CHECK (state IN ('active', 'moving', 'tombstoned')),
    sync_status TEXT NOT NULL CHECK (sync_status IN ('never', 'converging', 'converged', 'failed')),
    failure_names TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(failure_names)),
    converged_revision INTEGER,
    active_job_id TEXT,
    provider_lease_job_id TEXT,
    provider_lease_effect_id TEXT,
    provider_lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, environment_id, id),
    UNIQUE (adapter_id, destination_kind, destination_owner, destination_name, environment_id),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, adapter_id) REFERENCES adapters (org_id, project_id, id)
);

CREATE TABLE adapter_target_keys (
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    PRIMARY KEY (target_id, key_id),
    FOREIGN KEY (org_id, project_id, environment_id, target_id) REFERENCES adapter_targets (org_id, project_id, environment_id, id),
    FOREIGN KEY (org_id, project_id, adapter_id) REFERENCES adapters (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, key_id) REFERENCES keys (org_id, project_id, id) ON DELETE CASCADE
);

CREATE TABLE adapter_ledger (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    provider_origin TEXT NOT NULL,
    destination_id INTEGER NOT NULL,
    surface TEXT NOT NULL CHECK (surface IN ('secret', 'variable')),
    effective_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'dispatched', 'owned', 'released')),
    updated_at TEXT NOT NULL,
    UNIQUE (target_id, surface, normalized_name),
    FOREIGN KEY (org_id, project_id, environment_id, target_id) REFERENCES adapter_targets (org_id, project_id, environment_id, id)
);
CREATE UNIQUE INDEX adapter_ledger_active_provider_name
    ON adapter_ledger (provider_origin, destination_id, surface, normalized_name)
    WHERE state <> 'released';

CREATE TABLE adapter_route_moves (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    target_id TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('origin', 'target')),
    pending_origin TEXT,
    pending_credential_ciphertext BLOB,
    authority_principal_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('scrubbing', 'activating', 'attention_required', 'completed', 'canceled')),
    keep_remote INTEGER NOT NULL CHECK (keep_remote IN (0, 1)),
    created_at TEXT NOT NULL,
    UNIQUE (org_id, project_id, id),
    CHECK (state IN ('completed','canceled') OR (kind = 'origin' AND target_id IS NULL AND pending_origin IS NOT NULL AND pending_credential_ciphertext IS NOT NULL)
        OR (kind = 'target' AND target_id IS NOT NULL AND pending_origin IS NULL AND pending_credential_ciphertext IS NULL)),
    FOREIGN KEY (org_id, project_id, adapter_id) REFERENCES adapters (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, target_id) REFERENCES adapter_targets (org_id, project_id, id),
    FOREIGN KEY (authority_principal_id) REFERENCES principals (id)
);
CREATE UNIQUE INDEX adapter_route_moves_pending_origin
    ON adapter_route_moves (org_id, project_id, pending_origin)
    WHERE pending_origin IS NOT NULL AND state NOT IN ('completed','canceled');
CREATE UNIQUE INDEX adapter_route_moves_active_adapter
    ON adapter_route_moves (adapter_id) WHERE state NOT IN ('completed','canceled');

CREATE TABLE adapter_route_move_targets (
    move_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('repository', 'organization')),
    destination_owner TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    destination_id INTEGER NOT NULL CHECK (destination_id >= 0),
    name_prefix TEXT NOT NULL,
    orphaned_names TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(orphaned_names)),
    PRIMARY KEY (move_id, target_id),
    UNIQUE (org_id, project_id, environment_id, move_id, target_id),
    FOREIGN KEY (org_id, project_id, move_id) REFERENCES adapter_route_moves (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, environment_id, target_id) REFERENCES adapter_targets (org_id, project_id, environment_id, id)
);

CREATE TABLE adapter_route_move_keys (
    move_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    PRIMARY KEY (move_id, target_id, key_id),
    UNIQUE (org_id, project_id, environment_id, move_id, target_id, key_id),
    FOREIGN KEY (org_id, project_id, environment_id, move_id, target_id) REFERENCES adapter_route_move_targets (org_id, project_id, environment_id, move_id, target_id),
    FOREIGN KEY (org_id, project_id, key_id) REFERENCES keys (org_id, project_id, id) ON DELETE CASCADE
);

CREATE TABLE adapter_route_move_claims (
    move_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    key_id TEXT,
    provider_origin TEXT NOT NULL,
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('repository', 'organization')),
    destination_owner TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    surface TEXT NOT NULL CHECK (surface IN ('secret', 'variable')),
    effective_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    PRIMARY KEY (move_id, target_id, surface, normalized_name),
    UNIQUE (provider_origin, destination_kind, destination_owner, destination_name, surface, normalized_name),
    FOREIGN KEY (org_id, project_id, environment_id, move_id, target_id) REFERENCES adapter_route_move_targets (org_id, project_id, environment_id, move_id, target_id),
    FOREIGN KEY (org_id, project_id, environment_id, move_id, target_id, key_id) REFERENCES adapter_route_move_keys (org_id, project_id, environment_id, move_id, target_id, key_id) ON DELETE CASCADE
);

CREATE TABLE adapter_conflicts (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    job_id TEXT,
    destination_id INTEGER NOT NULL,
    target_generation INTEGER NOT NULL,
    surface TEXT NOT NULL CHECK (surface IN ('secret', 'variable')),
    effective_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    adopted_at TEXT,
    UNIQUE (artifact_id, surface, effective_name),
    FOREIGN KEY (org_id, project_id, environment_id, target_id) REFERENCES adapter_targets (org_id, project_id, environment_id, id),
    FOREIGN KEY (org_id, project_id, environment_id, job_id) REFERENCES adapter_outbox (org_id, project_id, environment_id, id)
);

CREATE TABLE adapter_outbox (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('converge', 'scrub', 'activate')),
    route_move_id TEXT,
    authority_principal_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    dedup_key TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'superseded')),
    created_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE (org_id, project_id, environment_id, id),
    FOREIGN KEY (org_id, project_id, environment_id, target_id) REFERENCES adapter_targets (org_id, project_id, environment_id, id),
    FOREIGN KEY (org_id, project_id, route_move_id) REFERENCES adapter_route_moves (org_id, project_id, id),
    FOREIGN KEY (authority_principal_id) REFERENCES principals (id),
    CHECK (kind <> 'activate' OR route_move_id IS NOT NULL)
);
CREATE UNIQUE INDEX adapter_outbox_active_dedup
    ON adapter_outbox (dedup_key) WHERE state IN ('queued', 'running');
CREATE INDEX adapter_outbox_due ON adapter_outbox (state, next_attempt_at);

CREATE TABLE adapter_effects (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    surface TEXT NOT NULL CHECK (surface IN ('secret', 'variable')),
    effective_name TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition IN ('create', 'update', 'delete')),
    intent_audit_id TEXT NOT NULL UNIQUE,
    outcome_audit_id TEXT UNIQUE,
    outcome TEXT CHECK (outcome IN ('success', 'failure', 'unknown')),
    created_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (org_id, project_id, environment_id, target_id) REFERENCES adapter_targets (org_id, project_id, environment_id, id),
    FOREIGN KEY (org_id, project_id, environment_id, job_id) REFERENCES adapter_outbox (org_id, project_id, environment_id, id)
);
