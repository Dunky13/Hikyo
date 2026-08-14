-- +goose Up
-- Retention policy and payload collection (#53, ops-spec retention and
-- revision-model ADR). Roll-forward only: collected material is intentionally
-- unrestorable, so a Down migration would make a promise the data cannot keep.
--
-- THREE RETENTION CLASSES:
--
--   * org/project policy columns are tenant configuration. Org policy is born
--     at keep-if-either(90 days, 10 revisions); `unlimited` is a stored mode,
--     never an absent-value default. Project NULLs mean inherit-until-modified.
--   * revision_pins from #52 are the durable retention claims. Expiry ends
--     retention protection but never delivery, so expired rows remain stored.
--   * retention_runtime is instance operational state. It is not audit data:
--     prune failures and staleness are ops-log facts, while successful policy
--     changes are the security audit events.
--
-- snapshots remains permanent LINEAGE. payload_present is #52's presence bit;
-- collected_at and collected_policy add the named-refusal bookkeeping. Their
-- combined CHECK makes the three columns one fact. snapshot_entries remains the
-- only value-bearing history. The stamped policy cannot be rewritten later.
--
-- hikyo:table retention_runtime class=instance chain=-

ALTER TABLE orgs ADD COLUMN retention_mode TEXT NOT NULL DEFAULT 'keep-if-either'
    CHECK (retention_mode IN ('keep-if-either', 'unlimited'));
ALTER TABLE orgs ADD COLUMN retention_age_seconds INTEGER NOT NULL DEFAULT 7776000
    CHECK (retention_age_seconds > 0);
ALTER TABLE orgs ADD COLUMN retention_revision_count INTEGER NOT NULL DEFAULT 10
    CHECK (retention_revision_count > 0);

ALTER TABLE projects ADD COLUMN retention_revision_count INTEGER
    CHECK (retention_revision_count IS NULL OR retention_revision_count > 0);
ALTER TABLE projects ADD COLUMN retention_age_seconds INTEGER
    CHECK (
        (retention_age_seconds IS NULL AND retention_revision_count IS NULL)
        OR (retention_age_seconds > 0 AND retention_revision_count > 0)
    );

ALTER TABLE snapshots ADD COLUMN collected_at TEXT;
ALTER TABLE snapshots ADD COLUMN collected_policy TEXT NOT NULL DEFAULT ''
    CHECK (
        (payload_present = 1 AND collected_at IS NULL AND collected_policy = '')
        OR (payload_present = 0 AND collected_at IS NOT NULL AND collected_policy <> '')
    );
CREATE INDEX snapshots_retention_scan_idx
    ON snapshots (org_id, project_id, environment_id, revision DESC, published_at);

CREATE TABLE retention_runtime (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_prune_success TEXT
);
