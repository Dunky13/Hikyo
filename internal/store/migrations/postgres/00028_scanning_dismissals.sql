-- +goose Up
-- Secret-scanning dismissal rows (#74, secret-scanning ADR §4).
-- Roll-forward only: no Down section by policy (system-architecture ADR).
--
-- A dismissal is the "keep as config" escape hatch for a Surface-1 warn: an
-- explicit, sticky acknowledgement that a config-classified value which looks
-- like a credential is accepted as-is, so the identical value does not re-warn
-- on every save. It is keyed by (org, project, environment, key identity, rule
-- semantic digest, value fingerprint) — the ADR's dismissal identity, spelled
-- exactly.
--
-- WHY EACH IDENTITY COLUMN:
--   * `rule_digest` is a digest of the COMPILED rule definition (regex +
--     consumed fields), never the rule ID. An upstream pin bump that changes a
--     rule's detector changes its digest, so the dismissal re-fires by
--     construction — rule-ID reuse cannot silently carry an old dismissal
--     forward.
--   * `value_fingerprint` is a KEYED digest (crypto.ScanningFingerprint) under
--     the tier-3 scanning key, over the canonical stored value bytes. It is
--     never a bare hash: a bare hash in a stolen database is an
--     offline-verifiable oracle for guessable values. The fingerprint is the
--     ONLY place the derived value artifact is persisted, and it never enters an
--     audit payload (§5).
--
-- The chain is org+project with `environment_id` an ordinary addressed column —
-- the same shape value_entries (00015) and key_presence_environments (00013)
-- use, and for the same reason: the warn/dismiss paths are environment-scoped
-- and bind environment_id from the proof, while key-scoped and instance-scoped
-- deletes (reclassify-drop, key delete, rotation) span environments.
--
-- LIFECYCLE (ADR §4), all in the safe direction (re-fire):
--   * key deletion deletes the key's rows — the composite FK to `keys` refuses
--     to drop a key while any dismissal references it, so key delete removes
--     them first (DeleteByKey);
--   * reclassification to secret drops the key's rows (moot) — DeleteByKey;
--   * project deletion removes the project's rows — transitively, because a
--     project cannot be deleted while it holds keys and a key cannot be dropped
--     while it holds dismissals; DeleteByProject is provided for the ADR-literal
--     removal and explicit-order cleanup;
--   * scanning-key rotation drops ALL rows (DeleteAll) — old fingerprints must
--     die, that is the rotation's purpose.
-- Rows travel in backup/restore with the database like any other tenant row.
--
-- hikyo:table scanning_dismissals class=environment chain=org_id,project_id
CREATE TABLE scanning_dismissals (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    rule_digest TEXT NOT NULL,
    value_fingerprint BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    UNIQUE (org_id, project_id, environment_id, key_id, rule_digest, value_fingerprint),
    FOREIGN KEY (org_id, project_id, key_id) REFERENCES keys (org_id, project_id, id)
);
