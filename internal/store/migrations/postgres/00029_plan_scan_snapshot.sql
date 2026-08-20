-- +goose Up
-- Secret-scanning plan pin (#74 SS3, secret-scanning ADR section 7 (c)).
-- Roll-forward only. Structurally identical to the sqlite migration.
ALTER TABLE definitions_plans ADD COLUMN scan_snapshot TEXT NOT NULL DEFAULT '';
