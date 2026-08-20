-- +goose Up
-- Per-project machine-reveal opt-in. Roll-forward only. Structurally
-- identical to the sqlite migration; only the scalar type differs.
ALTER TABLE projects ADD COLUMN machine_reveal BOOLEAN NOT NULL DEFAULT FALSE;
