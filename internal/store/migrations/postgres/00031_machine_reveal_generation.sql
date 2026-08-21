-- +goose Up
-- machine_reveal_generation: see the sqlite migration. Roll-forward only.
ALTER TABLE projects ADD COLUMN machine_reveal_generation BIGINT NOT NULL DEFAULT 0;
