-- +goose Up
-- Roll-forward only: no Down section by policy (system-architecture ADR).
CREATE TABLE orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL,
    metadata TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
