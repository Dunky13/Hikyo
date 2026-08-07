-- +goose Up
-- Canonical cross-engine semantics (system-architecture ADR): timestamps as
-- UTC RFC 3339 text, booleans as integers, JSON as text validated at the
-- boundary. Roll-forward only: no Down section by policy.
CREATE TABLE orgs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL,
    metadata TEXT NOT NULL,
    created_at TEXT NOT NULL
);
