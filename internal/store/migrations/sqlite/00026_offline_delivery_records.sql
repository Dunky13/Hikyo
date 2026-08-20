-- +goose Up
-- Idempotency ledger for client-durable offline disclosure reconciliation.
-- The principal and client record id are the whole dedupe identity; audit rows
-- remain append-only and are never queried as mutable application state.
-- hikyo:table offline_records class=authn chain=-
CREATE TABLE offline_records (
    principal_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, record_id)
);
