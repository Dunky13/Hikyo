-- +goose Up
-- Idempotency ledger for client-durable offline disclosure reconciliation.
-- hikyo:table offline_records class=authn chain=-
CREATE TABLE offline_records (
    principal_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (principal_id, record_id)
);
