-- +goose Up
-- The workspace session's assurance record (#71, multi-instance ADR).
-- Roll-forward only: no Down section by policy.
--
-- STRUCTURALLY IDENTICAL to the sqlite dialect, which carries the reasoning.
-- Nothing differs here — TEXT is TEXT on both engines and neither the default
-- nor the NOT NULL needs a dialect note — but the file exists because a
-- migration that landed on one engine only is exactly the drift the
-- cross-engine parity lint is there to refuse.
ALTER TABLE workspace_handoffs ADD COLUMN factors TEXT NOT NULL DEFAULT '[]';
ALTER TABLE workspace_handoffs ADD COLUMN factor_class TEXT NOT NULL DEFAULT '';
DELETE FROM workspace_handoffs;
ALTER TABLE reauth_windows ADD COLUMN bound_operation TEXT NOT NULL DEFAULT '';
ALTER TABLE reauth_windows ADD COLUMN bound_key_set TEXT NOT NULL DEFAULT '';
