-- +goose Up
-- Secret-scanning plan pin (#74 SS3, secret-scanning ADR section 7 (c)).
-- Roll-forward only. A definitions plan records the scanning ruleset snapshot
-- version it was scanned under, so `definitions apply` re-scans iff the running
-- ruleset differs from the pinned one; a same-version apply adds no second scan.
-- The default is the empty string, which an apply under a wired ruleset reads as
-- skew and re-scans -- the correct fail-safe for any pre-existing plan row.
ALTER TABLE definitions_plans ADD COLUMN scan_snapshot TEXT NOT NULL DEFAULT '';
