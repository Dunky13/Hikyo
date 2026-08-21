-- +goose Up
-- Per-project machine-reveal opt-in (source-of-truth ADR: "Granting `reveal`
-- to a machine identity is an explicit, documented, per-project operator
-- opt-in"; machine-identities ADR section "Authentication, authorization and
-- the fetch path"; permission-model ADR section "Machine principal
-- allowlists"). Roll-forward only.
--
-- machine_reveal is a project-settings write. While it is 0 (the default) no
-- machine principal may be granted `reveal` in this project and no machine
-- fetch delivers secret plaintext, whatever grant rows exist; flipping it
-- back to 0 withdraws delivery on the next fetch without touching the grants
-- (every fetch re-authorizes against current policy) and moves every machine
-- cursor, because the authorized delivery projection changed.
ALTER TABLE projects ADD COLUMN machine_reveal INTEGER NOT NULL DEFAULT 0
    CHECK (machine_reveal IN (0, 1));
