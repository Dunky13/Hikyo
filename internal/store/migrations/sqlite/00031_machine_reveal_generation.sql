-- +goose Up
-- machine_reveal_generation advances on every flip of the machine-reveal
-- opt-in and is bound into every machine delivery cursor, so a flip moves the
-- cursor even for a principal whose grant rows make it invisible, and across
-- an off-on-off pair between two polls (machine-identities ADR: any
-- authorization movement invalidates the cursor). Roll-forward only.
ALTER TABLE projects ADD COLUMN machine_reveal_generation INTEGER NOT NULL DEFAULT 0;
