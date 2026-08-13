-- +goose Up
-- The flat value model (#50, flat-model ADR, encryption ADR § Envelope format).
-- Roll-forward only: no Down section by policy (system-architecture ADR).
--
-- THE WHOLE MODEL IS THIS TABLE. A Value attaches to a (key, environment) and
-- there are no other layers: no project-defaults row, no `base` pointer, no
-- non-environment value row. Resolution is a lookup, not a walk.
--
-- PRESENCE IS TWO-STATE AND IS SPELLED BY THE ROW'S EXISTENCE. `set` is a row;
-- `absent` is no row. There is deliberately no presence column, because a
-- column with two states and a NULL is three states, and the third one is the
-- `masked` state the flat model deleted. Clearing a value DELETES the row, and
-- with no inheritance there is nothing underneath for it to fall back to —
-- which is the "no fallback source exists" half of mvp-boundary C2, held by the
-- schema rather than by a service-layer promise.
--
-- The chain is org+project, with `environment_id` an ordinary addressed column
-- — exactly the shape 00013 gave `key_presence_environments`, and for the same
-- reason read from the other side. Two operations must span environments
-- within one project: deleting a key must be able to see whether ANY
-- environment still holds a value for it (it refuses, naming them, rather than
-- destroying delivered material — the per-affected-environment publish leg
-- that would authorize the destruction is #51's), and a diff reads two
-- environments' sets. A three-column chain would make both unexpressible,
-- because the predicate analyzer requires every chain column as an equality
-- conjunct. Nothing is lost: the binding layer binds `environment_id` from the
-- verified proof's resolved chain on every environment-addressed method, so
-- the caller supplies it on exactly the two project-scoped paths above, and an
-- environment id from another project simply misses the org+project conjuncts
-- — the uniform nonexistent outcome.
--
-- hikyo:table value_entries class=environment chain=org_id,project_id

-- `ciphertext` is a sealed envelope under the PROJECT DEK, kind `value`, whose
-- AAD binds org_id, project_id, environment_id, key_id, THIS ROW'S id, and the
-- field tag — so a ciphertext lifted onto any other row, environment or
-- project stops decrypting (encryption ADR § Envelope format; env_id per the
-- flat-model amendment). Config values are sealed exactly like secret ones:
-- classification is the DISCLOSURE boundary, never the storage boundary, and a
-- table where only some rows are encrypted invites the reclassification
-- ceremony to become a re-encryption migration.
--
-- `id` IS BOUND INTO THE AAD, so it is immutable and never reused: the ADR's
-- "identifiers bound into an AAD are immutable and never reused" is a
-- constraint on this column specifically. Every write of a value mints a FRESH
-- id (delete-then-insert) rather than updating in place — never copying
-- ciphertext between rows is the same rule read from the other end, and a
-- fresh id per occurrence is the cheapest way to make id reuse unrepresentable.
--
-- `updated_by` is the principal whose act produced this occurrence. It is the
-- supply record the re-delivery gate reasons about ("the publisher supplied it
-- iff its plaintext was present in their own request"), and it is a principal
-- id — never a name, never anything derived from the value.
--
-- The UNIQUE over the chain plus key_id is what makes "a value attaches to a
-- (key, environment)" a schema fact: two rows for one cell is unrepresentable,
-- so no resolver ever has to pick between them.
CREATE TABLE value_entries (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL,
    UNIQUE (org_id, project_id, environment_id, key_id),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, key_id) REFERENCES keys (org_id, project_id, id)
);

-- Reading one environment's whole set is the delivery-shaped query (and the
-- diff's per-side query); the UNIQUE index above leads with org/project and
-- carries environment_id second, so it already serves it.
