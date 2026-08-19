-- +goose Up
-- Revisions, drafts and publishing (#51, revision-model ADR as amended by the
-- flat-model ADR; schema-model ADR for validation timing and key groups).
-- Roll-forward only: no Down section by policy (system-architecture ADR).
--
-- FOUR TABLES, TWO RETENTION CLASSES. The revision-model ADR splits history in two
-- and the split is structural here rather than a policy note:
--
--   * `snapshots` + `revision_key_changes` are LINEAGE, retained indefinitely.
--     They record what happened -- revision number, publisher, pinned input
--     revisions, and which keys changed -- and they never contain a value in
--     any form.
--   * `snapshot_entries` is PAYLOAD. It is the value-bearing materialization,
--     and it is what retention policy collects (#52/C6). Collecting it leaves
--     the lineage above intact, which is exactly the ADR's "a collected
--     revision cannot be restored, diffed by value, or revealed" with nothing
--     left behind to reconstruct it from.
--
-- `pending_changes` is neither: it is per-user working state, published or
-- discarded, never history.
--
-- hikyo:table pending_changes class=environment chain=org_id,project_id
-- hikyo:table snapshots class=environment chain=org_id,project_id
-- hikyo:table snapshot_entries class=environment chain=org_id,project_id
-- hikyo:table revision_key_changes class=environment chain=org_id,project_id

-- PENDING CHANGES -- per-user working state (revision-model ADR, Draft model).
--
-- A pending change attaches to a `(key, environment)` per the flat-model
-- amendment, is OWNED by one principal, and carries an IMMUTABLE VERSION ID:
-- `id` is what a publish names, and editing the same cell mints a new id
-- rather than mutating this row. That is what makes selection isolation
-- checkable -- a publisher applies exactly the versions they previewed, and a
-- version id that no longer exists is refused loudly rather than resolved to
-- whatever the owner typed since.
--
-- SUPERSEDED VERSIONS ARE COLLECTED IMMEDIATELY, which is the strictest
-- reading of the schema-model ADR's Bounds amendment ("garbage collection of
-- superseded pending versions; only the latest version per (owner, key,
-- environment) is publishable and revalidated"). The UNIQUE below is that
-- bound expressed as a schema fact: one live version per (owner, cell), so a
-- client saving one field in a loop cannot grow this table at all, and the
-- per-user live-draft quota it also demands is bounded by the project's own
-- key and environment caps.
--
-- TWO BASELINE COLUMNS, because the ADR states two different things and they
-- are not the same fact:
--
--   * `staged_from_revision` is the published revision the edit was staged
--     against -- "recorded against the published revision it was staged from".
--     It is provenance a client shows ("staged from rev 12"), never a check.
--   * `staged_from_entry` is the freshness check's whole input: the id of the
--     published value-entry row this cell held at staging time, or the empty
--     string when the cell was `absent`. The optimistic check is stated PER
--     ENTRY -- "rejected loud if the published state of any selected entry has
--     advanced since that version was staged" -- and per-entry is also the only
--     usable reading: an environment-wide revision comparison would invalidate
--     every outstanding draft in an environment whenever any unrelated key was
--     published there.
--
-- `ciphertext` is a sealed envelope under the PROJECT DEK -- kind
-- `project_field`, owner_table `pending_changes`, owner_row_id THIS ROW'S id,
-- additionally bound to this row's environment_id and key_id.
-- A draft holds real material and is stored exactly like a published value:
-- the permission-model ADR's "a pending secret's plaintext remains reveal-gated
-- exactly as a published one is" is a storage statement as much as an
-- authorization one. It is NULL for an `unset` draft and only then, which the
-- CHECK enforces rather than trusting a writer.
CREATE TABLE pending_changes (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('set', 'unset')),
    ciphertext BLOB,
    staged_from_revision INTEGER NOT NULL,
    staged_from_entry TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (org_id, project_id, environment_id, key_id, owner_id),
    CHECK (
        (operation = 'set' AND ciphertext IS NOT NULL)
        OR (operation = 'unset' AND ciphertext IS NULL)
    ),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, key_id) REFERENCES keys (org_id, project_id, id),
    FOREIGN KEY (owner_id) REFERENCES principals (id)
);

-- SNAPSHOTS -- the immutable per-(project, environment) materialization.
--
-- `revision` is the monotonic, human-facing number the ADR pairs with the
-- opaque change token, and the UNIQUE is what makes allocation checkable: two
-- publishes computed from the same baseline cannot both land, because the
-- second one's revision number is already taken. That is a belt on the
-- serialized publish, not a substitute for it -- unique numbers alone do not
-- linearize the outcome, which is why publish also runs serializable and holds
-- the project lock.
--
-- THERE IS NO CHANGE-TOKEN COLUMN, deliberately. The token is
-- HMAC(scoped token key, delivery manifest) and the scoped key is derived from
-- the CURRENT root token key; storing the token would make `rotate-token-key`
-- either a rewrite of immutable history or a silent lie. Deriving it at read
-- is what lets rotation change every token while content, revision numbers and
-- pinned input revisions all stay exactly where they are (mvp-boundary C4).
--
-- `schema_revision` is the pinned input the flat-model ADR fixes; the other
-- half of that pin tuple -- this snapshot's own value-entry revisions -- lives
-- per row on snapshot_entries, because that is the granularity it has.
CREATE TABLE snapshots (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    schema_revision INTEGER NOT NULL,
    published_by TEXT NOT NULL,
    published_at TEXT NOT NULL,
    UNIQUE (org_id, project_id, environment_id, revision),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id)
);

-- SNAPSHOT ENTRIES -- the resolved key->value map, the payload class.
--
-- `key_name` and `classification` are COPIED rather than joined to the live
-- catalogue, and that is the closed-schema guarantee expressed in the schema:
-- "a delivered payload's key set is exactly the declared keys that resolve in
-- that environment, UNDER THE SCHEMA REVISION THAT SNAPSHOT PINNED". A rename
-- or a reclassification after the fact must not retroactively change what a
-- historical revision delivered, and classification is sticky to the stored
-- occurrence per the revision-model ADR's diff rules.
--
-- `value_entry_id` is the pinned value-entry revision -- the published cell
-- this entry materialized from. It is metadata, not a reference: the cell is
-- delete-then-insert, so the row it names may be gone, and the snapshot must
-- keep answering anyway. Hence no foreign key, deliberately.
--
-- `ciphertext` is RE-SEALED into this row (kind `project_field`, owner_table
-- `snapshot_entries`, owner_row_id this row's id, additionally bound to this
-- row's environment_id, key_id and snapshot_id), never copied from the value
-- entry: the encryption-model ADR's never-copy-ciphertext rule, and the reason a
-- lifted snapshot ciphertext stops decrypting anywhere else.
CREATE TABLE snapshot_entries (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN ('secret', 'config')),
    ciphertext BLOB NOT NULL,
    value_entry_id TEXT NOT NULL,
    UNIQUE (snapshot_id, key_id),
    FOREIGN KEY (snapshot_id) REFERENCES snapshots (id)
);

-- REVISION LINEAGE -- which keys changed in each revision. Never values.
--
-- This is the permanently-retained half, and the retention split is only real
-- if this table cannot reconstruct a collected payload. It holds a key id, the
-- key's name at that revision, and one of three transitions -- nothing derived
-- from a value, not a length, not a digest, not a changed-from marker.
--
-- It is also the "recently changed" matrix signal's source (revision-model ADR,
-- Matrix UI): a value publish writes rows for exactly the environments it
-- touched, so the signal recomputes for exactly those environments without any
-- service-side bookkeeping deciding which.
CREATE TABLE revision_key_changes (
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    change TEXT NOT NULL CHECK (change IN ('added', 'edited', 'removed')),
    PRIMARY KEY (org_id, project_id, environment_id, revision, key_id),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id)
);
