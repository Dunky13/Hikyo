-- +goose Up
-- The key catalogue (#49, schema-model ADR as amended by the flat-model ADR).
-- Roll-forward only: no Down section by policy (system-architecture ADR).
--
-- The ADR's first structural decision: THERE IS NO SEPARATE SCHEMA OBJECT.
-- Every constraint is declared inline on the Key, and "the project's schema"
-- is the set of its key declarations — one artifact to pin, one to diff, one
-- to authorize. So there is no `schemas` table here, and there never will be
-- one; a key's rules live in its own row.
--
-- What is deliberately absent, at the column: no value row of any kind, no
-- pending change, no snapshot. Values attach to (key, environment) and arrive
-- with #50; the flat-model ADR's "a structure that must not be used is a bug
-- that hasn't happened yet" forbids the dormant column as much as the live one.
--
-- hikyo:table key_groups class=key chain=org_id,project_id
-- hikyo:table keys class=key chain=org_id,project_id
-- hikyo:table key_presence_environments class=key chain=org_id,project_id
-- hikyo:table project_schema_revisions class=key chain=org_id,project_id

-- A key group is a named, project-level set of keys; a key belongs to at most
-- one, which is why the membership is a column on `keys` rather than a join
-- table. At-most-one keeps co-publish closure from becoming transitive across
-- groups, where selecting one pending change could drag in a chain the
-- publisher never previewed.
--
-- Groups exist here as DECLARATIONS only. The closure algorithm and the
-- all-or-none presence evaluation are publish-time (#51); this migration
-- carries the vocabulary they will read.
CREATE TABLE key_groups (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, name)
);

-- A Key is declared once per project.
--
-- `id` is the identity and is immutable; `name` is a mutable label on it.
-- Everything that must survive editing — a future pending change's target, a
-- historical value's owner, a group membership, an audit record — references
-- the id, so a rename never breaks a reference. Names are unique among LIVE
-- keys, which is exactly what UNIQUE over a hard-deleted table gives: a
-- deleted key's name may be reused, and identity being the id means a
-- historical diff is never ambiguous about which key it meant.
--
-- `declaration` holds the canonical JSON form of the value-dependent rules
-- (internal/schema.Canonical). Byte-stable by construction, which is what
-- makes canonical-form deduplication a byte comparison and — load-bearing —
-- makes "did a value-dependent rule change?", the reveal gate's input, a byte
-- diff rather than a field walk a new field could silently escape.
--
-- `folder_path` is a plain string, NOT a reference to `folders`. A folder is
-- organizational only in v1 (namespace + display grouping, no folder-scoped
-- grants, no folder-level values), and the domain model gives a Key a folder
-- PATH rather than a folder id. A foreign key here would invent an entity
-- relationship the model does not have.
--
-- The presence MODES live on the row and the explicit environment sets live in
-- their own table below, because `mode: all` is symbolic and covers
-- environments created later: expanding it into ids at declaration time would
-- silently exempt a new environment from a rule the operator wrote as
-- "always".
CREATE TABLE keys (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    folder_path TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN ('secret', 'config')),
    description TEXT NOT NULL,
    deprecated BOOLEAN NOT NULL,
    deprecation_note TEXT NOT NULL,
    declaration TEXT NOT NULL,
    required_mode TEXT NOT NULL CHECK (required_mode IN ('all', 'none', 'explicit')),
    forbidden_mode TEXT NOT NULL CHECK (forbidden_mode IN ('all', 'none', 'explicit')),
    group_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    -- Composite membership FK: a key can only join a group in its OWN project,
    -- so a cross-project membership is unrepresentable rather than merely
    -- unwritten. NULL group_id skips the constraint (MATCH SIMPLE), which is
    -- the "belongs to no group" case.
    FOREIGN KEY (org_id, project_id, group_id) REFERENCES key_groups (org_id, project_id, id),
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, name)
);

-- The explicit halves of `required_in` / `forbidden_in`. One row per
-- (key, environment, rule).
--
-- The environment foreign key is the point of the table: environment lifecycle
-- and presence rules are the same serialized domain, and the ADR names the
-- exact race — transaction A deletes environment E and computes its cascade
-- from the schema it read, while transaction B adds E to a required_in set.
-- With the FK, the losing transaction fails LOUDLY instead of leaving a
-- dangling reference; the service takes the project row first so it rarely
-- has to.
CREATE TABLE key_presence_environments (
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    rule TEXT NOT NULL CHECK (rule IN ('required', 'forbidden')),
    PRIMARY KEY (org_id, project_id, key_id, rule, environment_id),
    FOREIGN KEY (org_id, project_id, key_id) REFERENCES keys (org_id, project_id, id),
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id)
);

-- The project's own monotonic schema revision — the key-catalogue revision,
-- since the catalogue IS the schema. #50 pins it on value verdicts and #51
-- pins it on snapshots and on the compiled-validator cache, so it is built
-- now: retrofitting a revision counter after snapshots exist means rewriting
-- every pinned input.
--
-- Its own table rather than a column on `projects`, so both engines reach the
-- same shape: sqlite can neither add a NOT NULL column without a default nor
-- drop one afterwards, and `projects` cannot take the table-rebuild treatment
-- 00009 used on `environments` (environments, folders and grants all reference
-- it). A separate table needs no default on either engine.
--
-- Every project has exactly one row, inserted with the project and backfilled
-- here. A missing row is therefore a defect, and the bump — an UPDATE checked
-- for affected rows — reports it as one rather than creating it silently.
CREATE TABLE project_schema_revisions (
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    PRIMARY KEY (org_id, project_id),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id)
);

-- The backfill. Revision 0 is "no declaration has ever changed", which is the
-- truth for every project that predates this migration.
INSERT INTO project_schema_revisions (org_id, project_id, revision)
SELECT org_id, id, 0 FROM projects;
