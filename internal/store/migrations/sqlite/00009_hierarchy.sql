-- +goose Up
-- Hierarchy CRUD (#48, domain-model as amended by the flat-model ADR):
-- Instance -> Organization -> Project -> Environment -> Folder.
-- Roll-forward only: no Down section by policy (system-architecture ADR).
--
-- Two additions, and deliberately nothing else. There is NO base pointer, no
-- project-defaults table and no value row of any kind here: the flat-model
-- ADR's "a structure that must not be used is a bug that hasn't happened
-- yet" forbids the dormant column as much as the live one.
--
-- wenv:table folders class=folder chain=org_id,project_id

-- display_order is the environment's user-defined display position within its
-- project (domain-model: "user-defined per project, display-ordered"). It is a
-- real mutable property, rewritten as a whole ordered set by the reorder
-- operation, never a derived one.
--
-- It carries NO DEFAULT, on either engine. A default on an ordering column is
-- exactly the silent fallback this project refuses: a writer that forgot the
-- column would not fail, it would quietly claim first position. sqlite cannot
-- ADD a NOT NULL column without a default and cannot drop one afterwards, so
-- the column arrives through the documented table rebuild rather than an ALTER
-- — the postgres side backfills and then DROPs its default, so both engines end
-- at the same shape and the same story: backfilled to 0, no default at rest.
--
-- The rebuild's premise, stated because it is load-bearing: `environments` has
-- no creation path before this ticket (no route, no CLI verb) and the grant API
-- is #55's, so no real deployment holds an environment row or an env-scoped
-- grant here. DROP TABLE runs an implicit DELETE under foreign_keys=1; a
-- database that somehow does hold an env-scoped grant fails this migration
-- LOUDLY rather than losing the row, which is the correct outcome for a
-- premise that turned out false.
CREATE TABLE environments_new (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    display_order INTEGER NOT NULL CHECK (display_order >= 0),
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, name)
);

-- The explicit 0 is the backfill, written once here rather than standing as a
-- default that would apply forever.
INSERT INTO environments_new (id, org_id, project_id, name, note, created_at, display_order)
SELECT id, org_id, project_id, name, note, created_at, 0 FROM environments;

DROP TABLE environments;

-- RENAME rewrites references TO environments_new, of which there are none;
-- grants' foreign key names `environments`, which exists again at commit.
ALTER TABLE environments_new RENAME TO environments;

-- A folder is organizational only in v1: namespace + display grouping. No
-- folder-scoped grants (permission-model ADR), no folder-level values
-- (domain-model). Its identity is the immutable id; `path` is the mutable
-- name, unique among the project's folders.
--
-- Composite ancestry FK, exactly as environments: the parent exposes
-- (org_id, id) and the child references the pair, so a folder whose chain
-- crosses tenants is unrepresentable rather than merely unwritten.
CREATE TABLE folders (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, path)
);
