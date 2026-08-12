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
-- hikyo:table folders class=folder chain=org_id,project_id

-- display_order is the environment's user-defined display position within its
-- project (domain-model: "user-defined per project, display-ordered"). It is a
-- real mutable property, rewritten as a whole ordered set by the reorder
-- operation, never a derived one.
--
-- It ends with NO DEFAULT, on either engine. A default on an ordering column is
-- exactly the silent fallback this project refuses: a writer that forgot the
-- column would not fail, it would quietly claim first position. The default
-- exists for the length of the backfill and is then dropped; the sqlite side
-- reaches the same shape through the documented table rebuild, because that
-- engine can neither add a NOT NULL column without a default nor drop one.
ALTER TABLE environments ADD COLUMN display_order BIGINT NOT NULL DEFAULT 0;
ALTER TABLE environments ALTER COLUMN display_order DROP DEFAULT;
ALTER TABLE environments ADD CONSTRAINT environments_display_order_non_negative
    CHECK (display_order >= 0);

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
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, id),
    UNIQUE (org_id, project_id, path)
);
