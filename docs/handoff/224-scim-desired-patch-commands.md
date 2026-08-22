# Handoff: #224 SCIM desired resources and PATCH commands

Issue: https://github.com/Hikyo-Org/Hikyo/issues/224 (parent #204; programme
#203; audit ID `BE08-A`).

## Contract

- Create and PUT accept complete `DesiredUser` / `DesiredGroup` values. These
  types contain no PATCH mode, presence flags, or command scripts.
- PATCH accepts closed `UserPatchCommand` / `GroupPatchCommand` variants. The
  transport validates the complete PatchOp message before creating commands.
- Pure reducers apply commands in wire order over stored desired state. The
  service persists and reconciles only the final reduced state in one
  transaction.
- Group reduction returns whether membership was commanded, so reconciliation
  metadata comes from the same pure reduction as the complete desired state.
- User subject-source write-once checks, group member ordering/deduplication,
  lifecycle grants, ETags, and no-op event behavior remain service-owned.

## Regression evidence

`internal/service/scim_patch_test.go` table-tests ordered user and group
reduction without a database, including add/remove reversal, replacement,
clear, deduplication, and input immutability. SCIM wire and isolation suites
retain the closed parser matrix and exercise both SQLite and PostgreSQL.

Extension-path subject-source omission and removal now have explicit
regressions in `internal/isolation/scim_e2e_test.go`: PUT omission preserves the
stored source, while explicit removal is refused as `mutability` before storage
mutation. Unsupported plain and pathless Group attributes are rejected by the
parser before command construction.

Generated outputs: none.

## Validation

```text
go build ./...                                      passed
go vet ./...                                        passed
go test -count=1 ./internal/service ./internal/scimproto
                                                     236 passed
go test -count=1 ./internal/isolation/ -run SCIM
  (SQLite + PostgreSQL)                              passed in 75.538s
go test -count=1 ./...
  (57 packages; SQLite + PostgreSQL)                 non-DB packages passed;
                                                     shared PostgreSQL volume
                                                     hit ENOSPC during 11 tests
exact 11 infrastructure-aborted tests on clean,
  RAM-backed PostgreSQL                              passed in 8.704s
git diff --check                                     passed
```

Two-axis review round 2: clean (standards and issue #224 specification).
