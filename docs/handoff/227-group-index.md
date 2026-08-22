# #227 — Transaction-local key-group index

Issue: https://github.com/Hikyo-Org/Hikyo/issues/227 (parent #204; programme
#203; audit ID `BE10-B`). Base: `origin/main` at `6dff17c5`.

## Contract

- `groupIndex` is an immutable transaction-local snapshot of catalogue keys,
  key-group membership, and explicit environment-presence rows. Construction
  scans each input row once and indexes keys by id, members by group, and
  presence by key.
- `validateStaticMembership` owns declaration-time required/forbidden conflicts.
  `validateResolvedPublish` separately owns publish-time per-key presence,
  value validation, and all-or-none `(group, environment)` closure.
- Direct publish builds one full snapshot after selected-environment authority
  is established, then shares it across closure, freshness detail, and every
  affected environment materialization. Restore impact preview uses a
  membership-only snapshot because its proof does not license presence reads.
- Schema fan-out creates a fresh `groupIndexPhase` after the catalogue mutation.
  The phase loads only after the first environment publish authorization and is
  shared across the remaining materializations. Membership writes therefore
  cannot reuse the pre-mutation static-validation snapshot.
- Refusal order, public error text, group/key detail, token formats, database
  schema, and generated output remain unchanged. No process cache exists.

## Regression evidence

- Static membership and resolved `(group, environment)` permutation tables.
- Exact input-scan and catalogue-read count assertions.
- Cross-engine conformance scenario: adding an absent member to a group whose
  existing member is set is refused during same-transaction schema fan-out,
  and the membership write rolls back; retry succeeds after both members are
  set.
- Existing selective-publish closure, cross-owner refusal, required-presence,
  restore ceremony, and audit coverage remain green.

## Validation

```text
go test -count=1 ./internal/service/... -run 'Group|Publish|Key'
                                                    23 passed
go test -race -count=1 ./internal/service -run '^TestGroup'
                                                    17 passed
go test -count=1 ./internal/conformance -run
  'TestConformanceSQLite/(key_groups_declaration_side|group_membership_rebuilds_publish_index|selective_publish_closes_over_key_groups|required_in_absent_vetoes_publish)'
                                                     5 passed
go test -count=1 ./internal/isolation/             1,090 passed
go test -count=1 ./...                             3,193 passed / 57 packages
go vet ./...                                       passed
go build ./...                                     passed
gofmt -l <changed Go files>                        clean
git diff --cached --check                          passed
```

No `HIKYO_TEST_POSTGRES_DSN` was configured. The cross-engine conformance
scenario is registered in the shared corpus and ran on the available SQLite
path; PostgreSQL remained environment-skipped.

## Review

Round 1 found duplicate pre-mutation presence reads in `SetGroup`, silent
broken-index fallbacks, two redundant key-map rebuilds, and retained raw
presence rows. All were fixed. Round 2 returned `CLEAN` on both Standards and
issue #227 Spec axes.
