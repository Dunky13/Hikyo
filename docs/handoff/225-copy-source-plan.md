# Handoff: #225 resolve value-copy sources once

Issue: https://github.com/Hikyo-Org/Hikyo/issues/225 (parent #204; programme
#203; audit ID `BE09-A`).

## Contract

- Explicit copy resolves every named source key once into one transaction-local
  `copySourcePlan`. The plan retains source cells, classification metadata, key
  IDs in request order, clone-only skipped names, and transaction-bound proofs;
  it never retains plaintext.
- Destination authorization consumes only the metadata plan. After every
  destination passes, `openCopySourcePlan` acquires the source-copy proof, loads
  ciphertext rows, performs the source ceremony, decrypts, records per-key
  disclosure events, and hands material to destination writes.
- Destination refusal therefore performs no source authorization, decrypt/open,
  or disclosure write. A dual-refusal conformance fixture verifies it records
  exactly the destination denial and no premature source denial.
- Clone reuses its existing catalogue snapshot, then loads the same plan before
  its born-invalid check. Gate-blocked secrets remain explicitly skipped;
  absent source cells remain omitted; partial/full copy result order is pinned.
- Public API, ciphertext format, migrations, and generated outputs are
  unchanged.

## Review

Round 1 found one blocking issue on both Standards and Spec axes: source-copy
authorization was initially evaluated while building the plan, before
destination preflight. Because authorization denials are durably settled, a
dual refusal could record a source denial for a source step never reached.

The plan was split into metadata resolution and post-destination source loading.
Round 2 verified the fix and returned `CLEAN` on both axes. No baseline code
smells remained.

## Validation

```text
go test -count=1 ./internal/service/... -run 'Copy|Clone|Value'  5 passed
go test -race -count=1 ./internal/service/... -run
  'Copy|Clone|Value'                                             5 passed
go test -count=1 ./internal/conformance -run
  '^TestConformanceSQLite$/value_(copy_runs_the_locked_formula|clone_at_creation)$'
                                                               3 passed
go test -count=1 ./internal/isolation/                       1,090 passed
go build ./...                                                  passed
go vet ./...                                                    passed
go test -count=1 ./...                          3,176 passed / 57 packages
git diff --check                                                clean
gofmt -l <changed Go files>                                    clean
```

`HIKYO_TEST_POSTGRES_DSN` was unavailable in this worktree, so local
PostgreSQL conformance/isolation legs skipped; SQLite and compile-time
cross-engine paths passed.
