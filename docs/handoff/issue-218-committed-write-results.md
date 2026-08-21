# Issue #218: committed-attempt write results

## Stack position

- Stack root: PR #274 (`d253e65614713f94377a738611e143da5a8c1702`)
- Immediate base: PR #281 (`b6c0df2cde0522ab5793f05a7280f3a27a7e24cc`)
- Issue: #218
- Generated outputs: none

## Contract

`tx.WriteResult[T]` runs the existing `writeOnce` transaction inside the
existing bounded retry loop. Each attempt owns its result. The result is copied
to the return slot only after `writeOnce` reports success, which is after commit
and denial settlement. A failed call returns the zero value of `T`.

`T` must be detached data. Repositories, authorizers, proofs, interfaces,
functions, channels, unsafe pointers, or other attempt-owned references must
not be returned. `internal/lint.CheckTransactionResults` enforces that rule
repository-wide from Go type information, with a negative fixture and an
isolation invariant. `tx.Write` remains the simple no-result API and delegates
to `WriteResult`.

## Migrated high-risk callers

- `internal/service/values.go`: stage, declare, revealing read, revealing diff,
  and copy response/advisory data
- `internal/service/retention.go`: per-chunk candidate, collection, and plan
  counters
- `internal/service/revisions.go`: export rows/served revision and scanning-key
  dismissal count
- `internal/service/adapters.go`: credential replacement and revocation results,
  including publication only after the outer provider-fence retry succeeds
- `internal/service/retention.go`: failed-sweep telemetry keeps the final
  attempt's observed candidate count outside the committed-result channel and
  resets it before each retry

The remaining outer state found by the inventory is intentionally different:

- `rateCharged` flags and durable-refusal errors are operation-scoped and must
  survive retries; resetting them would double-charge or lose a committed
  refusal.
- Existing aggregates in rollback, publish, hierarchy, keys, delivery, and
  import reset at the start of every attempt and publish only after `Write`
  succeeds. They are retry-safe today; package-local conversion can happen in
  later bounded migrations without expanding this change.
- `ReadResult` is not added. The inspected read-only callers replace their
  result on every attempt rather than incrementally mutating it, so no failing
  read case justifies a second generic API in this issue.

## Validation

- `go test -count=1 ./internal/store/tx ./internal/lint`: 40 passed
- `go test -count=1 ./internal/service`: 145 passed
- `go test -count=1 ./internal/isolation -run
  '^TestRetentionFailedSweepCountsObservedCandidates(SQLite|Postgres)$'`:
  2 passed across SQLite and PostgreSQL 18
- `go test -race -count=1 ./internal/store/tx ./internal/service`: 159 passed
- `go test -count=1 ./internal/isolation -run
  'TestInvariant09bTransactionResultsAreDetached|TestInvariant09TransactionLayerHandlesProof'`:
  2 passed
- `go build ./...`: passed
- `go vet ./...`: passed
- `GOFLAGS=-p=1 HIKYO_TEST_POSTGRES_DSN=... go test -count=1 ./...` against
  PostgreSQL 18: 3977 passed in 57 packages
- Immediate PostgreSQL 18 isolation reproduction:
  `go test -count=1 ./internal/isolation`: 2083 passed

The first PostgreSQL attempt used a role without `CREATEDB` and failed only the
tests that create derived databases. A concurrent full run later pushed the
isolation package past its ten-minute package timeout; the immediate standalone
isolation run passed, and the final full run serialized package binaries with
`GOFLAGS=-p=1` without changing the test timeout. All temporary databases and
the temporary role were removed afterward.
