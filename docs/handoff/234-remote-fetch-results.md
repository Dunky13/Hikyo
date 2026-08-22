# Handoff: #234 closed remote-fetch results

Issue: https://github.com/Hikyo-Org/Hikyo/issues/234 (subissue of #204;
programme #203; audit `BE17-B`). Implemented from fresh `origin/main` at
`709b2b0ca32b906b95a9ae7149664328ca823b97`.

## Contract

- `remotefetch.Result` is a sealed union: `Attempted` carries the listing,
  remote outcome, and diagnostic error; `NotAttempted` carries only target id
  and `context_cancelled` or `slot_not_acquired`.
- `FetchAll` returns exactly one result per input target in input order. The
  scheduler starts requests under the existing fan-out semaphore. Cancellation
  while the next target waits for a full slot records `slot_not_acquired`; later
  targets record `context_cancelled`. Cancellation seen after slot acquisition
  but before `Directory` also records `context_cancelled`.
- A request that reached `Directory` remains `Attempted` even when transport,
  TLS, HTTP, or cancellation makes it fail. No response body enters either
  result variant.
- Service settlement, identity-conflict detection, and fetch-gate coverage use
  the same attempted-variant check. `NotAttempted` serves the last snapshot and
  cannot update remote health, write `remote.fetch_failed`, contribute an
  identity conflict, or make a coalesced round cover that target.

No persisted schema, API wire format, or generated output changed.

## Tests

- Mid-queue cancellation proves result cardinality, input order, one attempted
  request, one slot refusal, and explicit cancellation for targets not queued.
- A real TLS peer returning HTTP 503 proves attempted network failure remains
  distinct from cancellation before scheduling.
- Service tests prove gate coverage counts attempted variants only and the
  shared variant discriminator rejects `NotAttempted` before settlement or
  conflict processing.

## Validation

```text
go test -count=1 ./internal/remotefetch ./internal/service
  219 passed on the final rebased head
go test -race -count=1 ./internal/remotefetch/...
  11 passed
go test -count=1 ./internal/remotefetch/... ./internal/service/... -run Remote
  4 passed
go test -count=50 ./internal/remotefetch -run 'TestFetchAllReturnsOneOrderedResultPerTargetWhenCancelledMidQueue|TestFetchAllDistinguishesAttemptedNetworkFailureFromCancellation'
  100 passed
go test -count=20 ./internal/service -run 'TestFetchGateCoverage|TestAttemptedFetch|TestConflictingIdentities'
  140 passed, including nil-variant subtests
go vet ./...
  passed
go test -p 4 -count=1 -timeout=20m ./...
  passed: 57 packages
```

The first unbounded full-suite run made four `internal/importer` live-helper
tests hit their existing 30-second request deadline under host contention. All
four passed together in 14.4 seconds when replayed alone. Bounding package
concurrency at four made the unchanged full suite pass; no timeout was raised.

## Review

- Spec axis: CLEAN in round 1.
- Standards round 1 found pointer/value union ambiguity and an incomplete
  cancellation-window comment. Both were fixed with canonical pointer-only
  variants, fail-loud invalid-variant handling, tests, and exact contract text.
- Standards round 2 requested nil-interface and typed-nil regression coverage.
  Added all three constructible cases. Round 3: CLEAN.

Exact-head CI and merge evidence live on the pull request.
