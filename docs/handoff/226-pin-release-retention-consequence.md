# Issue #226: pin-release retention consequence

## Contract

`DELETE .../pins/{workloadPrincipal}` returns the released revision and one
closed `retention_consequence`: `retained`, `collection_eligible`, or
`already_collected`. The value is computed after pin deletion in the same write
transaction, from the locked snapshot row and the effective retention policy.
It is transaction-time truth: a later sweep may immediately collect an eligible
payload.

Pin listing also returns a server-derived release preview. The SPA uses that
preview only to preserve the existing sole-retention-keeper confirmation. The
release response remains authoritative if policy, other pins, or GC changed
after the list read.

## What changed

- The retention service owns the closed consequence. The store supplies the
  proof-bound snapshot lock; the release service returns detached
  committed-attempt data.
- OpenAPI, Go bindings, TypeScript clients, Zod schemas, CLI JSON/table output,
  and the history drawer carry the same result.
- The browser-side SQL mirror was removed. The drawer refreshes pin and revision
  queries after release and renders the returned revision/consequence.
- Boundary fixtures cover exact/inside/outside age cutoffs, the revision-count
  cutoff, exact pin expiry, policy changes, another live pin, and collected
  payloads. Every result is checked against an immediate real sweep.
- A deterministic both-engine race fixture pauses GC after the snapshot mark
  while its transaction still owns the write lock. A concurrent release waits
  and then reports `already_collected` after GC commits.

## Validation

- OpenAPI and TypeScript client regeneration: deterministic and drift-free.
- `go test -count=1 ./...`: 3,180 passed across 57 packages.
- TypeScript client: typecheck passed; 12 tests passed.
- Web: typecheck passed; 248 tests passed.
- `go build ./...`, `go vet ./...`, and `git diff --check`: passed.
- Final standards and issue-spec review axes: clean after two fix rounds.

PostgreSQL isolation tests require `HIKYO_TEST_POSTGRES_DSN`; local runs without
it execute SQLite and fail closed in CI if the PostgreSQL DSN is absent.
