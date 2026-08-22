# Issue #254: service-account persistence aggregate

## Contract

`CreateServiceAccountAggregate` owns the ordered principal and service-account
inserts. `DeleteServiceAccountAggregate` resolves the account once, locks its
principal, and then owns the complete deprovisioning order:

1. revoke and remove credentials;
2. remove pin generations;
3. remove grant origins and grants;
4. remove the service-account row and principal.

Both methods run through the transaction-bound authn resolver. Authorization,
display-once credential policy, and audit construction remain in the identities
service. The aggregate results are detached facts: creation returns the created
identity, while deletion returns that identity plus row counts for every part of
the blast radius.

No persisted schema changes are required. The federation query annotations
change from `:exec` to `:execrows` only so deletion can report pin-generation
row counts; the matching SQLite and PostgreSQL sqlc outputs are regenerated.

## Failure and concurrency coverage

- Both aggregate methods run against real SQLite and PostgreSQL harnesses.
- A test-only mutation seam injects an error at each of the two create writes
  and each of the seven delete writes. Every case asserts complete rollback;
  delete cases also prove credential revocation state and authentication remain
  unchanged.
- Concurrent delete/mint tests hold deletion after its principal lock. A racing
  mint serializes on that lock and returns `ErrNotFound` after deletion commits,
  with no credential row left behind.
- The test-only seam is pinned by the repository boundary test: production Go
  files outside its declaration cannot call it.

## Validation

- `go test -count=1 ./internal/store/... ./internal/service/... ./internal/isolation -run 'Identity|ServiceAccount|Machine'`: 43 passed
- `go test -race -count=1 ./internal/isolation -run '^TestServiceAccount(CreateAggregate|DeleteAggregate|AggregateRollback|DeleteSerializesMint)SQLite$'`: 13 passed
- `go test -count=1 ./internal/lint -run 'Test(DenialWriterIsSoleWriter|GrantLockRepo)$'`: 2 passed
- PostgreSQL coverage is present but was not run locally because `HIKYO_TEST_POSTGRES_DSN` is unset; CI is the authoritative PostgreSQL leg.

