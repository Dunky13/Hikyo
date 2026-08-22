# Issue #255 — closed workload-federation JWKS source

## Outcome

Federation runtime models now carry one closed `jwkssource.KeySource` value instead
of independently mutable mode and static-document fields. Its zero value is
remote discovery; the static arm can only be created by validating and
canonicalizing a JWKS document.

## Compatibility and persistence

- The HTTP contract remains `jwks_mode` plus optional `static_jwks` through the
  1.0 freeze. The server converts that compatible shape once and rejects both
  impossible pairings, including a discovery request that explicitly carries an
  empty `static_jwks` property.
- SQLite and PostgreSQL keep the existing `jwks_mode` and `static_jwks` columns
  and constraints. The authn store facade maps them to and from `KeySource`; no
  migration or generated output changed.
- Static documents retain the 1 MiB cap and usable-signing-key policy, and are
  stored in the canonical JSON emitted by go-jose.
- The verifier switches on the closed source. Static verification uses the
  already-validated keys and cannot enter discovery, refresh, or cache paths.

## Regression coverage

- `internal/jwkssource/key_source_test.go`: impossible combinations, stable
  canonicalization, size cap, and signing-key policy.
- `internal/server/federation_test.go`: wire-boundary rejection and canonical
  handoff to the service.
- `internal/isolation/federation_e2e_test.go`: exact source round-trip plus
  static no-egress verification on SQLite and PostgreSQL variants.

## Local validation

```text
go test -count=1 ./internal/service/... ./internal/store/... ./internal/oidcfed/...
323 passed

go test -count=1 ./internal/server/...
227 passed

go test -count=1 ./internal/isolation/ -run Federation
23 passed (PostgreSQL variants require HIKYO_TEST_POSTGRES_DSN and run in CI)

go test -run '^$' ./...
all packages compile

go test -count=1 ./...
3359 passed across 58 packages
```
