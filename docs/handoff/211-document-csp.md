# #211 — Document-scoped dynamic CSP

## Contract

Static response security remains global: every response carries the baseline
Content Security Policy, `X-Content-Type-Options: nosniff`, and
`Referrer-Policy: no-referrer`, including API errors, probe failures, missing
assets, and other refusals.

The datastore-backed remote-origin lookup is document-scoped. A successful SPA
root or fallback response reads the current configured remote origins once and
extends `connect-src` through the existing canonical origin filter. API,
health, readiness, metrics, asset, root-file, and refusal responses do not read
remote origins and retain the self-only baseline CSP.

Remote origins are not cached and are never derived from request data. The next
successful document navigation therefore observes remote removal immediately.

## Module boundary

`internal/server/spa.go` owns both layers: global static response headers and
the single SPA document writer. `internal/server/server.go` adapts
`RemoteService.RemoteOrigins` and passes that source only to the SPA writer.
Root and fallback documents cannot drift because both pass through `serveSPA`.

## Evidence

`internal/server/spa_test.go:TestRemoteOriginsAreReadOnlyForSuccessfulSPADocuments`
uses the real router with a counting `RemoteService`. It covers API refusal and
404 responses, liveness, readiness, metrics, hashed and root assets,
non-document application requests, missing index refusal, root HTML, fallback
HTML, and document `HEAD`.

## Validation

```sh
gofmt -w internal/server/server.go internal/server/spa.go internal/server/spa_test.go
go test -count=1 ./internal/server/...
go test -count=1 ./...
```

Verified on 2026-08-21:

- focused server suite: 168 tests passed in 1 package;
- full Go suite: 2,918 tests passed in 56 packages;
- adversarial review Round 2: CLEAN;
- generated outputs: none.
