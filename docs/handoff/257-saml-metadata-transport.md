# Handoff: #257 guarded SAML metadata transport

Issue: https://github.com/Hikyo-Org/Hikyo/issues/257 (parent #207; programme
#203; audit ID `BE21-B`). Base: `ecf96da4`.

## Contract

- `SAMLProviders` no longer exposes an `HTTPClient` field. Production app
  wiring uses `NewSAMLProviders`, which constructs the guarded metadata
  transport with the production resolver, dialer, TLS minimum, response-header
  timeout, and whole-request timeout.
- Deterministic tests inject only DNS resolution, final dialing, test trust
  roots, and a shorter timeout below the policy boundary. They cannot replace
  the HTTP client or round tripper.
- Metadata URLs remain HTTPS-only and reject userinfo, fragments, missing
  hosts, and literal non-public targets before DNS or dialing.
- Every request, including each same-origin redirect, revalidates URL shape,
  resolves again, and rejects any non-public answer. The transport dials a
  validated pinned IP while preserving the original HTTP host and TLS server
  name.
- Redirects remain same-origin and capped at five. TLS 1.2, the 10-second
  response-header timeout, the 15-second whole-request timeout, and the
  `samlsp.MaxDocumentBytes` response limit remain enforced.

## Regression evidence

- A real TLS metadata fixture proves deterministic injected responses traverse
  the guarded URL, TLS, DNS, and dial path.
- Redirect tests reject cross-origin pivots, userinfo/fragments, and a
  same-origin hostname that rebinds to loopback before the second request.
- Slow and oversized responses fail within their configured bounds.
- Constructor coverage pins the production resolver/dialer, TLS 1.2 minimum,
  response-header timeout, and whole-request timeout.
- App structural coverage pins production wiring to `NewSAMLProviders` and
  rejects restoring a `SAMLProviders` struct literal.
- Existing proxy, public-IP pinning, multi-address fallback, literal private
  target, SAML service, app, boundary, and isolation coverage remains green.

Generated outputs: none.

## Validation

```text
go test -count=1 ./internal/service/... -run SAML        passed (26 tests)
go test -count=1 ./internal/app/... ./internal/boundary/... passed (67 tests)
go test -count=1 ./internal/isolation/ -run SAML         passed (6 tests)
go test -race -count=1 ./internal/service/... -run 'TestSAMLMetadata|TestSAMLProvidersExposeNoHTTPClientOverride|TestNewSAMLProvidersBuildsProductionMetadataPolicy'
                                                          passed (16 tests)
go build ./...                                            passed
go vet ./...                                              passed
go test -count=1 ./...                                    passed (3368 tests, pre-review)
go test -count=1 ./...                                    57 packages passed; isolation hit its
                                                          10m timeout under shared-host contention
go test -count=1 ./internal/isolation/                    passed (1093 tests on retry)
./scripts/ci/verify-docs.sh                               passed
```

Two-axis review round 1 found incomplete redirect URL-shape validation and a
missing app-wiring regression test; both were fixed. Round 2 returned Standards
`CLEAN` and Spec `SOUND`.
