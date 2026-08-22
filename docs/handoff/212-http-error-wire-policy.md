# #212 — Total HTTP error wire policy

Issue: https://github.com/Hikyo-Org/Hikyo/issues/212 (parent #204; programme
#203).

## Contract

Hikyo's JSON error envelope is governed by one server-layer `WireError`
policy. Each public error code has exactly one HTTP status, fixed message, and
detail rule. `bad_request` and `conflict` alone may carry an explicitly safe
detail; every other class redacts it.

Unknown internal errors, wrapped unknown errors, and unrecognized public codes
all collapse to the same `500 internal` response. Domain errors remain free of
HTTP types. Handler authentication, authorization, validation, and
non-enumeration ordering is unchanged; only classification and rendering move
behind the policy.

One contextual override is explicit: an unusable workspace handoff remains
`403 forbidden` for approval/redemption, while authenticated transaction lookup
collapses unknown, stale, consumed, and non-owned state to `404 not_found`.

## Enforcement

- `internal/server/errors.go` owns the complete public-code table and the
  wrapped-error classifier.
- `writeHandlerError` consumes one policy for status, code, message, and detail
  handling instead of choosing those values independently.
- `internal/server/errors_internal_test.go` compares the policy table with the
  OpenAPI `ErrorCode` enum, so a new public code without a complete mapping
  fails tests.
- `internal/server/contract_test.go` proves plain, wrapped, and detail-carrying
  unknown handler errors expose only the uniform internal response.

## Validation

```sh
go test -count=1 ./internal/server/...   # 183 passed
go test -count=1 ./internal/isolation/  # 1084 passed
go test -count=1 ./...                  # 2933 passed in 56 packages
```

Standards review was CLEAN. Spec review reached CLEAN in three rounds after
fixing partial handler-family migration and preserving the workspace handoff
403/404 context split.
