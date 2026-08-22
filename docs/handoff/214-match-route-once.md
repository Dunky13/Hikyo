# #214 — Match and carry each Go API route once per request

Baseline: `d31919a8`. Scope: `api/spec.go`, `internal/server/api.go`,
`internal/server/hierarchy.go`, one isolation consumer, and focused API/server
tests.

## Contract choice

Admission uses a two-step type-state seam because SCIM body policy must run
between route matching and shape validation:

```go
match, err := api.MatchRequest(r)       // one router.FindRoute
op := match.Operation()                 // cloned row for SCIM classification
validated, err := match.Validate()      // same route, params, request, and row
request := validated.Request()          // original request + cloned row
```

`ValidateRequest(r)` is the one-shot form: it matches and validates once and
returns `*ValidatedRequest`. The server uses the split form because
`http.MaxBytesReader` cannot wrap SCIM wire bodies before the wire-specific
single-value/body-size policy runs; doing so could disclose a pre-authentication
400 that the SCIM contract requires to be ranked behind authentication.

Immutability and injection boundaries:

- `MatchedRequest` alone holds the kin-openapi route and path parameters. They
  are private, attempt-local, and never enter context.
- The operation row is cloned at match, validation, context attachment, and
  context read boundaries. Registry changes after validation cannot alter the
  row carried through that request.
- Only `ValidatedRequest.Request()` can attach a row, and only to the original
  request that passed validation. It accepts no caller-supplied request or
  context, while its row field and context key remain private.
- A zero `ValidatedRequest` returns no request and cannot attach an operation.

## Behaviour

- No route: unchanged `ErrNoRoute` → uniform 404.
- Malformed request: unchanged `ValidationError.Member` → 400 naming member.
- Matched route without an operation/registry row: fail-loud internal error →
  uniform 500. It is an impossible contract invariant, never a public 404.
- `OperationFor` remains for registry inspection. The unvalidated
  `WithRequestOperation` compatibility helper was removed; its isolation
  consumer now validates before attaching the row.

## Changed files

| File | Change |
| --- | --- |
| `api/spec.go` | Central request resolver; `MatchedRequest`/`ValidatedRequest`; cloned-row context accessors; result-returning `ValidateRequest`; removed dead `OperationIDFor`. |
| `internal/server/api.go` | Match once, classify/bound, validate, attach validated row; injectable matcher seam for admission count test. |
| `internal/server/hierarchy.go` | Strict-server error legs consume context row instead of re-routing. |
| `internal/isolation/identities_e2e_test.go` | Artifact-refusal fixture validates its contract-shaped request and consumes that request's carried row. |
| `api/match_test.go` | Underlying router count, cloned-row carry, no-route, fail-loud invariant, zero-value pins. |
| `internal/server/admission_internal_test.go` | Real middleware matcher count plus admitted, 404, malformed, over-bound, and invariant-500 pins. |

## Lookup count

Admitted request before → after: **3 → 1**; strict-server error legs previously
made it 4. Before: SCIM classification + validation + context attachment each
routed. After: `MatchRequest` routes once; every later consumer uses its result.

The count proof has two layers: `api` wraps the real kin-openapi router and
asserts `MatchRequest` calls it once; `internal/server` wraps `MatchRequest` and
asserts the real admission middleware calls that seam once. Either layer
regressing fails a focused test without adding a production counter.

## TDD and review evidence

Initial red:

```text
api/match_test.go:50:16: undefined: MatchRequest
api/match_test.go:121:11: undefined: MatchedRequest
--- FAIL: TestPreChangeAdmissionSequenceLookupCount
    route lookups = 3, want 1
```

Review R1 found three valid gaps and all were fixed:

1. Impossible registry mismatches were downgraded to 404 → now fail as 500.
2. Context carried only operation ID and re-read registry → now carries cloned
   validated row through a private key.
3. Count test replayed calls rather than real middleware → added server matcher
   seam and real admission assertion.

Native R2 found one remaining injection path: exported `WithRequestOperation`
could attach a route row without validating its request. The helper was removed
and its sole isolation consumer now uses `ValidateRequest`.

Native R3 found that `ValidatedRequest.WithContext(ctx)` still allowed a valid
route A result to be attached to an arbitrary context B. That method was
removed: `ValidatedRequest.Request()` can only return the original validated
request with its row attached. The first broader `AuthzOp` binding attempt was
discarded after TDD correctly exposed valid SCIM dynamic-operation semantics;
the request-bound API fixes the injection seam without changing authorization.

Scoped green after fixes:

```text
gofmt -l api internal/server                                      # no output
go test -count=1 ./api ./internal/server/... ./internal/authz      # 249 passed
go test -count=1 ./internal/isolation                              # 1,084 passed
go vet ./api/... ./internal/server/... ./internal/authz/... ./internal/isolation/...  # clean
go test -count=1 ./...                                             # 2,916 passed; 56 packages
```

Standards R2 and spec R2 were clean. Native R3's final blocker was fixed and
closed by the request-bound attachment API above; the three-round review cap
precludes another cross-model pass. The final full-suite gate is green.
