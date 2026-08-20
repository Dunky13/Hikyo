# Handoff: #113 OpenAPI artifact-class admission

Issue: https://github.com/Hikyo-Org/Hikyo/issues/113.

**State: complete.** The embedded OpenAPI document is the sole runtime source
for bearer artifact-class admission. A resolved bearer whose class is absent
from the exact request operation's `x-hikyo-artifacts` allowlist receives the
same 404 body as a nonexistent tenant object, and the refusal is durably
recorded as `auth.artifact_class_refused` before the response returns.

## Runtime design

1. `api/spec.go` parses every operation into an immutable cached row containing
   method, path, `operationId`, authorization operation, formula, artifact
   classes, and minimum revision. Loading fails if any operation omits or
   empties `x-hikyo-artifacts`; contract tests also require every operation
   admitting an authenticated artifact to declare the uniform 404 response.
2. Contract validation resolves the exact request row and places only its
   `operationId` in context. Consumers re-read the cached row, so callers cannot
   inject an alternate artifact list and there is no parallel route table.
3. Authentication still resolves the live identity inside the request
   transaction. `authz.TxAuthorizer.AdmitOperation` maps that trusted identity
   to the contract vocabulary and checks the attached row before handler logic
   or grant authorization can use it.
4. The shared seam is used by proof-backed `Actor.resolve`, account-security
   `Authenticate`, and self-scoped `AuthenticateSelfSurface`. Account and self
   services retain their narrower session-shape guards after contract admission
   because those methods require a session row.
5. Generic HTTP bearer resolution includes provisioning credentials, while the
   SCIM wire lets a live non-SCIM bearer reach the same admission seam before
   applying its binding-specific rules. Thus both SCIM cross-class directions
   receive the contract-driven refusal; correct SCIM credentials still prove
   their path binding and stamp last-used inside the wire transaction.
6. Direct in-process calls have no request operation. Their existing service
   semantics remain unchanged, except the locked #71 instance-connection
   confinement is derived from the same OpenAPI registry at `Authorize`.

## Artifact classes

| Resolved identity | OpenAPI class |
|---|---|
| CLI, browser, or workspace session | `human-session` |
| workload, automation, or federated service account | `machine-credential` |
| SCIM provisioning connection | `scim-credential` |
| instance connection | `instance-credential` |
| local host authority | `local` |

`delivery.fetch` is now machine-only. `serveDirectory` declares the distinct
`instance-credential` class alongside the human class; no other operation
admits an instance connection. The former `internal/authz/eligibility.go` and
its parallel `humanOnly` registry flags are removed.

## Refusal and audit contract

Artifact mismatch returns `domain.ErrNotFound`, which the HTTP transport renders
with the same status and bytes as the nonexistent-resource control. The
transaction rolls back and durable settlement flushes an instance-trail
`auth.artifact_class_refused` event containing the operation, artifact class,
and bounded `class-mismatch` cause. Event-id or flush failure becomes a loud
error; the server never returns the uniform denial without its audit record.

## Tests and invariants

- `api/artifact_admission_test.go` proves request lookup and authorization-op
  views come from the embedded document and rejects missing/empty declarations.
- `api/spec_test.go` prevents the runtime class-mismatch 404 from disappearing
  from any bearer-admitting operation's documented response set.
- `internal/isolation/artifact_admission_wire_test.go` exercises real HTTP on
  SQLite and PostgreSQL: machine to proof-backed, account-security, and
  self-scoped human-only routes; human to machine-only delivery; SCIM to human
  and human to SCIM; exact status/body equality against dialect-matched missing
  controls; six durable named refusal events.
- `internal/isolation/eligibility_test.go` derives route confinement from
  `api.Operations()`. Only `/healthz`, `/readyz`, and `/metrics`, which live
  outside OpenAPI, remain operational pins.
- Generated Go and TypeScript clients were refreshed after the contract change.

## Validation

- Focused OpenAPI, authz, service, server, and SQLite isolation tests: green.
- PostgreSQL artifact-admission wire test: green against the disposable local
  PostgreSQL fixture.
- Go generation, TypeScript client generation, typecheck/tests, docs checks,
  web typecheck/tests/build, UI-tagged Go build/tests, and `git diff --check`:
  green.
- Full dual-engine Go suite: green (2,706 tests across 40 packages).
- Independent standards and specification reviews: clean after fixes.
