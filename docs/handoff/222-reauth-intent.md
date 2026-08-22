# Handoff: #222 closed reauthentication intents

Issue: https://github.com/Hikyo-Org/Hikyo/issues/222 (parent #204; programme
#203; audit ID `BE06-A`). Base: `2a7509c95951bec568a9080f2fa2144f097438c4`.

## Contract

- `service.ReauthIntent` is the closed value crossing service boundaries.
  Disclosure constructors cover reveal, copy, publish, and mint for exactly one
  environment and a canonical key set. Adapter constructors cover only the four
  allowed operations and a canonical environment set.
- One descriptor table owns variant-to-purpose-to-operation mapping. Intent
  bindings derive stored purpose/operation/set fields and byte-exact WebAuthn
  challenge JSON from that relation. Unknown variants fail closed.
- Unbound TOTP/OIDC/WebAuthn windows remain environment-scoped. Exact workspace
  step-up stores authorization operations such as `value.reveal` while the HTTP
  approval projection remains the wire spelling `reveal`.
- Server handlers parse the unchanged OpenAPI request shapes into intents before
  dispatch. CLI handoff, WebAuthn completion, persisted workspace handoff, and
  disclosure ceremony consumers reconstruct or receive intents before use.
- Persisted reauthentication-window columns and signed JSON field order are
  unchanged. Generated outputs: none.

## Regression evidence

- Exhaustive table covers unbound, four disclosure, and four adapter variants,
  including canonical ordering and exact challenge-binding bytes.
- Boundary tables reject mixed TOTP, passkey, CLI, and workspace combinations
  before service dispatch.
- Cross-intent isolation fixtures preserve purpose, operation, environment,
  key-set, adapter-set, unbound-window, and workspace refusal behavior.
- Two-axis Codex review reached `CLEAN` after ceremony APIs were migrated from
  raw purpose/environment/key arguments and descriptor classification became
  exhaustive.

## Validation

```text
go test -count=1 ./internal/service/... ./internal/server/... ./internal/cli/...
                                                             587 passed
go test -count=1 ./internal/isolation/                       1090 passed
go test -count=1 ./...                                       3082 passed / 57 packages
go vet ./...                                                 passed
gofmt -l <changed Go files>                                  clean
git diff --check                                             clean
```
