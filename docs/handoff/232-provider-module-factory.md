# Handoff: #232 provider-aware adapter module factory

Issue: https://github.com/Hikyo-Org/Hikyo/issues/232 (parent #204; programme
#203; audit ID `BE16-B`). Base: `6dbb07bc713ec7cb2671274153b563e3683fa2b9`.

## Contract

- `adapter.Provider` is the closed compiled-in provider set. API defaulting
  resolves an omitted create provider explicitly to Forgejo; persisted and
  internal empty or unknown kinds fail before credential opening.
- One app registry owns the Forgejo and GitHub Actions constructors. One
  factory instance captures the operator egress policy and is injected into
  both worker loading and service planning/probing.
- `adapter.ModuleLease` binds every constructed module to idempotent cleanup.
  Partial construction errors release immediately; service operations defer
  release; worker loaders release on later errors or transfer one release-once
  closure with the loaded plaintext.
- Provider modules, credential lifetimes, request deadlines, destination
  validation, and egress exceptions are unchanged. This is compiled-in wiring,
  not a runtime plugin framework.

## Regression evidence

- Registry totality covers every supported provider exactly once.
- Unknown-provider tests prove worker and service refusal before credential use.
- Partial-construction, post-construction error, and repeated-release tests pin
  release-once behavior.
- Shared-factory coverage proves worker and service construction resolve the
  same module type and origin-scoped egress policy.

Generated outputs: none.

## Validation

```text
go test -count=1 ./internal/app/... ./internal/adapter/... ./internal/service/...
                                                          355 passed
go test -race -count=1 ./internal/adapter/...              110 passed
go build ./...                                             passed
go vet ./...                                               passed
go test -p 4 -count=1 -timeout=20m ./...                   3236 passed / 57 packages
```

Two-axis Codex review reached `CLEAN` in round 2 after release ownership was
made singular and production worker/service parity coverage was strengthened.
