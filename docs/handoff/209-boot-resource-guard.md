# Handoff: #209 boot resource ownership guard

Issue: https://github.com/Hikyo-Org/Hikyo/issues/209. Implementation is based
on `origin/main` commit `d31919a877732abfa1293fe2784462aeb9798b22`.

## Implemented locally

- `internal/app/app.go` now arms a private `bootGuard` before startup resource
  acquisition, registers database and listener cleanup immediately, releases
  them in reverse acquisition order on every error, and disarms only after the
  complete `Server` exists.
- Cleanup is idempotent. Cleanup errors are logged without replacing the
  primary boot error. Successful boot leaves `Server.Close` as the sole
  steady-state owner.
- A narrow private `bootResources` seam covers only database, listener, and
  outbound-directory-client construction/cleanup. Service wiring remains local
  to boot; no general dependency-injection container was added.
- `internal/app/boot_cleanup_test.go` injects failures before database
  acquisition, after database acquisition, and after listener acquisition. It
  asserts exact close counts, listener-before-database order, primary-error
  preservation, idempotence, continued cleanup after a close error, and
  successful ownership transfer.

## Verification

```text
rtk go test -count=1 ./internal/app/
Go test: 32 passed in 1 package

rtk go test -race -count=1 ./internal/app/
Go test: 32 passed in 1 package

rtk go test -count=1 ./...
Go test: 2913 passed in 56 packages

go list ./... | grep -v '/internal/isolation$' | xargs go test -race -count=1
All selected packages passed, including internal/app, internal/lint,
internal/service, and internal/store.

rtk go vet ./internal/app/
rtk go build ./...
rtk git diff --check
All succeeded.
```

## Review

- Matt Pocock Standards axis: `CLEAN`.
- Matt Pocock Spec axis: initial review found early disarm and missing
  Boot-level close assertions; both were fixed; round 2: `CLEAN`.
- Native Codex (`gpt-5.6-sol`, high) found no blocking issue: resource
  ownership transfer and cleanup were reported consistent and correctly
  ordered. Its sandbox could not bind local sockets, so parent-run socket and
  race evidence above is authoritative.

## Delivery state

Local implementation only. No push, pull request, merge, CI, or deployment is
claimed. PR description must reference `Closes #209`, state that no migration
or generated output changed, and include the verification results above.

## Suggested skills

- `code-review` for any follow-up diff.
- `cross-model-review` if Claude-authored code changes.
