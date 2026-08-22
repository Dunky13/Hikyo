# Issue #231: one Compose filesystem publication owner

## Contract

`RenderLock.Publish(PublishPlan) (PublishResult, error)` is the sole CLI path
for generation materialization, the atomic stamp switch, and generation GC.
`PublishPlan` contains only the runtime directory, local stamp keys, and final
target bytes. Live and offline adapters both call the same operation.

`PublishResult` is meaningful on success and failure. It reports candidate
stamps, per-target materialization, the completed `PublishPhase`, and `Recover`
facts: observed active stamps, planned candidate stamps, whether the active
selection is known, and whether normal recovery/GC cleanup remains pending. A
failed stamp commit re-reads `.env` so an error after rename cannot incorrectly
claim the previous stamps are active.

Publication is recoverable, not multi-file atomic. Before a stamp switch, the
previous selection remains active while complete or torn candidates are safe
to retry/recover. After the switch, candidate generations remain active even
if GC fails. GC derives protected generations from the stamp file and retains
the configured history independently for each target.

## Side-effect ordering

- Live: build render plan -> publish filesystem -> persist apply-pending state
  -> save encrypted snapshot -> save cursor.
- Offline: append and fsync disclosure records -> publish filesystem.
- Snapshot, cursor, and offline-record persistence are deliberately outside
  `Publish`; no cross-file atomicity is claimed.
- Sync compares active stamps with durable last-applied stamps. Docker success
  records the applied stamps before apply-pending state is cleared, so any
  crash or bookkeeping failure remains retry-visible.

## What changed

- `internal/compose/generation.go` owns publication sequencing and explicit
  recovery state behind one deep module interface.
- `internal/cli/compose.go` removes duplicated live/offline generation,
  stamp-commit, and GC loops.
- Failure tests cover materialization, stamp switch, post-commit, partial GC,
  per-target retention, torn-generation recovery, live snapshot/cursor
  persistence, offline pre-publish disclosure order, and durable apply retry.

## Generated outputs

None.

## Validation

- `go test -race -count=1 ./internal/compose/... ./internal/cli/...`: passed,
  363 tests.
- `go vet ./internal/compose/... ./internal/cli/...`: passed.
- `go test -count=1 ./internal/isolation -run '^TestComposeCLI'`: passed,
  6 tests.
- `go build ./...`, `go vet ./...`, and `go test -count=1 ./...`: passed;
  full test suite passed 3,251 tests in 57 packages.
- `./scripts/compose-demo.sh`: passed; 21 stored values were byte-exact,
  embedded-newline refusal preserved the generation and stamps, and sync moved
  the stamp and restarted the app.
- `gofmt -l internal/compose internal/cli` and `git diff --check`: clean.
- Three code-review rounds completed; standards and specification reviews are
  clean.
