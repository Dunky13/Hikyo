# Issue #231: one Compose filesystem publication owner

## Contract

`RenderLock.Publish(PublishPlan) (PublishResult, error)` is the sole CLI path
for generation materialization, the atomic stamp switch, and generation GC.
`PublishPlan` contains only the runtime directory, local stamp keys, and final
target bytes. Live and offline adapters both call the same operation.

`PublishResult` is meaningful on success and failure. It reports candidate
stamps, per-target materialization, whether candidate stamps became active,
whether GC completed, and `Recover` facts: observed active stamps, planned
candidate stamps, whether the active selection is known, and whether normal
recovery/GC cleanup remains pending. A failed stamp commit re-reads `.env` so
an error after rename cannot incorrectly claim the previous stamps are active.

Publication is recoverable, not multi-file atomic. Before a stamp switch, the
previous selection remains active while complete or torn candidates are safe
to retry/recover. After the switch, candidate generations remain active even
if GC fails. GC still derives protected generations from the stamp file.

## Side-effect ordering

- Live: build render plan -> publish filesystem -> save encrypted snapshot ->
  save cursor.
- Offline: append and fsync disclosure records -> publish filesystem.
- Snapshot, cursor, and offline-record persistence are deliberately outside
  `Publish`; no cross-file atomicity is claimed.

## What changed

- `internal/compose/generation.go` owns publication sequencing and explicit
  recovery state behind one deep module interface.
- `internal/cli/compose.go` removes duplicated live/offline generation,
  stamp-commit, and GC loops.
- Failure tests cover materialization, stamp switch, post-commit, GC, live
  post-publish snapshot persistence, and offline pre-publish disclosure order.

## Generated outputs

None.

## Validation

- `go test -count=1 ./internal/compose/... ./internal/cli/...`: passed, 357 tests.
- Remaining full, race, demo, and review gates: pending.
