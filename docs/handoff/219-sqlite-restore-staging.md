# Handoff: #219 uniquely owned SQLite restore staging

Issue: https://github.com/Hikyo-Org/Hikyo/issues/219 (parent #204; programme
#203; audit ID `DB02-B`).

## What changed

- `store.RestoreSQLite` creates its staging database with `os.CreateTemp` in
  the destination directory. Every concurrent attempt therefore owns a unique
  path while preserving same-filesystem publication.
- `sqliteRestoreStaging` owns the open file plus the exact database, WAL, and
  SHM paths. It closes the file before SQLite opens the snapshot and removes
  only those owned paths during unwind.
- Cleanup errors join the restore error instead of disappearing. A cleanup
  failure after publication is therefore explicit even though the destination
  hard link already exists.
- Publication remains `os.Link`: the destination is never overwritten if it
  appears while a restore is running. `os.CreateTemp`'s `0600` mode carries to
  the published hard link.

## Regression evidence

- A mutation barrier holds one restore open while a second reaches the same
  phase. Their staging paths must differ; exactly one publication succeeds and
  the other returns `ErrTargetNotEmpty`.
- The cleanup table injects failures at staging creation, archive extraction,
  staging close, database open, mutation, database close, fsync, publication,
  and cleanup. Every created staging artifact is absent afterward.
- The publication-conflict row proves pre-existing target bytes remain
  unchanged. The permission test proves the published database is `0600`.

## Validation

```text
go test -count=1 ./internal/store -run 'TestRestoreSQLite'        13 passed
go test -count=1 ./internal/store/...                            61 passed
go test -race -count=1 ./internal/store/...                      61 passed
go test -count=1 ./internal/isolation -run '^TestBackupRestoreDrillSQLite$'
                                                                 11 passed
go test -count=1 ./...                                           2916 passed
```

The first full-suite run passed 2802 tests but three unrelated tests timed out
under package-level contention. Both isolation failures passed together (2/2),
the lint package passed alone (28/28), and the unchanged full command then
passed all 2916 tests.

Docs build, Astro diagnostics, OSS/PWA static policy, live-docs, and fallback
checks passed. The offline Playwright check could not launch Chromium in this
macOS agent (`MachPortRendezvousServer`, error 141) on two attempts; no page or
application code ran.
