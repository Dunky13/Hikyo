# Issue #238: prepared single-use disclosure sink

## Contract

`disclose.Prepare` now selects and owns the exact destination before any
display-once value is minted or requested. It returns one `PreparedSink`:

- `Destination` reports the already-selected audit delivery mode;
- `WriteOnce` consumes the sink, writes through the reserved handle, and
  closes it on success or failure;
- a second write is refused with `ErrSinkConsumed`;
- `Abort` is idempotent and closes an unused terminal or removes only the
  exact empty file reservation owned by the sink;
- `AbortOnReturn` joins cleanup failures into the caller's returned error, so
  cancellation and pre-write failures cannot hide failed cleanup.

## Platform ownership

Unix preparation retains the checked parent dirfd and the `O_EXCL`,
`O_NOFOLLOW`, exactly-`0600` file descriptor. `WriteOnce` fsyncs the file and
directory. `Abort` requires both an empty open descriptor and the same
device/inode at the retained dirfd before unlinking. The parent is owner-only
and not group/world writable, so untrusted UIDs cannot replace the entry.

Windows preparation uses `CREATE_NEW` with no sharing and retains that handle
until write or abort. Empty abort uses `FileDispositionInfo` so deletion is
bound to the owned handle. The pre-existing Windows DACL limitation remains;
Windows is a client platform, not a bootstrap host.

## Migrated callers

All former `Preflight` then `Emit` pairs were removed across local admin and
backup, account reset/TOTP/recovery, service-account/SCIM/remote credentials,
definitions export, value reveal/export, and single/multi-environment import
artifacts. Prepared file reservations are aborted on every early return.

No API, database, migration, or generated output changed.

## Review and validation

- Standards review round 2: CLEAN
- Issue #238 spec review round 2: CLEAN
- `go test -count=1 ./internal/disclose/... ./internal/app/... ./internal/cli/...`:
  280 passed
- `go test -race -count=1 ./internal/disclose/...`: passed
- `go vet ./internal/disclose/... ./internal/app/... ./internal/cli/...`: passed
- `go build ./...`: passed
- `go test -count=1 ./...`: 3,083 passed in 57 packages
- Windows `internal/disclose` tests: cross-compiled on macOS; Windows-only
  lifecycle fixtures are committed for native CI execution
