# Issue #239: bounded controlling-terminal session

## Contract

`disclose.TerminalSession` now owns one validated read/write/close handle for a
single command ceremony:

- construction rejects and closes handles that cannot read confirmations;
- `Confirm` and `ConfirmEnumerated` accept at most eight input bytes;
- `ConfirmName` retains the exact-name, 256-byte confirmation contract;
- terminal destination approval completes during preparation, before any
  display-once material is minted;
- `WriteDisclosure` uses the same handle as prior confirmations;
- password and TOTP prompts reuse the session's input descriptor without
  reopening the controlling terminal;
- input, output, decline, abort, and command-return paths close the handle;
- `Close` is idempotent, so command and prepared-sink ownership can overlap
  without closing the platform handle twice.

`Prepare(options, session)` lets a `PreparedSink` wrap the command's session
for the terminal leg. Explicit file and `--dangerously-print` destinations
remain independent and preserve the prepared-sink guarantees from #238.

## CLI ownership

Platform startup opens at most one controlling-terminal session for a client
command and passes it through `cli.IO`. `cli.Run` closes it on every return.
Confirmations and all terminal disclosure preparation use that session; raw
terminal-opener callbacks are no longer passed through CLI or disclosure
options. No session is cached across process invocations.

## Platform behavior

Unix retains one read/write `/dev/tty` descriptor. Windows presents separate
`CONIN$` and `CONOUT$` descriptors behind one session handle and closes both.
Neither platform falls back to redirected stdin, stdout, or stderr.

## Validation

- `go test -count=1 ./internal/disclose/... ./internal/app/... ./internal/cli/...`:
  287 passed
- `go test -race -count=1 ./internal/disclose/... ./internal/cli/...`: 250 passed
- `go test -count=1 ./...`: 3175 passed across 57 packages
- `go vet ./internal/disclose/... ./internal/app/... ./internal/cli/...`: passed
- `go build ./...`: passed
- Windows `internal/disclose` and `internal/cli` tests: cross-compiled on macOS;
  the native-only composite-console lifecycle fixture is committed for Windows
  CI execution
- three Codex-only review rounds: final standards and spec reviews clean

No API, database, migration, generated output, or wire contract changed.
