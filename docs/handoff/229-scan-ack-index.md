# #229 — Decode and index scan acknowledgement tokens once

Status: implemented as a stacked change on PR #290 at
`9a340d8dce43e6cc1adceaca2c0e70d7c25b42d9`.

## Contract

Each acknowledgement submission remains a distinct `ackEntry` carrying its
original index, opaque token, decoded binding or decode error, and used state.
On first scanner use, `ackSet` opens every presented token exactly once and
indexes valid bindings by acknowledgement kind, locator, and rule digest.

Matching uses a second per-binding index for snapshot and content digest, with
input-ordered entry lists and cursors. Duplicate tokens therefore remain
distinct and are consumed in submission order without token × finding scans.
Rejection classification builds a first-finding index and walks retained token
entries in original order, preserving the fixed precedence:

`unreadable → surplus → version-skew → stale → expired`.

Token format, ruleset semantics, public refusal text, and Surface 1/Surface 2
kind separation are unchanged. No database migration or generated output is
required.

## Validation

- `go test -count=1 ./internal/service/... -run 'Scan|Ack'`: 16 passed
- `go test ./internal/service -run '^$' -bench '^BenchmarkAckSetMaximum$'
  -benchtime 3x -count=1`: maximum-size match and rejection benchmarks passed
- `go test ./internal/scanning/ -run '^$' -bench BenchmarkScan -benchtime 3x
  -count=1`: passed
- `go test -race -count=1 ./internal/service -run
  '^TestAckSet(OpensEachPresentedTokenOnce|RejectionPrecedenceAndInputOrder|CrossSurfaceReplayRejected|StaleContentAndVersionRejected|SurplusReported)$'`:
  5 passed
- `go test -count=1 ./internal/isolation/`: 1,090 passed
- `go build ./...`: passed
- `go vet ./...`: passed
- Exact stacked head on PR #290: `go test -count=1 ./...`: 3,139 passed in
  57 packages

## Review

- Standards axis: `CLEAN`
- Spec axis: exact duplicate-token fixture gap fixed; round-2 verification
  `CLEAN`

## CI repair

The first PR run's `no-egress` job was terminated by its hosted runner with
exit 143. A failed-job rerun then exposed a separate workflow defect: GitHub
reuses successful dependency jobs from the original attempt, while
`github.run_attempt` advances for the rerun. `app-build` therefore remained at
artifact `hikyo-app-<run>-1`, but rerun consumers requested
`hikyo-app-<run>-2`.

App artifacts are now scoped to `github.run_id` only. A partial rerun consumes
the prior successful dependency artifact; a full rerun safely replaces it with
`overwrite: true` after the exact-head build succeeds. The policy fixture pins
both requirements and rejects future attempt-scoped app artifact names.

The fresh exact-head run then reproduced the original shutdown on a second
hosted runner. `no-egress.sh` was terminating a derived process group after the
probe; when `setsid` forked, that group could include the runner shell. The
probe now enables strace's `--kill-on-exit` ownership and kills only the exact
tracer PID. A lifecycle fixture rejects negative process-group signals, and the
Ubuntu 24.04 probe completes without leaving the traced server behind.

CI-repair validation: build-artifact reuse, required-jobs, changed-path,
trusted-script, cache-policy, no-egress lifecycle, ShellCheck, actionlint, and
the complete Ubuntu 24.04 no-egress probe passed locally.
