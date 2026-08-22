# #229 — Decode and index scan acknowledgement tokens once

Status: implemented as a stacked change on PR #290 at
`ebf6de5f19bc8c51eb1e7d75a884cc7fd64177ea`.

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
