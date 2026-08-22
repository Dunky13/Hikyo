# Handoff: #236 explicit CLI authentication artifacts

Issue: https://github.com/Hikyo-Org/Hikyo/issues/236 (subissue of #205;
programme #203; audit `CL01-A`). Implemented and validated on current
`origin/main` at `136f7567b8556e4198e0112c4237464b7e5f9647`.

## Contract

- `AuthArtifact` is a sealed union: `HumanSession{SessionArtifact}` or
  `MachineCredential{Origin, CredentialRef}`. Machine credential plaintext
  remains only on the request client; the aggregate records `HIKYO_TOKEN` or
  `--token-file`, never the value or file path.
- The leaf-command authentication table is exhaustive and default-deny.
  Machine eligibility is limited to the locked automation commands;
  management, account, adapter, and other human-only commands reject machine
  artifacts before network work.
- `--auth=human|machine` selects explicitly. When both eligible artifact kinds
  exist and neither is selected, resolution refuses rather than letting an
  ambient machine credential replace the stored human session. An ineligible
  ambient artifact does not displace the one eligible artifact.
- Legacy unversioned `sessions.json` maps still decode unchanged. A future
  numeric version envelope fails with an actionable CLI-upgrade message.
  Machine credentials remain invocation-scoped and are never persisted as
  sessions.

## Tests and fixtures

- The auth table test proves every shipped top-level command has leaf rules and
  asserts the locked human/machine boundaries for mixed families.
- Resolution tests cover explicit machine artifacts, plaintext exclusion,
  dual-eligible collision refusal, explicit human selection without reading a
  token file, ineligible ambient-token handling, and pre-network human-only
  refusal.
- `sessions-legacy.json` and `sessions-future.json` exercise safe legacy reads
  and actionable future-version failure.
- The scanning isolation canary now stores its administrator token as the human
  CLI session it actually is instead of feeding that token through the machine
  `--token-file` channel.

Generated code: none. The frozen help golden changed only for the new `--auth`
selection guidance.

## Validation

```text
gofmt -l internal/cli
  clean
go build ./...
  passed
go vet ./...
  passed
go test -count=1 ./internal/cli/...
  251 passed
go test -count=1 ./internal/isolation/ -run 'CLI|Machine'
  36 passed
go test -count=1 ./internal/isolation/ -run TestScanningCanarySweepSQLite
  1 passed
go test -p 4 -count=1 -timeout=20m ./...
  3260 passed in 57 packages
```

The first full-suite run exposed the scanning canary's misclassified human
token. After the fixture stored a real `SessionArtifact`, the focused canary
and complete suite passed without changing production eligibility.

## Review

- Round 1 Standards and Spec both found the same two blockers: top-level policy
  was too coarse, and ambient machine auth still silently won collisions.
- The implementation moved policy to exact leaf operations supplied by
  `parseCommon`, added explicit selection, and added collision regression tests.
- Round 2 Standards: CLEAN. Round 2 Spec: CLEAN.

Exact-head CI and merge evidence live on the pull request.
