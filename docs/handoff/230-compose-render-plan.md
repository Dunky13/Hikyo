# Issue #230: one pure Compose render plan

## Contract

`compose.BuildRenderPlan(RenderInput) (RenderPlan, error)` is the single pure
decision point for live and offline Compose rendering. Adapters provide ordered
targets and normalized source rows plus explicit projection and absent-key
policy. The plan owns exact target bytes, snapshot rows, omissions, and typed
refusals.

Full live input refuses a configured key absent from the server delivery; full
offline input refuses a configured key absent from the sealed snapshot.
Config-only input skips absent keys because projected-out secrets and deleted
config keys are indistinguishable in that projection. Existing CLI refusal
text, sorting, all-or-nothing writes, and generation ordering remain unchanged.

`hikyo run` is deliberately excluded. It delivers the full environment, merges
against the sanitized parent process, performs collision and ARG_MAX checks,
then execs; it does not select render targets or encode dotenv files.

## What changed

- `internal/compose/renderplan.go` defines the pure input, plan, omission, and
  refusal model and performs selection, loader-control checks, raw encoding,
  and snapshot-row collection without filesystem, network, clock, crypto, or
  secret-fetch work.
- Live and offline CLI paths now only normalize their source into `RenderInput`,
  execute the shared plan, and perform source-specific side effects afterward.
- Pure golden coverage pins plan shape. Adapter tables prove equivalent live
  and offline inputs produce identical target bytes and refusals, including
  config-only and refusal cases. Omission provenance remains source-specific:
  a live unset row is `no-value`; a snapshot that never stored it is `absent`.

## Generated outputs

None.

## Validation

- `go test -count=1 ./internal/compose/... ./internal/cli/...`: 350 passed.
- `go test -race -count=1 ./internal/compose/... ./internal/cli/...`: 350 passed.
- `go vet ./internal/compose/... ./internal/cli/...`: passed.
- `go test -count=1 ./internal/isolation -run '^TestComposeCLI'`: passed.
- `go build ./...`, `go vet ./...`, and `go test -count=1 ./...`: passed.
- `./scripts/compose-demo.sh`: passed all 21 byte-exact round trips,
  refusal atomicity, doctor, and sync/restart checks.
- `git diff --check` and scoped `gofmt -l`: passed.
- Standards and issue-spec review axes: CLEAN in round 2.
