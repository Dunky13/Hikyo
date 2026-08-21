# CI race and fuzz sharding handoff

## Outcome

Race and fuzz return as blocking pull-request checks for Go, SQL, operator, and
Kubernetes Go changes without reducing their coverage. Both checks use three
parallel shards and retain the existing aggregate job IDs, so `ci-required`
continues to enforce `race` and `fuzz` without a ruleset migration.

No JUnit dependency or report format was added. The planner is exercised
through its public command-line interface by native shell fixtures, matching
the rest of the CI policy tests.

The follow-up build optimization now produces the embedded SPA and native UI
binary once in `app-build`. Both browser shards consume that exact run-scoped
artifact. The six-target GoReleaser snapshot stays parallel: serializing it
behind the native browser build would lengthen the critical path.

## Coverage and trust model

- Race assigns all 56 Go packages except `internal/isolation` exactly once.
  Isolation remains covered by the normal suite and the dedicated scheduled
  race-isolation workflow because its probe-based namespace/container tests
  exceed the detector's per-package timeout.
- Fuzz discovers declarations from Go test files with the Go parser rather
  than compiling every package with `go test -list`. It assigns all 17 current
  targets exactly once and keeps targets from one package on one shard.
- Pull requests cannot edit the planner used to plan their own validation. The
  reusable base-branch workflow loads `analysis-shards-go/main.go` from the
  pull request base SHA, then plans against the exact checked-out head.
- A new package or fuzz target is deterministically assigned with FNV-1a.
  Explicit assignments keep the currently slow packages balanced.
- Each race shard has its own PostgreSQL service and race build cache. Each
  fuzz shard has its own weekly rotating build/fuzz cache.

## Failure reporting

Every fuzz matrix lane finishes even if another lane fails. Each failing lane
uploads only new, bounded Go reproducers. The aggregate `fuzz` job downloads
and merges those shard artifacts into the existing canonical artifact name,
so `fuzz-report.yml` keeps its current trusted reporting contract.

## Timing evidence

Before this change, the latest cold main run spent about 8m06s in race and
10m40s in fuzz. Warm pull-request history was about 7–8 minutes for race and
5m48s–5m57s for fuzz. Fuzz also spent about 3m30s compiling packages only to
discover target names.

Local exact-DSN race validation completed the three warm shards in 1m45s,
1m14s, and 1m18s. This demonstrates the intended critical-path reduction but
is not a hosted-runner benchmark. Record the first warm GitHub Actions timings
after merge before treating the speedup as production evidence.

Before the follow-up, frontend install, typecheck, unit tests, and build ran in
both browser matrix legs. Browser global setup also linked four more UI binaries
across the two isolated instances in each shard. The new graph runs browser
frontend validation and build once and supplies one prebuilt binary to both
shards. Release snapshot keeps its small SPA build so its six cross-platform
builds can run concurrently. Hosted timing remains pending until this exact
head runs on GitHub.

## Development downloads

A successful trusted `main` run retains the six GoReleaser archives,
`checksums.txt`, and `DEVELOPMENT-SNAPSHOT.txt` for 14 days as
`hikyo-development-<commit>`. Pull requests do not publish this artifact.

This is deliberately not a GitHub Release. It is unsigned evaluation output
without a release manifest, installer, upgrade promise, or production support.
The tag-only draft, offline recovery binding, primary signing, verification,
and publish sequence in `docs/release/signing.md` remains unchanged.

## Validation

- Full PostgreSQL-backed `go test -count=1 ./...` passed.
- All three exact race shard commands passed with `-race -vet=off -count=1`.
- All 17 planned fuzz targets entered their real fuzz functions and passed
  with `-fuzztime=1x`.
- Planner, changed-path, trusted-script, cache-policy, required-job, and fuzz
  reporting fixtures passed.
- Build-artifact reuse fixture, web typecheck/unit/build, and docs verification
  passed.
- Actionlint, ShellCheck, Go build, Go vet, formatting, and diff checks passed.
