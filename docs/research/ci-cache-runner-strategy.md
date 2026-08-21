# CI cache and runner strategy

**Date:** 2026-08-21

**Scope:** Hikyo's Go-heavy required CI in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), GitHub-hosted runners, and the now-reverted Blacksmith pilot. External facts use only official GitHub, Go, and Blacksmith sources. Timing and storage statements are direct observations from Hikyo runs and APIs; they are not assumed to generalize.

## Recommendation

Use a **dependency-seeded, main-only cache**, not a fresh full build-cache upload from every job on every `main` run:

1. Keep `GOMODCACHE` separate from `GOCACHE`. Save one immutable module snapshot per dependency and pinned CI-tool graph in GitHub's cache backend.
2. Remove `github.run_id` and `github.run_attempt` from Go build-cache primary keys. Let a key live until its Go version, runner ABI, mode, or dependency graph changes. PRs restore only; one trusted `main` job writes each compatibility bucket.
3. Keep `release-snapshot`'s high-value `GOCACHE`, but stop publishing a new 2.1 GiB archive per run. A cold GoReleaser action took 12m54s; the warm action took 36s after a 42s restore and followed with a 26s save—about 11m12 saved even after build-cache transfer. Use one stable dependency/toolchain/build-mode key and save only on an exact miss.
4. Run every workflow job on GitHub-hosted `ubuntu-latest`. The public repository receives free GitHub-hosted compute, while Blacksmith minutes are limited and the pilot did not produce a valid same-SHA end-to-end win.
5. Enforce the topology in a repository fixture: reject third-party runner labels and run IDs in Go cache keys, and require every cache writer to be trusted-main-only with an exact-hit guard.

This preserves third-party downloads and compiled dependencies while avoiding a new whole-cache archive for first-party churn on every push. It also keeps the whole required graph on the free GitHub-hosted pool.

## What is being cached

Go has two different caches:

| Cache | Default path here | Contents | Correct invalidation boundary |
|---|---|---|---|
| Module cache (`GOMODCACHE`) | `~/go/pkg/mod` | Downloaded module source, metadata, zips, and checksum-database state | Dependency/tool module versions |
| Build/test cache (`GOCACHE`) | `~/.cache/go-build` | Compiled packages, linked/build intermediates, successful test results, and fuzz coverage-expanding inputs | Go's internal content/action hashes plus outer runner compatibility |

The Go module reference explicitly says the module cache stores downloaded modules and is distinct from the build cache; it is safe for concurrent access and may be shared across projects on one machine. Go verifies downloaded module content against `go.sum`. ([Go module cache](https://go.dev/ref/mod#module-cache), [module authentication](https://go.dev/ref/mod#authenticating))

The build cache is not “first-party binaries keyed by repository SHA.” Go caches recently built **packages**, detects staleness from source content and build flags, and gives each cached action an ID derived from the command, environment, input-file contents, and executable contents. A change in package A invalidates A and packages whose build inputs change because of A; unrelated packages and third-party dependencies can still hit. ([Go 1.10 build-cache design](https://go.dev/doc/go1.10#build), [`go help cache`](https://go.dev/cmd/go/#hdr-Build_and_test_caching), [`ActionID` definition](https://pkg.go.dev/cmd/go/internal/cache#ActionID))

Therefore first-party compilation is worth *restoring* even though every PR changes some Go source. Physically separating first-party from third-party objects would fight Go's content-addressed cache design; one stable compatibility bucket lets Go reject stale objects itself. What is not worthwhile is *uploading a complete new archive after every `main` run* without proving that later compile savings exceed transfer and storage cost.

Hikyo correctly uses `go test -count=1` for service-backed and security-sensitive suites. `-count=1` disables successful **test-result** replay, but it does not disable reuse of compiled packages from the build cache. ([Go test caching](https://pkg.go.dev/cmd/go#hdr-Testing_flags))

## Current Hikyo evidence

### Storage churn

At `2026-08-21T13:47:06Z`, GitHub's [live repository cache API](https://api.github.com/repos/Hikyo-Org/Hikyo/actions/caches?per_page=100) returned **23 entries / 14.62 GiB**. Seventeen Go entries consumed **13.24 GiB**. Eight `release-snapshot`, `race`, and `fuzz` entries alone consumed **10.10 GiB**. Current major prefixes were:

| Prefix | Entries | Total |
|---|---:|---:|
| `go-release-snapshot-*` | 2 | 4.03 GiB |
| `go-race-*` | 3 | 3.11 GiB |
| `go-fuzz-*` | 3 | 2.96 GiB |
| `go-web-*` | 2 | 1.20 GiB |
| `go-k8s-e2e-*` | 2 | 1.08 GiB |
| `go-mod-*` | 1 | 0.46 GiB |

Keeping only one current generation of every existing bucket would be about **7.22 GiB**, already below GitHub's 10 GB default without deleting any validation mode. Consolidating compatible buckets can come later, after timing proves it helps.

GitHub's included Actions-cache allowance is 10 GB per repository. Entries unused for seven days are removed; at the configured storage limit, GitHub evicts least-recently-used entries and warns that repeated create/evict cycles can cause cache thrashing. Usage above 10 GB is billable only when the repository/account has configured a higher limit. ([GitHub caching limits and eviction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#usage-limits-and-eviction-policy), [Actions storage billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions#how-use-of-github-actions-is-measured), [cache REST API](https://docs.github.com/en/rest/actions/cache))

**Repo inference:** every build-cache key ends in `${{ github.run_id }}-${{ github.run_attempt }}`. That guarantees an exact miss and a new immutable archive on every successful `main` run. The restore prefix then selects the newest previous archive. This is the direct cause of rapid multi-generation duplication.

### Transfer cost versus saved work

In [PR run `32485491113`, job `96780986863`](https://github.com/Hikyo-Org/Hikyo/actions/runs/32485491113/job/96780986863), `release-snapshot` missed `GOCACHE`: GoReleaser binary compilation took 12m33s and the whole action took 12m54s. In warm [main run `32486378726`](https://github.com/Hikyo-Org/Hikyo/actions/runs/32486378726), the job restored a 467 MB module cache in 14 seconds and a 2.064 GB build cache in 42 seconds; GoReleaser then took 36 seconds (13 seconds compiling binaries and 21 seconds archiving), followed by a 26-second build-cache save. Even charging the restore and save to the warm path, this cache saved about **11m12s**. `release-snapshot` is the strongest measured case for retaining `GOCACHE`; its problem is per-run archive churn, not low value.

During the now-reverted Blacksmith pilot, the same warm main run's `test` job restored 464 MB of modules in 21 seconds and 425 MB of ARM64 build cache in 11 seconds. Its tests still ran 7m24s; the job took 8m55s. In PR run `32485491113`, both Blacksmith caches missed, build took 2m20s, tests took 8m02s, and the job took 12m17s.

Those misses do **not** prove a branch-scope failure. The PR looked up its caches around 13:12 UTC; preceding [main run `32484974039`](https://github.com/Hikyo-Org/Hikyo/actions/runs/32484974039) did not finish saving the relevant seeds until around 13:17. The same cold-seed overlap explains the release and Blacksmith misses. The then-current per-run keys worsened this stampede: overlapping main runs could restore the same ancestor and each publish another full archive under a different run-ID key.

A GitHub-hosted cached test in [PR run `32482402791`](https://github.com/Hikyo-Org/Hikyo/actions/runs/32482402791) took 10m12s with an 8-second build and 8m33s test step. It used a different SHA/base workflow, so it is **not** a valid Blacksmith-versus-GitHub benchmark. Likewise, in main run `32486378726`, `web (desktop)` finished after `test`; moving `test` alone did not determine that run's overall completion time.

## Key and restore design

GitHub caches are immutable: an existing cache cannot be changed; a new key is required. On a miss, restore keys are searched in order, partial matches choose the newest matching cache, and a successful job may save the new primary key. ([GitHub cache semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#cache-action-usage), [key matching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#cache-key-matching))

Use keys shaped by **compatibility**, not by every run:

```text
go-mod-v2-<os>-<hash(go.mod + go.sum + pinned CI-tool modules)>

go-<mode>-v2-<os>-<arch>-<runner-image-ABI>-<go.mod+go.sum-hash>
restore prefix:
go-<mode>-v2-<os>-<arch>-<runner-image-ABI>-
```

- `mode` should start with `standard`, `race`, and only measured special buckets such as `fuzz`. Go's internal hash already accounts for tags and compiler options, but separating large instrumentation/multi-target populations avoids transferring irrelevant objects.
- `go.mod` plus `go.sum` is the application dependency and toolchain boundary: `go.mod` carries requirements, replacements, and Hikyo's exact Go directive; `go.sum` authenticates resolved module content. `scripts/ci/go-tool-modules.txt` adds pinned actionlint and govulncheck modules that are invoked outside `go.mod`. On a dependency or tool change, the broad restore prefix supplies older still-valid objects; the trusted writer then saves the new exact graph key.
- Do **not** hash `**/*.go` into the outer key. `setup-go` warns that doing so creates frequent caches and can slow workflows through added uploads/downloads. Go already rejects stale objects internally. ([`setup-go` source invalidation guidance](https://github.com/actions/setup-go/blob/main/docs/advanced-usage.md#cache-invalidation-on-source-changes))
- Include OS, architecture, and GitHub's `ImageOS` runner ABI; the exact Go version is already inside the `go.mod` hash. `setup-go` recommends target-specific cache inputs and its restore-only example includes OS, architecture, image suffix, and exact Go version. This avoids downloading a large archive that can only miss internally. ([`setup-go` multi-target guidance](https://github.com/actions/setup-go/blob/main/docs/advanced-usage.md#multi-target-builds), [restore-only example](https://github.com/actions/setup-go/blob/main/docs/advanced-usage.md#restore-only-caches))
- `GOMODCACHE` contents are source and architecture-neutral, so x64 and ARM Linux jobs may share one module lineage **within the same cache backend**. Keep OS/archive boundaries if Windows is introduced because cross-OS archives are disabled by default. ([Actions cache cross-OS option](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#input-parameters-for-the-cache-action))
- Hikyo's actionlint and govulncheck commands are pinned outside `go.sum`. Their authoritative module versions live in `scripts/ci/go-tool-modules.txt`; `run-go-tool.sh` invokes those exact pins, the file participates in the module-cache key, and the sole trusted writer downloads both complete transitive module graphs.

Use `actions/cache/restore` in every reader and `actions/cache/save` in one successful trusted `main` writer per bucket. This is the pattern `setup-go` recommends for several builds in one repository and for avoiding parallel-writer races. ([`setup-go` parallel-build guidance](https://github.com/actions/setup-go/blob/main/docs/advanced-usage.md#parallel-builds))

## Branch and provider boundaries

GitHub scopes caches by key, cache version, and branch. A PR can restore caches from its branch, base branch, and default branch, but cannot access sibling/child branches. Default-branch cache reads are the intended way for main-only writers to accelerate PRs. Cache paths must never contain secrets because a PR, including one from a fork, can read eligible base-branch caches. ([GitHub branch scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#restrictions-for-accessing-a-cache), [`actions/cache` scopes](https://github.com/actions/cache#cache-scopes))

Blacksmith transparently redirects official `actions/cache`, `actions/cache/restore`, `actions/cache/save`, and `setup-go` traffic to its colocated cache **instead of GitHub's backend**. Its old `useblacksmith/cache` and language setup forks are archived. Blacksmith says cache use has no additional charge, includes 25 GB per repository per week, and evicts least-recently-used entries that have not been accessed for more than seven days. ([Blacksmith Actions cache](https://docs.blacksmith.sh/blacksmith-caching/dependencies-actions))

**Repo decision:** the pilot was reverted and every workflow now runs on GitHub-hosted `ubuntu-latest`. One GitHub cache backend therefore serves all jobs, and `test` remains the sole trusted module-cache writer. The cache-policy fixture rejects a future third-party runner label unless this decision is deliberately revisited.

## Runner placement

The repository is [public](https://api.github.com/repos/Hikyo-Org/Hikyo). GitHub documents `ubuntu-latest` for public repositories as a 4-CPU/16-GB standard VM with free, unlimited usage. Therefore Blacksmith has no direct compute-cost advantage here; it must earn scarce minutes by reducing the critical path. ([GitHub public runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories), [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions))

Blacksmith grants 3,000 x64 2-vCPU-equivalent minutes per organization each month. Higher-vCPU runners consume proportionally more; ARM has a 0.625 price ratio. The current 4-vCPU ARM runner therefore consumes **1.25 allowance minutes per wall-clock minute**. Blacksmith's job metrics expose CPU, memory, and network utilization for right-sizing. ([Blacksmith instance types and free-minute conversion](https://docs.blacksmith.sh/blacksmith-runners/overview#faq), [Blacksmith metrics](https://docs.blacksmith.sh/blacksmith-observability/metrics))

| Jobs | Placement now | Reason |
|---|---|---|
| Every workflow job | **GitHub `ubuntu-latest`** | The repository is public, GitHub-hosted compute is free, all jobs share one cache backend, and no valid same-SHA evidence showed that limited Blacksmith minutes reduced end-to-end p95. |

## Measurement plan

Run a two-week or 20-comparable-run experiment; do not compare unrelated PRs as if they were A/B samples.

1. **Fix observability first.** Record workflow critical-path duration, queue time, every job/step duration, cache exact/fallback/miss status, archive size, restore/save seconds, and provider. Snapshot GitHub cache usage through the [cache REST API](https://docs.github.com/en/rest/actions/cache); use Blacksmith's job metrics for CPU, memory, and network.
2. **Test the same SHA four ways.** GitHub cold, GitHub warm, Blacksmith cold, Blacksmith warm. Use the same runner size, Go version, event/ref semantics, and service images. Repeat enough times to report median and p95, not the best run.
3. **Exercise cache granularity.** Run an unchanged SHA, a leaf first-party package change, a shared internal package change, and a `go.sum` change. Keep `-count=1`: measured gains then represent compilation/download reuse, never stale test-result replay.
4. **Score net value.** Per bucket, calculate `uncached work - restore - save`; delete any cache with non-positive median savings. For the current ARM 4-vCPU runner, calculate Blacksmith allowance as `wall minutes × 1.25`, then report workflow minutes saved per allowance minute.
5. **Set a promotion gate.** Move another job only when it is on the required workflow's p95 critical path in at least 25% of sampled full runs and same-SHA Blacksmith p95 materially reduces end-to-end completion within the monthly minute budget. Recheck after cache topology changes because faster caching can change which job is critical.

For difficult cache misses, Go provides `GODEBUG=gocachehash=1` to print hash inputs and `gocacheverify=1` to rebuild and verify cached entries; use these only on sampled diagnostic runs because output is intentionally large. ([Go cache diagnostics](https://go.dev/cmd/go/#hdr-Build_and_test_caching))

## Ranked options

| Rank | Option | Benefit | Cost/risk |
|---:|---|---|---|
| **1** | **Implemented: stable dependency/env keys + main-only exact-miss writers** | Stops per-run archive churn immediately; keeps module/compile reuse; uses one GitHub cache backend; lets evidence remove negative caches. | Stale-but-safe seed until dependency/env key changes. |
| **2** | Minimal: remove run IDs, add `cache-hit != 'true'` save guards, keep every job bucket | Largest storage reduction with least behavioral change. | Retains duplicated compiled dependencies across many job buckets and does not by itself fix GitHub-vs-Blacksmith writers. |
| **3** | Shared standard bucket plus separate `race`/measured special buckets | Best reuse/storage balance: unchanged first- and third-party packages can serve several jobs. | Needs a deliberate writer and before/after proof that larger shared downloads beat smaller job-specific rebuilds. |
| **4** | Re-run a controlled Blacksmith experiment | Could lower wall clock if a critical job proves faster. | Spends limited minutes, splits cache backends, and is not justified by current same-SHA evidence. |

Option 1 is implemented: `release-snapshot` and the other Go modes use stable compatibility keys, every writer skips exact hits, PRs remain read-only, pinned CI-tool modules are seeded centrally, scheduled isolation reuses the race cache, and fuzz alone rotates weekly to retain coverage discoveries. Re-rank or remove buckets only after measuring restore cost against saved work.
