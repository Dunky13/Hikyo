# CI speed phases 1–5 handoff

## Scope

These changes keep every existing CI assertion while shortening the critical
path, preventing obsolete pull-request runs from consuming runners, and
skipping validation domains that a pull request cannot affect.

- `changes` emits a tested JSON plan from the pull request's merge-base diff.
  Unknown paths and changes to the classifier or CI workflow select every job.
- Dependency manifests and build/tool configuration select every job because
  their effects can cross validation-domain boundaries.
- Pull requests run the complete suite inside each selected domain. They do not
  narrow individual Go, Vitest, or Playwright suites.
- Every `main` push selects every validation job. This is the full integration
  backstop and seeds trusted caches.
- `ci-required` is the permanent aggregate status. It requires `changes` and
  verifies each planned job succeeded, each unplanned job skipped, and DCO had
  the event-appropriate result.
- The obsolete `supply-chain-fixtures` compatibility context is removed;
  ruleset 20539346 requires only `ci-required`.
- Pull-request updates cancel older runs of the same PR. Main pushes use their
  run ID as the concurrency key, so none are discarded while pending.
- Go build caches are isolated by job. Pull requests restore them; successful
  `main` runs save rolling caches. All Go CI jobs restore one dependency-keyed
  module cache, while only `test` saves it on trusted `main`. Tagged releases
  build without a restored Go cache.
- Full six-target GoReleaser output and its manifest classifier run together
  in `release-snapshot`, parallel to the release shell fixtures.
- Go formatting and generated-code freshness run in `generated`, parallel to
  the full build, vet, SQLite, and PostgreSQL test job.
- Restored build caches never make tests vacuous: Go test commands use
  `-count=1`.

## Required gate state

Ruleset 20539346 was re-read before phase 5. It is active and strict, has no
bypass actors, and requires exactly `ci-required`. The checked-in desired state
remains `release/repository/main-ci-gate.json`.

## Validation before commit

- Actionlint and ShellCheck passed.
- Changed-path and required-job positive/negative fixtures passed.
- Generated Go and TypeScript clients were fresh.
- Go build, vet, and 2,297 PostgreSQL-backed tests in 38 packages passed;
  `internal/isolation` executed against PostgreSQL rather than skipping.
- Client tests: 4 passed. Web unit tests: 48 passed. Tagged UI tests: 121 passed.
  Playwright desktop/mobile flow tests: 86 passed.
- Docs verification passed.
- GoReleaser produced and classified all six OS/architecture archives.
