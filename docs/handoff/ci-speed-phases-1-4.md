# CI speed phases 1–4 handoff

## Scope

This change keeps every existing CI assertion while shortening the critical
path and preventing obsolete pull-request runs from consuming runners.

- `ci-required` is the permanent aggregate status. It requires `client`,
  `dco`, `docs`, `generated`, `lint`, `release-snapshot`,
  `supply-chain-checks`, `test`, and `web`.
- The old required `supply-chain-fixtures` context temporarily forwards
  `ci-required`. This keeps ruleset 20539346 safe during the migration.
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

## Required post-merge gate migration

Do not change the live ruleset before this commit merges under the old required
contexts.

1. Verify the post-merge `main` run reports a successful `ci-required` status.
2. Confirm `release/repository/main-ci-gate.json` still requires only
   `ci-required`.
3. Apply that repository configuration with
   `scripts/release/configure-repository.sh`.
4. Re-read live ruleset 20539346 and confirm strict mode plus exactly one
   required context: `ci-required`.
5. Remove the compatibility `supply-chain-fixtures` job in a later PR.

## Validation before commit

- Actionlint and ShellCheck passed.
- Required-job positive and negative fixtures passed.
- Generated Go and TypeScript clients were fresh.
- Go build, vet, tagged UI build/tests, and the full PostgreSQL-backed suite
  passed. `internal/isolation` executed against PostgreSQL rather than skipping.
- Client tests: 4 passed. Web unit tests: 20 passed. Playwright desktop/mobile
  flow tests: 36 passed.
- Docs verification passed.
- GoReleaser produced and classified all six OS/architecture archives.
