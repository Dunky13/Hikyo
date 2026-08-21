# Handoff: Dependabot #5 js-yaml CPU denial of service

## Scope

Dependabot [#5](https://github.com/Hikyo-Org/Hikyo/security/dependabot/5)
reports `GHSA-52cp-r559-cp3m` / `CVE-2026-59869` against the TypeScript
client's transitive development dependency on `js-yaml@4.1.1`.

## Decision

- Keep `@hey-api/openapi-ts@0.97.3`; upgrading it cannot close the finding
  because its latest transitive parser still pins a vulnerable `js-yaml`.
- Override vulnerable `js-yaml` 4.x versions to `4.3.1`. This is the smallest
  patched version that closes both the reported merge-key-chain finding and the
  newer `GHSA-5p4m-2wfm-xmqj` ordered-map CPU denial of service.
- Treat `clients/ts/pnpm-workspace.yaml` as build configuration in the changed-
  path classifier so override-only changes select the full CI suite.

## Changed surfaces

- `clients/ts/pnpm-workspace.yaml`: declares the narrow transitive override.
- `clients/ts/pnpm-lock.yaml`: resolves the sole `js-yaml` copy to `4.3.1`.
- `scripts/ci/classify-changed-paths.sh`: classifies the pnpm workspace config
  as a full-suite dependency/config change.
- `scripts/ci/classify-changed-paths_test.sh`: locks that classification in.

## Verification

- `pnpm --dir clients/ts audit --json`: zero vulnerabilities.
- `pnpm --dir clients/ts verify`: generated client stayed fresh; TypeScript and
  all 4 contract tests passed.
- Changed-path classifier fixture, ShellCheck 0.11.0, and actionlint 1.7.12
  passed.
- 14 independent supply-chain fixtures passed.
- Web TypeScript, 240 unit tests, and production build passed.
- Docs verification passed with 0 Astro diagnostics and 34 pages built.
- `go test -count=1 ./...` passed 3,971 tests across 56 packages against a
  disposable PostgreSQL 18 instance.
- Local `scripts/release/test-fixtures.sh` remains unverified because `cosign`
  is not installed; GitHub CI installs pinned cosign 3.1.3 before this gate.
