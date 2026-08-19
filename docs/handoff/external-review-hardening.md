# Handoff: external-review hardening (ADRs on main, race, fuzz, govulncheck, CodeQL)

PR: https://github.com/Hikyo-Org/Hikyo/pull/171

Origin: an external engineering review of the repository at `0f332ab`
(2026-08-19). Its verdict in one line: top-decile engineering artifact, not
yet something to put production secrets into. This branch addresses every
finding that is actionable inside the repository; the rest is listed under
"Left for the maintainer" with the reason.

## Findings and what this branch does about them

| Finding | Disposition |
| --- | --- |
| "The ADRs aren't in the repo" — 206 citations to ~19 ADRs the code names as canonical, none on `main`. | **Fixed.** The review's premise was slightly off — they were never private; they live on the public orphan branch `wayfinder-docs` of this same repository. Vendored `docs/adr/` (26 ADRs), `docs/spec/` (8), `docs/research/` (6), plus root `PRODUCT.md` and `DESIGN.md`, at that branch's tip `86f81b8`. Linked from README § Explore the project and CONTRIBUTING § Design decisions. `docs/adr/README.md` maps every short name used in code comments to its file. The frozen UI prototypes (`prototype/`, ~15 MB of PNGs) stay on the branch. |
| Citations "vary" (`audit` vs `audit-model`, `machine-identity` vs `machine-identities`, `isolation` vs `tenant-isolation`, …), suggesting they were written from memory. | **Fixed.** Every comment-level citation now uses the file stem: `permission-model`, `encryption-model`, `schema-model`, `revision-model`, `audit-model`, `machine-identities`, `system-architecture`, `tenant-isolation`, `scim-provisioning`, `import-paths`, `compose-integration`, `human-auth`. Only comments changed (Go, SQL, TS, sh, yml); sqlc output regenerated so the generated files carry the same text. `api/openapi.yaml` prose left untouched to avoid churning the generated clients. |
| No `-race` anywhere in CI. | **Fixed.** New `race` job (both engines): `go list ./... \| grep -v /internal/isolation$ \| xargs go test -race -count=1`. Local: all packages pass under the detector with PostgreSQL; no data race found. The isolation suite under `-race` exceeds the per-package timeout (it is the serial probe-based E2E suite), so it runs race-instrumented in the new weekly `race-isolation` workflow (`-timeout 150m`, `workflow_dispatch` for on-demand) — local race-instrumented run passed. |
| No fuzz targets despite hand-rolled binary parsers and an XML/SAML surface. | **Fixed.** 16 native Go fuzz targets: `internal/crypto` (`FuzzParseHeader` round-trip, `FuzzReadLP` bounds, `FuzzOpen` seal/open + single-byte-flip rejection, `FuzzReadRootKey`, `FuzzParseArtifact`), `internal/crypto/backup` (`FuzzExtractTo`), `internal/samlsp` (`FuzzParseXML`, `FuzzParseResponse`, `FuzzParseMetadata`), `internal/scimproto` (`FuzzParseFilter`, `FuzzParsePatch`, `FuzzDecodeUser`, `FuzzDecodeGroup`), `internal/importer` (`FuzzParseTemplate`, `FuzzParseManifest`, `FuzzParseValuesFile`). Each ran 30 s locally without a failing input; seeds run as normal tests inside `test`. New `fuzz` CI job discovers every `Fuzz*` target dynamically (one `go test -list '^Fuzz' ./...` over the tree) and runs each for 15 s, so a new target cannot be forgotten; a listing failure or zero discovered targets fails the job, so the pass cannot be vacuous. |
| No govulncheck / gosec / CodeQL. | **govulncheck: fixed, and it found something.** Binary-mode scans (seconds, scans what the linker kept; source mode over the ~1000-package graph takes minutes and gigabytes): the untagged `hikyo` binary in `test`, and the release-shaped `-tags ui` binary in the `web` job's desktop leg (the `ui` tag adds only `embed`/`io/fs`, but the shipped shape is what gets gated). On go1.26.2 it reported 16 reachable standard-library vulnerabilities (GO-2026-6218 … GO-2026-4918) — **toolchain pinned to go1.26.6** in `go.mod`, after which the scan is clean. **CodeQL: already running, now asserted.** The review looked for workflow YAML; CodeQL has run as GitHub's *default setup* (a repository setting: `actions`, `go`, `javascript-typescript`, weekly + every PR) since 2026-08-14 — this PR's own checks show `Analyze (go)` passing. Default setup and an advanced-setup workflow are mutually exclusive (the upload API rejects the latter while the former is on), so this branch ships no advanced-setup workflow; `scripts/release/configure-repository.sh` now PATCHes and asserts the default-setup state so the control is visible in the repo. Known limit of default setup: its Go autobuild compiles the untagged shape, so the 30-line `ui`-tagged `internal/webui/embedded.go` (embed + `fs.Sub`) is not extracted. **gosec: deliberately skipped** — govulncheck + CodeQL + the custom `internal/lint` analyzers cover the ask; gosec's signal on this tree is overwhelmingly G104/G304-style noise. |
| Dependency surface: sops/vault/openbao/k8s client-go drag in cloud KMS SDKs. | **Investigated, not changed** (product decision, see below). |
| Key rotation (#75) incomplete. | **Not in this branch.** It is a tracked 1.0 blocker with its own acceptance criteria (`model:fable-5`, `ready-for-agent`); folding a crash-safe root-rotation feature into a CI-hardening PR would violate the ticket discipline. Next ticket. |
| Security-commit log "reads more alarming than the risk was". | Informational; nothing to change. |
| Third-party audit of `internal/crypto` and `internal/authz`. | External; out of repository scope. |

## Dependency-surface numbers (for the maintainer's decision)

- Packages reachable only through `internal/importer`'s live connectors
  (sops decrypt → AWS/Azure/GCP/Huawei KMS SDKs, gRPC, envoy; vault/openbao;
  k8s client-go): **976 of the binary's packages**, ~23 MB of symbol size in a
  123 MB untagged binary (`go tool nm -size`).
- `go mod why -m cloud.google.com/go/kms` → `internal/importer` →
  `getsops/sops/v3/decrypt` → `sops/config` → `sops/gcpkms`.
- Options: (a) keep as is, rely on the new govulncheck gate for reachability
  — zero product change; (b) build-tag the live connectors (`importlive`) and
  ship a slim server image + a full CLI, which means two release flavours;
  (c) replace sops `decrypt` with an age-only path, dropping every KMS backend.
  The importer is CLI-side; the server never calls it.

## Verification on this branch

- `go build ./... && go vet ./...` on go1.26.6.
- `go test -count=1 ./...` with `HIKYO_TEST_POSTGRES_DSN` (both engines): green.
- `go test -race -count=1 <all but isolation>` with PostgreSQL on go1.26.6: green,
  no race reports. `go test -race -count=1 ./internal/isolation/`
  with PostgreSQL: green, 0 race reports, 37.5 min wall on an M-series laptop
  that was also running the non-isolation race pass (53 min on an earlier,
  heavier-contended run). A 4-vCPU GitHub-hosted runner is slower, hence
  `-timeout 150m` in the weekly workflow; size it from the first real run.
- Every fuzz target: 30 s campaign clean; dynamic discovery loop executed
  locally with `-fuzztime=2s` across all 16 targets.
- `govulncheck -mode=binary` on the built binary: 0 reachable (after the
  go1.26.6 pin; 16 before).
- `scripts/ci/check-required-jobs_test.sh`, `classify-changed-paths_test.sh`,
  `check-trusted-ci-scripts_test.sh`: pass. actionlint v1.7.12 and shellcheck:
  clean. `scripts/ci/verify-docs.sh`: pass (site builds with the vendored docs).

## CI mechanics to know

PRs run the **base** branch's `ci.yml` (`pull_request_target` →
`workflow_call`), so the new `race` and `fuzz` jobs, the govulncheck step and
the checker changes execute for the first time on the post-merge push to
`main`. Everything above was run locally, verbatim, for that reason. The
fixture tests from the PR head do run on the PR and pin the new job set.

## Left for the maintainer

1. Freeze or retire the `wayfinder-docs` branch for ADR/spec content —
   `docs/adr/` on `main` is now canonical and two copies will drift. Open
   issues link to the branch (e.g. #75 → `blob/wayfinder-docs/docs/adr/…`);
   those links keep working but point at the frozen copy.
2. Dependency-surface option (a)/(b)/(c) above.
3. #75 key rotation as its own ticket/worktree.
4. After the first `main` run: confirm `race` (~5-8 min on a 4 vCPU GitHub-hosted runner expected) and
   `fuzz` (~5 min) stay off the critical path; trigger `race-isolation` once
   via `workflow_dispatch` to size its timeout against the runner.
