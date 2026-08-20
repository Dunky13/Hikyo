# #74 Secret scanning — implementation handoff

Status: FEATURE-COMPLETE for 1.0 minus one named residual (below; the SPA
Surface-2 block dialog). Spec:
`docs/adr/secret-scanning.md` (locked; every `ew_` there reads `hik_` post-rebrand, see
`docs/handoff/rebrand-hikyo.md`). Gate: SS1–SS4 (ADR §9). Dual-engine `go test ./...` green;
the SS-row criteria matrix (`internal/isolation/scanning_criteria_test.go`) maps every §9 clause
to its fixture and fails on a dropped/renamed one.

## What shipped, by stream

- **Stream A — `internal/scanning`**: compiled ruleset generated from the vendored gitleaks
  snapshot + committed allowlist (`go run ./internal/scanning/gen` → `rules_gen.go`, drift-checked
  in CI); fail-closed import contract; `hik_` two-stage rule (RE2 + `crypto.ParseArtifact` CRC);
  TP/FP fixture corpus; `bench-scan` harness + `BenchmarkScan`; committed Pi-class artifact,
  CI-validated by `TestPiBenchArtifact`.
- **Stream B — crypto/audit/store**: tier-3 scanning-fingerprint key (HMAC inside the envelope
  package, `KindWrappedDEK` instance-scoped); `scanning_dismissals` migration + proof-bound repos;
  `scanning.finding_warned|dismissed|blocked|overridden` audit registry rows; `rotate-scanning-key`
  (outright replacement, drops all dismissals).
- **Stream C — service/server/cli/contract**: Surface-1 warn at stage/declare/copy/clone/import/
  declassify with sticky dismissals; Surface-2 block at every declaration ingress with content-bound
  ack tokens; the redacted `ScanFinding` DTO + `acknowledgements` fields wired into OpenAPI, the
  regenerated TS client, and the CLI.
- **Stream D — SPA/e2e/CI/criteria (this stream)**: the Surface-1 **warn dialog** on the matrix
  editing surface (`web/src/routes/ScanWarnDialog.tsx`, wired in `Matrix.tsx`) — names rule id + key,
  never matched text; "Reclassify as secret" (primary) and sticky "Keep as config"; no blanket
  ignore-all. Playwright flow `web/e2e/flows/scanning.spec.ts` (SS2/SS4 [UI]), registered in
  `e2e/registry.ts`. CI: the `generated` job drift-checks `rules_gen.go`; the `test` job runs the
  `BenchmarkScan` relative regression guard (the corpus and Pi-artifact validation already run under
  the ordinary `go test ./...`, so no extra step). The SS-row criteria matrix.

## Wire shape (from `api/openapi.yaml`)

- `ScanFinding` = `{ rule_id, surface, locator, acknowledgement? }`. `surface` ∈
  `value_write | declassification | import_value | edit`. `locator` is the key identity (Surface 1)
  or a schema-location class like `key.declaration.pattern` (Surface 2). **Never** matched text,
  offset, length, or excerpt. `acknowledgement` is an opaque, short-lived, content-bound token,
  present only where an acknowledgement is possible.
- **Surface-1 warn** rides the *success* response: `findings: ScanFinding[]` on `PendingChange`
  (value stage), on `Key` (declassification reclassify response), and on the copy/clone/import/declare
  value-write results. The save succeeded regardless; a clean save omits `findings`.
- **Surface-2 block** rides the *error* body: `error.findings: ScanFinding[]` on a `bad_request` a
  declaration ingress refused.
- **Acknowledgement** = `acknowledgements: string[]` on the write request. On a value write, a
  keep-as-config token re-submitted with the identical value records the sticky dismissal
  (`SetValueRequest.acknowledgements`). On a declaration write, one override token per finding is
  re-scanned against current content; stale/version-skewed/surplus tokens are rejected by name.
  There is no blanket ignore-all input on any surface.

## Vendoring pin (phase 0, done)

- Upstream: `github.com/gitleaks/gitleaks`, tag **v8.19.0**, commit
  `44ad62e0b103f7907c4b3dd494aca64e4fefd94f`
- Source path: `config/gitleaks.toml` (177 rules) → vendored at
  `internal/scanning/rules/vendor/gitleaks.toml`
  (sha256 `f0530f72a3962c6b824d7c03714a896b3e5e609d6a2f3bf11be97b6d715e1372`)
- License: MIT, retained at `internal/scanning/rules/vendor/LICENSE`
  (sha256 `e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6`)
- Why this pin: at gitleaks HEAD the mandatory-family rules carry `entropy` (and some
  per-rule `allowlists`) — the ADR §3 fail-closed import contract rejects them, making the
  minimum coverage manifest unfillable. v8.19.0 is the latest tag where every mandatory
  family has contract-clean rules (`id`/`description`/`regex`/`keywords` only).
- Family → rule IDs at this pin: AWS `aws-access-token` (AKIA/ASIA); GitHub `github-pat`,
  `github-oauth` (gho\_), `github-app-token` (ghu\_/ghs\_), `github-fine-grained-pat`
  (github*pat*); GitLab `gitlab-pat` (glpat-); Slack `slack-bot-token`, `slack-user-token`
  (+ 5 more xox rules available); Stripe `stripe-access-token` (sk|rk*(test|live|prod));
  PEM `private-key`; plus the Wenv-owned `hik_` rule (two-stage, ADR §3).

## Import-contract interpretation (recorded decision)

The generator consumes exactly `id`, `regex`, `keywords`. `description` and `tags` are
non-semantic annotations present on every upstream rule and are ignored (a literal reading
that rejects any rule carrying a description rejects the entire upstream corpus at every
commit that ever existed). Any **verdict-affecting** field beyond the contract — `entropy`,
`allowlists`/`allowlist`, `path`, `secretGroup`, or anything unrecognized — rejects the rule
at generation, fail-closed, named in the generator error. The global `[allowlist]` block in
the snapshot is not consumed.

## Seam contract (binding on all streams)

Package `internal/scanning`:

- Generated, committed compiled ruleset (drift-checked like the sqlc/oapi `generated` CI
  job). Generator is a Go tool in this repo reading the vendored TOML + committed allowlist.
- `Load() (*Ruleset, error)` — validates the embedded compiled ruleset at boot; any error
  refuses server start (wire into server startup, fail fast).
- `(*Ruleset) Scan(ctx, content []byte) ([]Finding, error)` — `Finding{RuleID string}`
  ONLY. No match text, offsets, lengths, excerpts — banned from the type so it cannot leak
  (ADR §4). Locators are attached by the caller (service layer), never by the scanner.
- `(*Ruleset) SnapshotVersion() string` — pin + allowlist digest; recorded in ack tokens.
- Per-rule **semantic digest** (SHA-256 over canonical `id`‖`regex`‖sorted `keywords`)
  computed at **generation time**, emitted as string constants — the scanning package
  imports no hash/HMAC primitive at runtime (SS4 architecture-test extension).
- `hik_` rule: RE2 candidate extraction, then `crypto.ParseArtifact`
  (`internal/crypto/bearer.go:151`) for grammar+CRC — never a reimplemented checksum.
- Keywords are a prefilter only. ≤ 64 compiled rules asserted at generation. Scan honours
  ctx deadline (shares the enclosing operation's clock, ADR §7).

Crypto (`internal/crypto`):

- One exported fingerprint function (HMAC-SHA-256 inside the envelope package) over
  domain-separation label ‖ (org, project, env, key) scope binding ‖ canonical stored value
  bytes (post-trim — exactly what the value write persists). Signature style follows the
  package. No new envelope kind for the key: instance-scoped tier-3 under `KindWrappedDEK`
  via the reserved `tier3AAD` row (`aad.go:66`, `keyring.go:273`); `aad_test.go`'s 6-kind
  assertion stands.
- `rotate-scanning-key`: outright replacement, no keyring versioning, drops ALL dismissal
  rows in the same transaction. Modelled on `RotateTokenKey`
  (`internal/service/revisions.go:571`, authz `OpRotateTokenKey`, CLI
  `internal/cli/revisions.go:183`).

Store:

- Migration `00027_scanning_dismissals.sql` (both engines): dismissal rows keyed by
  (org, project, environment, key identity, rule semantic digest, value fingerprint),
  ADR §4 lifecycle (reclassify→drop key's rows; key delete→drop; rotation→drop all;
  project delete→drop; backup/restore carries rows). Repos via proof-bound
  `internal/store/repos*.go`; services never import sqlitegen/pggen.

Audit (`internal/audit/registry.go`): `scanning.finding_warned|finding_dismissed|
finding_blocked|finding_overridden`, exactly the §5 table (scope class, chain, object,
payload v1, `success` only, `security` retention). Events commit in the same `tx.Write`
closure as the write; block events commit alone before the refusal returns.

## Chokepoint set (recorded decision — differs from the validation set)

Surface 1 (warn, non-blocking): `stage` (Set/Unset, `internal/service/values.go:435`),
`declare` (`:552`), copy/clone (`:984`/`:1506`), `Import` (`:1900`/`import.go:411`), and
`Reclassify` secret→config (`keys.go:1042` — the declassification ceremony). **Publish does
NOT scan** (ADR §6.1 no-retro-scan: values are scanned at entry, not re-scanned at
publish). "SAVING IS FREE" is preserved — warn never blocks a save.

Surface 2 (block): every existing declaration ingress — key Create/Rename/UpdateMetadata/
UpdateDeclaration/SetGroup (`internal/service/keys.go`), key-group naming, folder and
environment naming (`internal/service/hierarchy.go`), and the definitions Git-flow chokepoints
`definitions plan` (before the immutable plan persists) and `definitions apply` (re-scan on ruleset
snapshot skew) (`internal/service/definitions_apply*.go`) — refused **before any pending/plan state
persists**, per-finding locator + rule ID + short-lived content-bound ack token;
resubmission re-scans and rejects stale/surplus tokens by name (ADR §4).

## Scope residuals (one, named — not silently skipped)

This is the only §9 leg not closed; the criteria matrix marks it `Blocked`, pinned at 1.

1. **Surface-2 block dialog in the SPA (SS3.ui)** — the SPA has no declaration-editing surface
   (verified; `docs/handoff/60-chrome-surfaces.md:201`). Block presentation ships CLI/API; the
   dialog lands with the declaration-editing surface. Only the Surface-1 **warn** dialog ships here.

### Closed by Stream E (#74 SS3 plan/apply, on #70's Git flow)

- **`definitions plan` ingress (SS3.plan)** — `Definitions.Plan` scans every author-controlled
  bundle leaf (`bundleLeaves`, the same locator classes as direct edits) **before `persistPlan`
  writes the immutable plan**. A finding refuses the plan (`scanning.finding_blocked`, ingress
  `plan`) with nothing else persisted; acknowledged resubmission (tokens on the plan request)
  commits the plan and emits `finding_overridden`. The plan records the ruleset `SnapshotVersion`
  it was scanned under in the new `definitions_plans.scan_snapshot` column (migration `00029`, both
  engines). Fixture: `runScanningDefinitionsPlanBlock` (dual-engine, via `TestDefinitions*`).
- **`definitions apply` re-scan (SS3.apply)** — `Definitions.Apply` re-scans **iff** the running
  `Scan.SnapshotVersion()` differs from the plan's recorded one; a same-version apply adds no
  second scan (proven token-free). The re-scan runs in a read pre-flight **before**
  `prepareSchemaPublish` so a refusal mints no project DEK (the F2a orphan-key rule). Skew refusal
  is ingress `apply`; acknowledged apply commits with `finding_overridden`. Fixture:
  `runScanningDefinitionsApplySkew`.
- **`definitions check` (read-only)** — surfaces the same leaf findings on `CheckResult` (wire
  surface `check`), non-persisting, no token, no event; the CLI prints them to stderr and the drift
  exit contract is untouched. A dry-run warning that a `plan` would be refused.

Wire decisions: findings ride the existing refusal shape (`scanRefusalErr` → `error.findings`);
`--acknowledge` works on `hikyo definitions plan` and `apply`. Plan carries tokens as the
`acknowledge` **query parameter** (the plan request body is the canonical bundle bytes, so tokens
cannot ride the body; same exposure surface as the CLI flag that holds them). Apply carries them in
the request body (`acknowledgements`). `ScanFinding.surface` gained `plan|apply|check`; the audit
ingress enum already reserved `plan|apply`.

Nothing else is deferred. The Pi-class `bench-scan` artifact (SS1) is committed and CI-validated
(`TestPiBenchArtifact`): produced on **pi4-8gb `sapporo`** after the keyword-anchored suffix-window
fix (commit `b071d4a`), it parses, matches the pinned harness + ruleset snapshot versions, and
reports p99 ≤ 5 ms per item at the size cap with boot compile ≤ 2 s / ≤ 32 MiB.

## What #70 (definitions plan/apply) had to wire — DONE (Stream E)

Delivered on #70's Git flow; see "Closed by Stream E" above for the shipped shape. The service seam
(`internal/service/scan.go`) was verb-agnostic as designed — `scanDeclaration` gained an `ingress`
parameter and a `bundleLeaves` walk, and the plan/apply call sites and the two SS3 [E2E] fixtures
(`runScanningDefinitionsPlanBlock`, `runScanningDefinitionsApplySkew`) landed; the criteria pin
moved from 3 to 1.

## File ownership (parallel streams)

- Stream A: `internal/scanning/**`, generator cmd, its testdata, `bench-scan`. Only A
  touches `go.mod`/`go.sum` (TOML parser dep).
- Stream B: `internal/crypto/**`, `internal/audit/**`, migrations `00027`+ both engines,
  `internal/store/queries/**` + repos, rotate-scanning-key service/authz/CLI,
  `internal/boundary/boundary_test.go`.
- Stream C: `internal/service/**`, `internal/server/**`, `internal/cli/**`, `api/openapi.yaml`,
  regenerated `clients/ts/src/generated`.
- Stream D: `web/**` (`ScanWarnDialog.tsx`, `Matrix.tsx`, `api/matrix.ts`, `styles/app.css`,
  `e2e/flows/scanning.spec.ts`, `e2e/registry.ts`), `internal/isolation/scanning_criteria_test.go`,
  `.github/workflows/ci.yml` (`generated` + `test` jobs), this handoff.
- `.github/workflows/ci.yml`: single writer, integration phase only; new jobs join
  `ci-required`.

## E2E ports (this session)

`HIKYO_E2E_PORT=45860`, `HIKYO_E2E_PORT_B=45861`, `HIKYO_E2E_PORT_TLS=45862`.
