# #74 Secret scanning — implementation handoff

Status: IN PROGRESS (phase 0 committed). Spec: `docs/adr/secret-scanning.md` (locked; every
`ew_` there reads `hik_` post-rebrand, see `docs/handoff/rebrand-hikyo.md`). Gate: SS1–SS4 (ADR §9).

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
UpdateDeclaration/SetGroup (`internal/service/keys.go`), key-group naming, folder/env/
project/org naming (`internal/service/hierarchy.go`) — refused **before any pending state
persists**, per-finding locator + rule ID + short-lived content-bound ack token;
resubmission re-scans and rejects stale/surplus tokens by name (ADR §4).

## Scope residuals (NOT green in this PR — named, not silently skipped)

1. **`definitions plan|apply` ingresses (SS3 legs)** — verbs don't exist yet (#70,
   `internal/importer/artifacts.go:209`). The scanner + ack machinery here is verb-agnostic;
   #70 must call it before plan persistence and on snapshot-version skew at apply. SS3's
   plan/apply fixture legs land with #70.
2. **Surface-2 block dialog in the SPA** — the SPA has no declaration-editing surface
   (verified; `docs/handoff/60-chrome-surfaces.md:201`). Block presentation ships CLI/API;
   the dialog lands with the declaration-editing surface.
3. **Pi-class `bench-scan` artifact (SS1)** — produced on real Pi-class hardware, committed,
   CI-validated. Runs as a late phase on the homelab Pi; if unreachable this session it is a
   named blocking leftover, never fabricated.

## File ownership (parallel streams)

- Stream A: `internal/scanning/**`, generator cmd, its testdata, `bench-scan`. Only A
  touches `go.mod`/`go.sum` (TOML parser dep).
- Stream B: `internal/crypto/**`, `internal/audit/**`, migrations `00027`+ both engines,
  `internal/store/queries/**` + repos, rotate-scanning-key service/authz/CLI,
  `internal/boundary/boundary_test.go`.
- `.github/workflows/ci.yml`: single writer, integration phase only; new jobs join
  `ci-required`.

## E2E ports (this session)

`HIKYO_E2E_PORT=45860`, `HIKYO_E2E_PORT_B=45861`, `HIKYO_E2E_PORT_TLS=45862`.
