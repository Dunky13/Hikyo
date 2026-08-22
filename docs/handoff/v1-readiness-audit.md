# Hikyo 1.0 readiness audit — 2026-08-20

Assessment only; nothing was changed. Baseline: `main` @ `f91a09b2` with PR #192
(#75 key rotation + #187 reencrypt) merged locally as instructed. Evidence comes
from (a) the repo gate (#79, `docs/adr/mvp-boundary.md`), (b) all 45 handoff
docs + Claude/Codex session logs mined for conscious deferrals, (c) empirical
runs: source build, `server --dev`, the documented new-user CLI journey on a
fresh instance, `scripts/compose-demo.sh`, a distroless image built from
`Dockerfile.release` and run with a SQLite volume, `helm lint/template`, and a
Playwright walkthrough of the SPA at 1200px and 390px.

Screenshots: `docs/handoff/v1-readiness-audit-screens/` (untracked).

## Verdict table

| Axis (Marc's ask) | Verdict | One-line reason |
| --- | --- | --- |
| Feature-complete per the repo's own gate (#79) | **Yes, once #192 merges** | 37/38 blockers closed; #75 is the last and #192 closes it. The gate *act* (acceptance run, freeze tag, published artifacts) has not run. |
| CI green | **No** | `ci` on `main` is red for the last two pushes; #192's own checks fail (`lint`, `no-egress`, `supply-chain-checks`). See §1. |
| UI working as intended | **Mostly — signature surface is good; admin + reveal paths are blocked** | Matrix, row editor, history drawer, values page, mobile layout all hold up. But a browser session can never exceed password assurance, so every second-factor-gated admin surface (incl. org creation) is unreachable from the UI, and secret reveal is passkey-only by default. See §3. |
| Runs locally | **Yes** | `go build -tags ui` + `server --dev` boots; docs path works. Onboarding ceremony is long (§4). |
| Runs on Docker | **Image works; no user-facing path** | Distroless image boots with a SQLite volume once you pre-chown the volume to 65532 and pre-provision a root key. No docs, no `docker run` one-liner, no published image yet, no from-source Dockerfile. |
| Ready for k3s | **No** | Chart pins a placeholder digest, requires an external Postgres Secret, renders no Ingress, and never wires the root key — as shipped it cannot boot a server. Operator + CRDs are real and CI-tested. |
| Synchronises/manages secrets for a project | **Config yes; secrets no** | Workload principals are server-allowlisted to `{read}` only (`internal/domain/permission.go:255`). `hikyo run`, Compose `env_file`, and the k8s operator deliver config values; **no machine can receive a `secret` value in this build.** |
| Plug in `.env` files | **No** | No dotenv importer (sources: k8s, sops, infisical, vault). `values import` rejects a `.env`. The ADR's `scaffold` verb for dotenv onboarding is unimplemented. |
| Barrier to entry | **High** | ~25 commands and 5 hand-copied opaque IDs from clone to one value in two environments; mandatory TOTP before the first org; creator-admin grant requires a fresh login; opaque API errors; `--help` is broken. |

**Bottom line:** core model, crypto/authz plumbing, and the matrix UI are
1.0-quality. The last mile a first-time self-hoster walks — import a `.env`,
hand secrets to a workload, read one back, administer from the browser — is
where the launch bar fails today. This blocks *messaging*, not the gate act.

## 1. Gate state and CI (verified)

- `#79` blocked-by: 37 closed, `#75` open → closes with #192.
- `gh run list --branch main`: `ci` = **failure** on `f91a09b2` and `75cd868b`.
  Reproduced locally: `scripts/ci/check-trusted-ci-scripts_test.sh` fails with
  `missing ./scripts/ci/report-fuzz-finding.sh main` — #191 moved that call to
  `fuzz-report.yml:183`, the fixture still points at `ci.yml`. (The
  `internal/isolation` TOTP-route failure reported by the gate agent passes
  locally on the #192 merge; treat as flaky/fixed-by-#190 — re-check on CI.)
- `gh pr checks 192`: `validation / lint` fail, `no-egress` fail,
  `supply-chain-checks` fail → `ci-required` fail. "Will be merged soon" is not
  true against the branch ruleset as it stands.
- Open issues **missing from #79's enumeration but inside the 1.0 ADRs**:
  - `#183` secret-scanning Surface-2 block dialog in the SPA — `docs/adr/secret-scanning.md:129` locks SS3's `[UI]` criterion into the §1.2 gate.
  - `#185` / `#186` — ops-spec bounds registered `StatusPending ("enforcement-pending")` in `internal/conformance/boundregistry_test.go:108-124`; O2's criterion is "each named bound hit → named refusal fixture".
  - `#145–#164`, `#1`, `#41`: post-v1 per mvp-boundary §4 / trackers — fine.
- §6 done-verification: oasdiff gate (`api/freeze.go`, "NO FREEZE TAG EXISTS… freeze-armed later") and golden CLI snapshots (`internal/cli/golden_test.go`) exist and are CI-wired; **no discrete parity check could be located**; the self-hoster checklist (`docs/spec/self-hoster-checklist.md`) is a static table with no re-assertion script; docs-site/O4–O6 gates are wired in `release.yml:98-105` and `hikyo.app` + `security.txt` are live (HTTP 200).
- Release mechanics: on the first real tag, `release.yml` pushes the image to `ghcr.io/hikyo-org/hikyo` and the chart to `ghcr.io/hikyo-org/charts/hikyo` **unsigned and immediately**, while the GitHub release stays a draft until the offline signing ceremony. Image and chart are public before the signature exists.

## 2. Secrets and env management (verified empirically)

1. **Workloads cannot receive secrets.** `domain.machineAllowlists`:
   `ClassWorkload: {CapRead: true}`, `ClassAutomation: {read, edit, publish,
   definitions-edit}` — no `reveal` for any machine class. Granting `reveal` to
   a service-account principal returns 409 at project and environment scope.
   `hikyo run --context dev -- env` with a `read` grant:
   `cannot deliver secret(s) DATABASE_URL — … in this build that opt-in is not
   exposed, so a machine credential cannot receive these secrets yet`.
   `--config-only` works (`LOG_LEVEL=debug`). `internal/operator/reconciler.go:340`
   emits the same "undelivered (presence-only)" condition. The compose demo
   (`scripts/compose-demo.sh`, passes end-to-end) declares **config-only** keys.
   Docs (`compose.mdx:141-145`, `kubernetes-operator.mdx:171-183`) admit this.
   Handoffs trace it to #17/#58; no open issue tracks the opt-in.
2. **Human reveal works only after an undocumented raw-API dance.** CLI bearer
   is human-session class, so `POST /api/v1/auth/reauth/totp` is admitted — but
   (a) the instance default reveal window is 0 (`service.Auth.ReauthWindow` is
   never set anywhere; comment: "default 0 … a 0-window gate needs WebAuthn"),
   so TOTP is refused by design until you `PUT …/environments/{env}/settings
   {"protected":false,"reauth_window_seconds":300}`; (b) the CLI has **no
   verb** that calls `reauth/totp` (only `account factor step-up`, which
   elevates the session but opens no disclosure window); (c) a successful
   reauth **rotates the session token**, which the CLI's `sessions.json` does
   not learn about. After doing all three by hand, `values get --reveal
   --output-file` and `values copy` of a secret succeed. Out of the box, every
   documented reveal/copy-secret command in README and `values-workflows.mdx`
   returns `not permitted`.
   In the browser the Values page shows "Locked · a passkey per disclosure"
   and "Reveal every secret" disabled; with TOTP enrolled there is no way to
   reveal without a WebAuthn credential unless the per-environment window was
   raised first (UI knob exists in Project settings › Policy).
3. **No dotenv import.** `internal/importer/importer.go:292-297` registers
   exactly k8s/sops/infisical/vault. `hikyo values import --file app.env` →
   `malformed at values file: it is not a well-formed artifact of this kind`.
   `import-paths.md:6` assigns `.env` onboarding to a `scaffold → review →
   apply → values import` path whose `scaffold` verb is not in
   `internal/cli/verbs.go`. Closest path: one `key create` with a JSON
   declaration blob plus one temp-file `values set` per key, then `values
   publish --versions <ids>`; `values copy` names destination envs **by ID**
   (README shows names — `--from staging` returns "does not satisfy the API
   contract").
4. **Promotion dev→stage→prod** is one command (`values copy … --to <id,id>`)
   and writes a revision directly; `values diff` works; protected envs require
   `--confirm-protected`. Good, once the reveal window problem above is solved.
5. **Delivery targets shipped:** Compose `env_file` render/sync/doctor (proven
   by the demo), k8s operator (`HikyoInstance`/`HikyoSecret` CRDs, CI
   `k8s-e2e`), GitHub Actions + Forgejo adapters (one-way, value-blind). No
   generic webhook/file sync (post-v1 #157–#164).

## 3. UI (Playwright, desktop 1200px + mobile 390px)

Good:
- Matrix: calm, dense, state never colour-only (🔒/·/Δ/✎ glyphs), group rail,
  per-env history links, "Environments 3/3" toggle. Mobile collapses to a
  horizontally scrollable table with a Menu button; touch targets are ample.
- Row editor: write-only replacement per environment with honest microcopy,
  "Fill all", clear-to-absent, provenance (updated/by/revision).
- History drawer: per-env revision list, changed keys, restore/pin affordances,
  retention sentence, filter chip. Values page: masked cells, copy, publish-into,
  disclosure records. Account & security: passkey/TOTP enrolment with QR +
  secret, recovery codes, sessions, theme.
- Light/dark toggle present; copy is precise and on-brand.

Broken / blocking:
- **Browser sessions are capped at password assurance.** Login is
  username+password only; `web/src` calls no `totp/step-up` or
  `webauthn/login`. With TOTP enrolled, sign-in still yields `factors:
  password`. Instance administration then shows "Listing every organisation
  … needs a second factor … sign in again and present a passkey or
  authenticator code" — an instruction the login page cannot satisfy. Result:
  org creation, instance grants, credential policy, retention health are
  unreachable from the UI; #190's TOTP QR enrolment produces a factor the
  browser can never present for step-up.
- **First-run dead end.** Post-login shell: "No organisations yet. You will see
  one here once you are granted access to it." No CTA, no pointer to the CLI.
- **No project/environment/key creation in the UI** (org creation exists but
  is 2FA-gated as above). Matrix empty state says "Declare a key…" with nothing
  to click. All hierarchy authoring is CLI-only.
- Row editor → "History for DATABASE_URL" opens the history drawer **behind**
  the still-open modal (screenshot `06-history-desktop.png`).
- Matrix overflows horizontally at 1200px with only three environments
  (production header clipped).
- Minor: every page logs a console 401 on `/auth/whoami` before login and a
  403 on `/instance/retention-health` for non-2FA sessions.

## 4. Onboarding and developer experience (verified)

- Documented path to first value: IDs are still copied by hand for org,
  project, and two environments. Mandatory TOTP enrol + step-up precedes
  `org create`; creation now applies the creator's org `admin` template
  atomically and therefore revokes the current session, so the path is login →
  step-up → org create → login → step-up again, with no unreachable web-only
  grant step.
- **TOTP first-code rejection.** `StartTOTP` writes `last_step = created_step
  = now`; confirm/step-up require `last_step < step` (strictly greater), so the
  code the authenticator shows in the same 30-second step as enrolment/step-up
  is refused with a bare 401. Every run of my script and the official demo
  script needed the *next* code. A first-time user scanning a QR and typing
  immediately will be rejected with no explanation.
- `hikyo --help` → `unknown command "--help"`; the usage banner lists
  `client verbs not implemented yet: [render sync adopt definitions]`.
  `values` usage lists `export` (exists) and `import` (exists but not for
  dotenv). `hikyo run` has no `-h`.
- Service-account trap: `sa create` returns `id: sa_…` and `principal_id:
  mch_…`; grants need the `mch_` id. Docs say `--principal <service-account-id>`.
  Using `sa_` yields `the request does not satisfy the API contract` — the
  generic 400 with no field detail. 409s are equally opaque (`the current state
  of this resource refuses the request`).
- `--instance http://127.0.0.1:PORT` on `run`/`access` says "not in the local
  trust store" even after `login` established it (ref is stored as `host:port`).
- First `server --dev` boot logs a scary `PRE-MIGRATION EXPORT SKIPPED … there
  will be none` WARN; `curl http://127.0.0.1:8080/` returns 404 (SPA only on
  `Accept: text/html`; `/healthz` is the documented probe).
- Docker: `docker run -v vol:/data … --root-key-file /data/root.key` fails
  twice for a newcomer (volume owned by root → `permission denied` on
  `hikyo.db.lock`; then `no root key configured`, and the distroless image has
  no shell to generate one). `admin create` inside the container needs
  `HIKYO_ROOT_KEY` in env (no `--root-key-file` on that verb).
- Helm: `helm template` fails until `database.existingSecret` and
  `network.trustedProxyCIDRs` are set; nothing in the chart mounts or references
  a root key; `image.digest: sha256:RELEASE_IMAGE_DIGEST`.
- README "Implementation status": the "Not started yet" table lists #63–#66,
  #70, #74 (all closed); closing line names 11 blockers of which 10 are closed.
  README quick-start implies source build only (true today).

## 5. Deferrals mined from handoffs/sessions (status after verification)

| Item | Status |
| --- | --- |
| Machine `reveal` opt-in (#17/#58) | **VERIFIED blocking** — see §2.1; no open issue |
| Import wizard | Stale — #112 shipped `internal/cli/import_wizard.go` (TTY only) |
| Definitions-authoring UI + `definitions scaffold` | Unticketed; `scaffold` absent from verbs (affects dotenv path too) |
| OIDC/SAML/SCIM provider-config UI | Unticketed; CLI/API only |
| Backup retention pruning + RPO doctor check | Unticketed (#145 overlaps) |
| Compose snapshot AAD persistence; federation restore reactivation | Handoff-era, **unverified** here |
| Browser multi-org switching, pin-expiry badges, rev-to-rev diff, folder-rename drift | Low, unticketed |

## 6. Options for disposition (investigate ≠ decide)

Launch-blocking for the "try it on your project" message (recommendation: **do all of A before messaging**):

- **A1** Ship the per-project machine-reveal opt-in (or admit `reveal` for
  workload class behind the existing widening ceremony) so `run`/compose/operator
  can deliver secrets. Single biggest gap.
- **A2** Give the CLI a disclosure-reauth verb (`account factor reauth --env` →
  `/auth/reauth/totp`, store the rotated token) and set a sane non-zero
  instance default reveal window (or document the 0 default loudly and surface
  the Project-settings knob in docs).
- **A3** Browser second factor: TOTP step-up (and passkey login) on the login
  flow so admin surfaces are reachable; add a first-run CTA and project/env/key
  creation in the SPA, or at minimum an honest "use the CLI" empty state.
- **A4** Dotenv import (`hikyo import --from dotenv` or the ADR's `scaffold`) and
  `values export --format dotenv`/`hikyo run` for humans in dev.
- **A5** Fix TOTP first-code rejection (accept the start step, or message it).
- **A6** Fix CI on `main` (stale supply-chain fixture) and #192's failing checks
  before merging; add #183/#185/#186 to #79 or dispose them in the ADR.

Launch-important, not blocking:
- **B1** Docker quick path: published image + documented `docker run` (volume
  ownership, root-key provisioning, `admin create` via `docker exec`), or a
  from-source Dockerfile.
- **B2** Chart: root-key Secret wiring, optional Ingress, SQLite/PVC mode for
  homelab, real digest at release.
- **B3** Onboarding: names instead of IDs where the API allows, single
  `hikyo init` that does admin → TOTP → org → login → project → envs; explain
  the creator-admin session invalidation during first run.
- **B4** Error bodies with field detail on 400/409; fix `--help`; drop "not
  implemented yet" from the banner; document `mch_` vs `sa_`.
- **B5** README status tables; UI nits (modal stacking, matrix overflow).

Cosmetic / later: console noise, first-boot WARN wording, `/` 404 for curl.

## 7. Review gate note

No Codex cross-model pass was run: this is a readiness audit (no code diff),
and the standing rule targets Claude-authored code. If you want the audit
itself adversarially reviewed: (a) Codex high-effort pass over this file, or
(b) accept as-is and route findings to tickets.

## Cleanup performed

Dev servers on 48080/48082 stopped; `hikyo-smoke` container and
`hikyo-smoke-data` volume removed; local #192 merge reset back to `f91a09b2`.
