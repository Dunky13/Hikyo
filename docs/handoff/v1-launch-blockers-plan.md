# v1 launch blockers — implementation plan (option A of the readiness audit)

Source: `docs/handoff/v1-readiness-audit.md` §6 option A. One PR, stacked on
`main` @ `59e31b6b` (#192 merged; CI green again on main).

| # | Item | Owner | ADR authority |
| --- | --- | --- | --- |
| A1 | Per-project machine-reveal opt-in: project setting, live conjunct at grant-add and at every fetch, cursor invalidation, audit events, CLI + UI toggle; server-produced all-or-nothing refusal replaces the client-side hardcoded message in `internal/cli/compose.go:61` and `internal/operator/reconciler.go:340` | main thread (authz) + delegate (CLI/UI) | source-of-truth §123; machine-identities §139–141, §205–214; compose-integration §227–235; permission-model §139, §201–202 |
| A2 | CLI disclosure reauth: inline terminal TOTP where the effective window > 0, browser handoff (existing cli-reauth ceremony) where it is 0/protected; persist the rotated session token; `HIKYO_REAUTH_WINDOW` instance default (prod default stays 0, `--dev` sets 900s) | main thread | api-cli-surface § Login and reauth transports; human-auth § Assurance |
| A3 | Browser: TOTP step-up after password login, passkey login, honest first-run/empty states, project + environment creation forms. Key-declaration UI deliberately excluded (it is #183's SS2 surface) | main thread (auth) + delegate (forms) | human-auth; app-chrome #29 |
| A4 | `definitions scaffold --from <.env>` (pure local, additive bundle, everything `config` + `# TODO: classify`), `values import` dotenv leg per ADR, `values export --format dotenv`, `run --use-human-session` per the locked exception | delegate | source-of-truth § Onboarding under a closed schema; import-paths § Grammar join; api-cli-surface §96 |
| A5 | TOTP: accept the enrolment/step-up code shown in the same time step (`last_step` initialised to `created_step - 1`), name "code already used for this step" on the per-step replay refusal | delegate | human-auth §141, §207 |
| A6 | Gate bookkeeping: add #183/#185/#186 to #79's blocked-by; README status tables | main thread | mvp-boundary §1.2, secret-scanning SS3, ops-spec bounds |

Rules for every task: read the owning ADR section verbatim first; divergence
reopens the ticket rather than bending the code; no `as` casts / `z.any`; all
JSON through Zod on the web side; new routes go openapi → codegen → handler →
AuthService → stub → `pinnedContractSurface` → wire registry + probe
classification; audit event types need a real emitter; migrations in both
engines, ASCII-only SQL; golden CLI snapshots updated with `-update`; DCO
sign-off on every commit; Codex adversarial review R1–R3 before merge.
