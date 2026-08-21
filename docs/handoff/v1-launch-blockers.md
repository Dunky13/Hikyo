# v1 launch blockers — handoff (option A of the readiness audit)

Branch `t3code/v1-release-readiness`, stacked on `main` @ `59e31b6b` (#192
merged). Plan: `docs/handoff/v1-launch-blockers-plan.md`; audit that
motivated it: `docs/handoff/v1-readiness-audit.md`.

## What landed

| # | Commit | Summary |
| --- | --- | --- |
| A5 | `fix(auth): accept the enrolment-step TOTP code…` | `last_step` starts at `created_step - 1`; replay within a step answers 409 + safe detail ("already used for its time step; wait for the next code"). e2e fixture waits that answer out. |
| A4 | `feat(cli): dotenv onboarding…` | `definitions scaffold --from <.env>` (offline, additive bundle, every key `config` + `TODO: classify`), `values import --from-dotenv`, `values export --format dotenv`, `internal/dotenv`. `values export` moved from `-o` to `--format` per api-cli-surface line 146. |
| A1 | `feat(access): per-project machine-reveal opt-in` | `projects.machine_reveal` (migration 00030, both engines). Read live by the grant writer (`ErrMachineRevealOptIn`), the chokepoint (`authorize.go machineRevealWithdrawn`) and delivery (`withoutReveal`, so the cursor's projection moves). `GET/PUT …/projects/{project}/machine-reveal`, formula `project-settings@project ∧ reveal@project` (MFA-mandatory), audit `settings.machine_reveal_changed` both ways. CLI `project-settings machine-reveal get\|set --enabled`, web toggle with acknowledgement on Machine access, journey steps 4–5 live. Compose/operator refusals name the act. |
| A2 | `feat(cli): inline TOTP disclosure ceremony…` + `feat(auth): disclosure-purpose CLI browser handoff` | `internal/cli/reveal_window.go`: on 403 "not permitted" or the widening 409, read the reveal window; if TOTP is offered prompt at the terminal, `POST /auth/reauth/totp`, persist the rotated token, retry once. 0-window/protected → browser handoff (`cli-reauth` with purpose `reveal`/`copy` and the key set) to the UI's passkey ceremony; a mirrored window is redeemed. `run --use-human-session` (four locked conditions). `HIKYO_REAUTH_WINDOW_SECONDS`: 0 in production, 900 under `--dev`. |
| A3 | `feat(web): browser second factor…` | `StepUpBanner` (TOTP + passkey) in the shell while the session is password-only and the account holds a factor; passkey sign-in on the login page; first-run empty states name the path; New project / New environment forms; matrix empty state points at the CLI for key declaration. |
| A6 | `docs: refresh README…` | README status tables; #79 blocked-by now lists #183/#185/#186; configuration/compose/k8s/machine-identities/values-workflows docs. |

## Verified

- `go build ./... && go vet ./... && gofmt -l . && go test ./...` green (41 packages, sqlite engine; Postgres variants skipped locally — CI runs them).
- `pnpm --dir web typecheck` and `pnpm --dir web test` green (17 files, 224 tests).
- End-to-end on a fresh `--dev` instance (`/tmp/hikyo-journey2.sh`, not committed): enrolment-step TOTP accepted; scaffold → plan → apply → `values import --from-dotenv` → `values export --format dotenv`; `values get --reveal` prompts once, opens a 900 s window, second reveal needs no prompt; `project-settings machine-reveal set --enabled true` → `access grant add … reveal --env` runs the widening ceremony inline → `hikyo run` delivers the secret; `--enabled false` → next `run` refuses naming the act.
- Browser: password login → step-up banner → code accepted → instance administration reachable → organisation created from the UI (screenshot `v1-readiness-audit-screens/09-stepup-banner.png`).

## Decisions surfaced for the owner

1. **Instance default reveal window stays 0 in production.** `--dev` gets 900 s so an evaluation instance can reveal with an authenticator alone. Raise per environment in project settings or via `HIKYO_REAUTH_WINDOW_SECONDS`. Overridable.
2. ~~CLI 0-window ceremony is the browser's (not wired).~~ **Resolved after R3:** the `cli-reauth` handoff now carries disclosure purposes (`reveal`, `copy`) with the enumerated key set (migration 00032); the browser approve page runs the same purpose-bound passkey (or TOTP) ceremony the Values page runs and the CLI redeems a mirrored window. `values get/list/diff/export/copy` and `run --use-human-session` use it at 0-window/protected environments.
3. **Key declaration UI deliberately not added** — it is the SPA declaration surface #183 waits on.
4. `values export` `-o` → `--format` is a (pre-1.0) CLI-surface change.

## Not done / follow-ups

- Workload `reveal-history` under a pin (permission-model ADR: "`reveal-history` only where a pin requires it") is not grantable — the pre-existing machine allowlist refuses it outright; this PR only adds the opt-in conjunct at the chokepoint for both disclosure atoms. Follow-up ticket needed.

- Codex cross-model review (gpt-5.6-sol, high): R1 NOT CLEAN (1 BLOCKING / 5 HIGH) → fixed in `fix: address cross-model review R1…` → R2 one item open → R3 **SOUND-WITH-DISPOSITIONS** (#3, the CLI zero-window browser handoff). The owner chose to implement #3; the handoff slice had its own R1 (1 BLOCKING / 3 HIGH / 1 MEDIUM → fixed: dispatch by enrolment, honest TOTP scope, act-bound units, passkey-binding e2e) → R2 SOUND-WITH-DISPOSITIONS (residuals fixed) → R3 **SOUND-WITH-DISPOSITIONS** (no slice-blocking items). PR #194.
- Remaining owner disposition: OIDC re-run reauthentication is not implemented for any disclosure ceremony (browser or handoff) — a pre-existing gap of the reveal ceremony (`Ceremony.tsx` offers passkey/TOTP only); follow-up ticket.
- Playwright desktop suite green locally after repinning copy/selectors; the mobile project and the k8s operator e2e (the only live exercise of operator secret delivery under the opt-in) run in CI on #194.
- Docker quick path, chart root-key/Ingress, `hikyo init`, field-level error detail: audit option B, not in this PR.
