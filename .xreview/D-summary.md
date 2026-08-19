# Stream D summary — Compose demo, CI, docs, and reference units (#63)

Implemented on branch `t3code/implement-issue-63-D` without modifying Go code
under `internal/` or `api/`.

## Delivered

- `install/compose/demo/`: Alpine 3.21 stack using an absolute generated
  `env_file.path`, `format: raw`, a required generation variable in both path
  and stamp label, a committed non-secret Hikyo project template, README, and
  `.env` ignore.
- `scripts/compose-demo.sh`: clean temp HOME/state/runtime, real `--dev` server,
  bootstrap establishment, API TOTP enrollment, CLI login/context/step-up,
  public CLI hierarchy/key/value/SA/grant/mint flow, full representable JSON
  corpus plus `GREETING`, embedded-newline refusal assertions, base64 container
  byte checks, doctor allowlist, publish/sync/stamp/restart assertions, and
  cleanup/restoration traps.
- `.github/workflows/ci.yml`: selective `compose-demo` job, loud Docker Compose
  2.30.0 floor, pinned existing actions, terminal automation install, and the
  job added to `ci-required`. Shellcheck now includes the demo script.
- CI control plane: `compose_demo` plan entry, required-results validation, and
  fixtures for `install/compose/**`, `scripts/compose-demo.sh`, `internal/cli/**`,
  `internal/compose/**`, `internal/service/delivery.go`, `api/**`, and `go.mod`.
- Documentation: new `/docs/compose/` page and sidebar entry, updated CLI
  reference, reference systemd one-shot service/timer at a 5-minute cadence,
  and the Stream D handoff section.

## Live blocker

The script gets through a real server bootstrap, TOTP enrollment, CLI login,
context creation, TOTP step-up, and `org create`. It then installs explicit
`edit`, `publish`, `definitions-edit`, `manage-identities`, `manage-members`,
and `read` grants at the created org, logs in again, and performs a fresh TOTP
step-up. The public command:

```text
hikyo project create --context demo --org <org_id> --name stack
```

still exits `5` with exact stderr:

```text
hikyo: not found
```

Per the brief, no datastore insertion or Go-code workaround was added. The
script now fails loud with the command, exit, and stderr. Because project
creation is the prerequisite for keys, environment, delivery, and the project
config, the render/container/refusal/doctor/sync assertions are present but
could not execute locally.

## Validation

Passed:

- `bash -n scripts/compose-demo.sh`
- `shellcheck scripts/compose-demo.sh`
- `./scripts/ci/check-required-jobs_test.sh`
- `./scripts/ci/classify-changed-paths_test.sh`
- `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`
- Docker Compose 5.4.0 accepted the demo config with an absolute interpolated
  `env_file.path`; no unintended `$k` interpolation remained.
- `cd docs/site && pnpm install --frozen-lockfile && pnpm build` built 33 pages,
  including `/docs/compose/`, and precached 92 PWA files.
- `git diff --check`

Blocked as described above:

- `GOCACHE=/tmp/hikyo-go-build-cache ./scripts/compose-demo.sh`

No model or model CLI subprocess was invoked.
