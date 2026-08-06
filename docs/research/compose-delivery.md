# Docker Compose secret delivery patterns for Wenv

Date: 2026-07-29. Scope: how Wenv values reach workloads on the v1 persona's box — a self-hosting developer running Docker Compose on a single server. Compared: run-wrapper, rendered dotenv file, local agent daemon, Compose-native secrets, deploy-time CI injection; plus systemd credentials as a hardening path.

Cross-cutting criteria applied to each: plaintext-on-disk window + cleanup, single-host token provisioning UX, offline behaviour when Wenv is down at `docker compose up`, restart interaction (changes-apply-on-restart), and shell-history / process-environment leakage.

## 1. Exec wrapper: `wenv run -- docker compose up`

Prior art: [`infisical run`](https://infisical.com/docs/cli/commands/run) and [`doppler run`](https://docs.doppler.com/docs/cli). Fetch secrets over the API, inject into the child's environment, `exec` the command.

**Flag surface (prior art):**
- Infisical: `--env` (environment slug), `--path` (folder, multiple with first-path precedence), `--tags`, `--projectId`, `--token` / `INFISICAL_TOKEN`, `--expand` (shell-parameter expansion inside secret values, default on), `--secret-overriding` (personal over shared), `--command` for shell-chained commands vs bare `-- cmd`, `--watch` (restart child on secret change).
- Doppler: `-p/-c` project/config, `--command`, plus the fallback family: `--fallback=<path>`, `--fallback-only`, `--fallback-readonly`, `--passphrase` ([automatic fallbacks](https://docs.doppler.com/docs/automatic-fallbacks)).

**Env merging:** both merge fetched secrets over the inherited environment and pass the union to the child. Compose then sees them as "host OS environment", which is the interpolation source of highest precedence over `.env` ([Compose precedence](https://docs.docker.com/compose/how-tos/environment-variables/envvars-precedence/)). Critical Compose detail: host env vars do **not** land in containers by themselves — they only feed *interpolation* (`${VAR}` in the compose file) or `environment: VAR` pass-through entries. So `wenv run -- docker compose up` requires the compose file to reference each variable; a secret merely present in the wrapper's env is invisible to containers. This is the main UX trap to document.

**Failure behaviour:** Doppler writes an encrypted fallback snapshot (AES-256-GCM, PBKDF2, passphrase derived from token+project+config by default) on every successful run and can serve from it when the API is unreachable ([docs](https://docs.doppler.com/docs/automatic-fallbacks)). Infisical's offline story is patchy — cache-fallback has been a repeated feature request and bug ([infisical#1609](https://github.com/Infisical/infisical/issues/1609), [infisical#1639](https://github.com/Infisical/infisical/issues/1639), [cli#216](https://github.com/Infisical/cli/issues/216)); their newer answer is a separate caching daemon ([Infisical Proxy](https://infisical.com/docs/integrations/platforms/infisical-proxy)).

**Per-criterion:**
- *Plaintext on disk:* none in the happy path — secrets live only in process memory. Doppler-style encrypted fallback file is ciphertext, acceptable. Best-in-class here.
- *Token UX:* one static service-account token, delivered as `WENV_TOKEN` env var or a `~/.config/wenv` token file (0600). Scope it read-only to one project/environment. Rotation = issue new token, replace file, restart. Doppler's ephemeral-token trick (`--max-age 1m` tokens minted at deploy time) is a nice later addition, not v1.
- *Offline:* naked wrapper fails closed — server down means `docker compose up` (and any reboot-time restart) fails. Fail-fast is the house principle, but a *reboot while Wenv (possibly itself a container on the same box) is down* is the single-host chicken-and-egg case. Doppler's encrypted local snapshot is the proven middle ground: fail closed by default, `--fallback` opt-in with loud "serving stale from <timestamp>" stderr warning.
- *Restart interaction:* natural — secrets are re-fetched on every `wenv run`, and compose applies env changes on `up`/recreate. A systemd unit `ExecStart=wenv run -- docker compose up` gets fresh secrets on every restart. `--watch` (Infisical-style auto-restart) is post-v1.
- *Leakage:* child env is visible in `/proc/<pid>/environ`, but reads are gated by a ptrace `PTRACE_MODE_READ_FSCREDS` check — same-UID or root only, and it's a snapshot at `execve` time ([proc(5)](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)). `ps e` is subject to the same check. Real leak paths are softer: the env propagates to every child of compose, crash reporters, and `docker inspect` (env vars set via `environment:` are stored in container config, readable by anyone in the `docker` group). Shell history is clean as long as values never appear as CLI args — `wenv run` takes none.

## 2. Rendered dotenv file: `wenv export --format dotenv`

Prior art: [`infisical export`](https://infisical.com/docs/cli/commands/export) (formats: dotenv, dotenv-export, dotenv-eval, json, yaml, csv, Go templates; stdout by default, `--output-file` optional) and `doppler secrets download`.

**Compose interaction — two distinct consumers:**
1. `--env-file` / project `.env`: feeds *interpolation* of `${VAR}` in the compose file; host env still wins over `.env` for interpolation ([precedence](https://docs.docker.com/compose/how-tos/environment-variables/envvars-precedence/)).
2. `env_file:` attribute on a service: injects the file's contents directly into the container env. Paths resolve relative to the compose file; `required: false` exists; unquoted/double-quoted values are themselves interpolated unless `format: raw` is set ([services reference](https://docs.docker.com/reference/compose-file/services/)). The `env_file:` route is the one that removes per-variable plumbing — the whole rendered file lands in the container.

**Per-criterion:**
- *Plaintext on disk:* the defining weakness. The file exists in plaintext for at least the `up` invocation; in practice users leave it forever. Mitigations: write with 0600 (explicit `chmod`/`O_CREAT` mode, not umask-dependent), render to tmpfs (`/dev/shm` or a `systemd` `RuntimeDirectory=`) so it never touches persistent disk and dies on reboot, `trap ... EXIT` cleanup in a wrapper script. But compose `env_file:` paths are relative to the compose file, which nudges users toward rendering *next to the project*, on real disk, in the git worktree (`.gitignore` roulette). Backup tools, `docker cp`, and editors' file pickers all see it.
- *Token UX:* identical to pattern 1 (same CLI, same token).
- *Offline:* accidentally "good" — the stale file from the last render keeps working when Wenv is down. That's a silent-stale failure mode, the exact opposite of fail-fast: nothing tells the user the file is three weeks old. If Wenv ships export at all, it should refuse to *silently* reuse; staleness detection would need a sidecar timestamp/manifest, which is machinery pattern 1 doesn't need.
- *Restart interaction:* changes require re-render + `docker compose up -d` — a two-step the user will forget half of. Wrapper script or systemd `ExecStartPre=wenv export ...` fixes it, at which point you've rebuilt pattern 1 with a file in the middle.
- *Leakage:* no process-env exposure beyond what compose itself does, no shell history (values in file, not argv). But the file is the leak: readable by anything running as that user, included in tarball backups, easy to `cat` into a support ticket.

**Verdict:** ship `export` (it's ~free given the API client and is the escape hatch for tooling Wenv doesn't wrap), but document it as the manual/debug path, not the recommended deploy path.

## 3. Local agent daemon (Vault Agent prior art)

[Vault Agent](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent): long-running daemon doing auto-auth (token acquisition + renewal into sink files), consul-template rendering of secrets to files with re-render on change, process-supervisor mode (restart child on secret change), and client-side caching of tokens/leases. Infisical's equivalent is the [Infisical Proxy](https://infisical.com/docs/integrations/platforms/infisical-proxy) caching daemon.

**Cost for a homelab user:** a second always-on process with its own config file, unit file, token sink, template language, and failure modes — to talk to a server that is often *on the same box*. Vault Agent earns its keep with dynamic short-TTL secrets and lease renewal; Wenv v1 has static secrets and changes-apply-on-restart, so renewal/caching/templating machinery has nothing to do. The one thing an agent genuinely buys — serving cached secrets while the server is down — Doppler achieves with a passive encrypted snapshot file at zero operational cost.

**Verdict:** defer entirely. Revisit only if Wenv grows dynamic secrets or a watch/auto-restart story that needs a resident process.

## 4. Docker / Compose native secrets

**Non-swarm Compose (`docker compose`), current semantics** ([use-secrets guide](https://docs.docker.com/compose/how-tos/use-secrets/), [compose spec 09-secrets](https://github.com/compose-spec/compose-spec/blob/main/09-secrets.md), [services reference](https://docs.docker.com/reference/compose-file/services/)):
- Top-level `secrets:` sources: `file:` (contents of a host file) or `environment:` (value of a host env var); `external: true` references pre-created platform secrets (swarm only in practice).
- Services must opt in via service-level `secrets:`; mounted read-only at `/run/secrets/<name>` (long syntax `target` overrides).
- Non-swarm implementation is **a bind mount of the source file** — not tmpfs, no encryption at rest, no store. Spec/reference state that `uid`/`gid`/`mode` "are only implemented in Docker Compose when the source of the secret is `environment`"; for file-source secrets "these attributes are silently ignored" and default mode is world-readable `0444`.
- Consumption is **file-only**: the container reads `/run/secrets/foo`. Apps wanting env vars need the `_FILE` convention (supported by many official images) or an entrypoint shim. No native env-var delivery.
- Swarm mode is the real secret store: Raft-log encrypted at rest, tmpfs delivery, 500 KB limit, immutable (rotation = new named version + service update), and **only available to swarm services** ([swarm secrets](https://docs.docker.com/engine/swarm/secrets/)). Out of scope for the single-host compose persona (running a one-node swarm just for secrets is a hard sell).

**Per-criterion:** file-source compose secrets require the plaintext file on host disk *before* `up` — so for Wenv this degenerates to pattern 2 (render files, point `secrets:` at them), inheriting all its exposure problems while adding `_FILE`-convention friction. The `environment:` source composes nicely with pattern 1: `wenv run -- docker compose up` where the compose file maps `secrets: db_password: environment: DB_PASSWORD` — secret goes wrapper-env → file in container, never on host disk, and honors uid/gid/mode. That combo is worth documenting as the "file-consuming apps" recipe on top of the run-wrapper; it is not a standalone delivery pattern.

## 5. Deploy-time API call (CI fetches and injects)

CI job (Forgejo/GitHub Actions) calls Wenv, injects into the deploy step — either as masked CI env feeding `wenv run`/interpolation over SSH, or rendering a file and `scp`-ing it (pattern 2 remotely). Prior art: Infisical secrets-action, Doppler CI integrations, and Doppler's Docker recipe of baking an encrypted `--fallback-only` snapshot into deploys ([Docker HA](https://docs.doppler.com/docs/docker-high-availability)).

- *Plaintext:* lives in CI runner memory/logs-if-careless; on the host only if a file is shipped.
- *Token UX:* token lives in CI secret store, not on the box — arguably better scoping (the box itself holds nothing).
- *Offline/restart:* the fatal flaw for this persona: an unattended reboot restarts containers with whatever env/file the *last deploy* left. Secrets changed in Wenv since then silently don't apply until the next CI run — changes-apply-on-restart breaks.
- *Verdict:* not a v1 deliverable; it falls out for free (CI runs the same CLI with a token). Document as a recipe later.

## systemd credentials as a hardening path

For compose-via-systemd setups ([systemd credentials](https://systemd.io/CREDENTIALS/), [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)):

- `LoadCredential=wenv-token:/etc/wenv/token` (systemd ≥ 247) or `LoadCredentialEncrypted=` (≥ 250) with `systemd-creds encrypt`, which AES-256-GCM-encrypts using a TPM2-sealed key, `/var/lib/systemd/credential.secret`, or both — ciphertext on disk is useless off-box.
- The unit's process sees plaintext files under `$CREDENTIALS_DIRECTORY`, backed by non-swappable ramfs, access-checked per open, not inherited down the tree by default; ~1 MB per service limit.
- Fit for Wenv: this is the answer to "where does the *service-account token* live on the box". A wrapper unit does `LoadCredentialEncrypted=wenv-token:...` and `ExecStart=wenv run --token-file ${CREDENTIALS_DIRECTORY}/wenv-token -- docker compose up -d`. The CLI needs exactly one feature to support it: `--token-file` (read token from path). Everything else is documentation, not code. It hardens the weakest link of every pattern above (the long-lived token at rest) with zero Wenv-side machinery. Note: requires the user to run compose under systemd, which is also the right answer to restart-on-boot anyway.

## Recommendation (ranked)

1. **Primary v1: `wenv run` exec wrapper.** Argument: it is the only pattern with zero plaintext-on-disk in the happy path; it makes changes-apply-on-restart automatic (every restart re-fetches); it matches the fail-fast principle cleanly (server unreachable → non-zero exit, loud error); and it's the pattern Infisical/Doppler have already trained this persona on. Minimum flag surface: `-- cmd`, `--project/--env` selection, `--token`/`WENV_TOKEN`/`--token-file`, and *documented* merge semantics (fetched secrets override inherited env; collisions warn). Ship with a doc page on the Compose interpolation trap (host env ≠ container env; need `${VAR}` or `environment:` pass-through, or the `secrets: environment:` mapping from §4 for file-consuming images).
2. **Secondary v1 (cheap, same code path): `wenv export --format dotenv`** to stdout by default; `--output-file` sets 0600 explicitly. Positioned as debug/escape-hatch; docs steer deploy usage to `run`.
3. **Documented recipes, no new code:** systemd wrapper unit with `LoadCredentialEncrypted` for the token; compose `secrets: environment:` mapping on top of `run` for `_FILE`-convention images.
4. **Deferred:** agent daemon (no dynamic secrets → no justification), swarm secrets (wrong persona), CI deploy-time injection (works via the same CLI when someone wants it), `--watch` auto-restart.

## Open for the Compose-integration grilling ticket

- **Offline fallback:** pure fail-closed vs Doppler-style encrypted local snapshot with explicit `--fallback` opt-in + stale warning. Fail-fast principle vs the reboot-while-Wenv-is-down chicken-and-egg on a single box (especially if Wenv itself runs in that same compose stack). This is the sharpest trade-off and needs a decision, not a default.
- **Merge/override policy:** do fetched secrets override the inherited environment or vice versa; is a collision a warning or an error (fail-fast suggests error, prior art says silent override).
- **Token shape:** static long-lived service-account token (file, 0600) for v1, or short-lived tokens from day one; whether `--token-file` + systemd-creds is the *documented default* or an advanced page.
- **Does `export` warn/refuse on staleness at all**, or is the stale-file hazard purely a docs matter.
- **Restart ergonomics:** does Wenv ship a sample systemd unit (and is that in-scope for the binary, e.g. `wenv systemd install`), or docs-only.

## Sources

- https://infisical.com/docs/cli/commands/run · https://infisical.com/docs/cli/commands/export
- https://docs.doppler.com/docs/cli · https://docs.doppler.com/docs/automatic-fallbacks · https://docs.doppler.com/docs/docker-high-availability
- https://github.com/Infisical/infisical/issues/1609 · https://github.com/Infisical/infisical/issues/1639 · https://github.com/Infisical/cli/issues/216 · https://infisical.com/docs/integrations/platforms/infisical-proxy
- https://docs.docker.com/compose/how-tos/use-secrets/ · https://docs.docker.com/reference/compose-file/services/ · https://docs.docker.com/compose/how-tos/environment-variables/envvars-precedence/ · https://github.com/compose-spec/compose-spec/blob/main/09-secrets.md
- https://docs.docker.com/engine/swarm/secrets/
- https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent
- https://systemd.io/CREDENTIALS/ · https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html
