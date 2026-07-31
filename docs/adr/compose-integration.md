# Envweave Docker Compose integration (ADR, locked 2026-07-31)

Context: the v1 persona ([#3](https://github.com/Dunky13/envweave/issues/3)) is a self-hosting developer running Docker Compose on a single box, and Compose-first delivery is part of the wedge. The Compose research ([#6](https://github.com/Dunky13/envweave/issues/6), [compose-delivery.md](../research/compose-delivery.md)) surveyed five mechanisms — exec wrapper, rendered dotenv, local agent daemon, Compose-native secrets, deploy-time CI injection — plus systemd credentials as a hardening path, and left five questions open for this ticket: offline fallback, merge/override policy, token shape on the box, export staleness, and restart ergonomics. Every authorization question is already fixed upstream: the permission ADR ([#15](https://github.com/Dunky13/envweave/issues/15)) fixes the workload allowlist, the disclosure-by-proxy rule and the `values export` formula; the machine-identity ADR ([#17](https://github.com/Dunky13/envweave/issues/17)) fixes the token format, the two delivery channels, conditional fetch and per-key audit. This ADR fixes **which delivery paths ship, how a value change reaches a running stack, what happens on disk, what happens offline, and how a stack is adopted**.

> **Amends the threat model ([threat-model.md](./threat-model.md), [#8](https://github.com/Dunky13/envweave/issues/8)):** that ADR enumerates disclosure as the harm from value delivery. Delivering environment variables to a process is additionally a **code-execution capability** — `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP` and `PATH` all redirect what the child executes. It follows that **`publish` on an environment confers code execution inside every workload consuming it**, without `reveal` and without touching the compose file. This is a property of environment-variable delivery, not of Compose; the Kubernetes path ([#19](https://github.com/Dunky13/envweave/issues/19)) inherits it identically. § *Loader-control keys* fixes the mitigation, which bounds the hazard without eliminating it: an attacker holding `publish` can still set an application's own configuration to hostile values.

> **Amends the machine-identity ADR ([machine-identities.md § Lifetime](./machine-identities.md), [#17](https://github.com/Dunky13/envweave/issues/17)):** that ADR states *"revocation bites at the next fetch, never at expiry."* The offline snapshot in § *Offline behaviour* **weakens** that guarantee on the Compose path: a revoked workload continues to receive the last delivered values from local ciphertext until the box reaches the server again. The snapshot's **hard maximum age** is the only thing that makes revocation eventually bite, which is why an unbounded snapshot was rejected. Stated as an amendment rather than claimed as conformance: the guarantee is now *revocation bites at the next fetch, and at latest at snapshot expiry*.

Granularity note: this is the wayfinding-level Compose ADR. It fixes the delivery paths, the change-propagation mechanism, on-disk behaviour, offline behaviour, the merge rules and the adoption flow. Mechanism-level detail is delegated: concrete verb names, flags, exit codes, the complete per-verb authorization formulas and the CLI login flow → API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25)); event shapes for fetch, offline serve and reconciliation → audit ([#24](https://github.com/Dunky13/envweave/issues/24)); snapshot maximum age, fetch rate limits, sync interval defaults and render-directory conventions → operations spec (fog); whether Envweave ever triggers restarts beyond `sync` → workload refresh (fog); the resident-process question → architecture ([#22](https://github.com/Dunky13/envweave/issues/22)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## Two delivery paths, both supported

**1. `envweave run -- <command>`** — fetches, merges into the child environment, `exec`s. Zero plaintext on disk in the happy path. This is the recommended path for interactive and single-command use.

**2. Rendered env file consumed by `env_file:`** — `envweave` renders a dotenv file, compose injects its contents into the container. This is the path that removes per-variable plumbing.

Both are first-class and both are documented as deploy paths. The distinction that must lead the documentation is not preference but **mechanism**:

- `run` populates the *host* environment, which Compose uses for **interpolation only**. A variable present in `run`'s environment is **invisible to containers** unless the compose file references it — `${VAR}` in the file, or an `environment: VAR` pass-through entry. This is the single most common way a user concludes Envweave does not work, and it is the first thing the Compose page must say.
- `env_file:` injects the file's contents **directly into the container**, no per-variable reference required. Paths resolve relative to the compose file, so Envweave-managed targets are referenced by **absolute path** (§ *Where plaintext lives*).

*Rejected: `run` as the only supported deploy path.* It was this ADR's initial lean. It fails on its own terms: rendered-dotenv without `env_file:` — i.e. using `--env-file`, which also feeds interpolation only — imposes exactly the same per-variable plumbing as `run` while additionally putting plaintext on disk, so it is strictly worse and would never be chosen. The rendered path earns its place **only** through `env_file:`, and forbidding `env_file:` therefore collapses the second path entirely rather than merely discouraging it.

*Rejected: rendered dotenv as the primary path.* Inverts the plaintext trade-off to buy compose-file ergonomics.

*Rejected: Compose-native `secrets:` with a `file:` source as a delivery pattern.* Non-swarm Compose implements a file-source secret as a bind mount of a host file, with no store and no encryption, and the reference documents that `uid`/`gid`/`mode` are silently ignored for file sources, defaulting to world-readable. It therefore degenerates into path 2 with added `_FILE`-convention friction. The `environment:` source is different and **is** recommended, as a recipe on top of path 1 — see § *Recipes*.

*Rejected: Swarm secrets.* The real secret store, and the wrong persona: running a one-node swarm to obtain it is not a proposal this project makes to a homelab operator.

## No Docker socket, in v1 or as a hardening option

**Envweave never mounts, reads or connects to the Docker socket.** No component — server, CLI or any future agent — is configured with `docker.sock`.

Three independent grounds, any one sufficient:

1. **The operation does not exist.** A running container's environment cannot be changed. `docker container update` alters cgroup resources and the restart policy only; environment is fixed at `execve`. Every "apply the new env to the running container" design therefore reduces to **destroy and recreate**, which is restart-triggering, not delivery.
2. **Socket access is host root.** Docker's own documentation states that daemon access gives "root access to the machine hosting the daemon". The threat model bounds server compromise at *full control-plane compromise*; mounting the socket silently escalates that to *host root*. A socket-proxy allowlist does not help, because recreate requires container create, start and remove — the full-power set.
3. **It fights Compose's own convergence.** Compose reconciles desired against actual state by comparing the `com.docker.compose.config-hash` label on a container against the current service definition. An external actor recreating containers behind Compose's back must either write a hash it did not compute — lying to Compose about what the container was built from — or have its work reverted on the next `docker compose up`.

*Rejected: a label-watching agent daemon with the socket mounted.* This was raised explicitly and is the natural reading of "make it just work". Its only achievable form is a recreate loop, at the cost of ground 2, and it duplicates a job Compose already does correctly.

*Rejected: a local agent daemon generally (Vault Agent / Infisical Proxy shape).* v1 has static secrets and changes-apply-on-restart, so lease renewal, template rendering and client-side caching have nothing to do; the one thing an agent genuinely buys — serving while the server is down — is delivered by a passive snapshot at no operational cost (§ *Offline behaviour*).

## Change propagation — the stamp

**`envweave compose sync`** is a host process, not a daemon and not a socket client. It performs a **conditional fetch** carrying the authorization-bound cursor (#17), and on a change re-renders its targets and invokes `docker compose up -d`. Compose performs the recreate. `sync` is invoked one-shot from a systemd timer (recommended) or run with `--watch`; a resident daemon is not shipped, and whether one ever is belongs to the workload-refresh fog and to #22.

Delivery correctness must not depend on `sync` being present, because users will type `docker compose up -d`. It therefore rides on Compose's own convergence:

**Each render target's rendered content is hashed, and that hash is placed in the resolved service definition of every service consuming it**, as a label:

```yaml
services:
  api:
    env_file:
      - /run/envweave/acme-web-production/api.env
    labels:
      envweave.stamp: "${ENVWEAVE_STAMP_API}"
```

`ENVWEAVE_STAMP_API` is defined in a **managed block** of the compose project's `.env` file, which Compose auto-loads for interpolation with no extra flags:

```
# >>> envweave stamps (managed — do not edit) >>>
ENVWEAVE_STAMP_API=8c1f30a4
# <<< envweave stamps <<<
```

The stamp is a **hash of the rendered content**, not a revision number. Consequences, all deliberate:

- **Restart blast radius follows consumption, not publication.** A publish touching keys a service does not consume leaves that service's stamp unmoved, so Compose does not recreate it. With a single stack-wide revision number, rotating one API key would restart every service in the stack including the database — a self-inflicted outage on the most routine operation in the product.
- **Stamps are not secret.** They are hashes of a delivered set, computed client-side, and the `.env` file holding them is safe to commit. This is why the stamp file may live on persistent disk while values may not.
- **Rendering MUST be deterministic.** Canonical key ordering, canonical quoting and canonical line endings are normative; a non-deterministic renderer makes a stable stack recreate itself on every sync. The exact canonical form is #25's to specify and MUST be specified.

*Rejected: relying on Compose to notice that an `env_file:` changed.* An `env_file:` entry contributes its **path** to the service definition; whether file *contents* participate in the config hash has varied across Compose versions and carries a documented history of both needless recreation and missed recreation. A delivery guarantee resting on that is a silent-stale failure — the exact fail-quiet the project's fail-loud principle exists to prevent. `--force-recreate` remains available inside `sync` as a belt-and-braces path, but it is not the load-bearing mechanism.

*Rejected: modelling the key→service mapping server-side.* "Service" is not an Envweave concept: the domain model ([#7](https://github.com/Dunky13/envweave/issues/7)) is Instance > Org > Project > Environment > Folder > Key/Value, with folders organizational only. Teaching the server about Compose services would place a deployment-target concept inside the core model, and every subsequent integration would demand its own. A render target **is** the mapping, and it lives in the compose project where the mapping already exists.

**Missing stamps are an error, not a degradation.** `envweave compose doctor` reads the resolved project and **fails loudly** when a service consumes an Envweave-rendered `env_file:` without a stamp label, when a stamp label references an undefined variable, or when a rendered file's hash matches neither its label nor the server's current manifest. Without `doctor`, a forgotten label line is indistinguishable from correct operation until values silently stop applying. `sync` runs the same checks before its first render.

This also closes the research doc's open question on export staleness: **staleness is a check, not a documentation matter.**

## Where plaintext lives

- **Rendered values are written only to a runtime directory backed by tmpfs** — `RuntimeDirectory=` under systemd, otherwise `$XDG_RUNTIME_DIR` or an explicitly configured runtime path. Never the compose project directory, never the git worktree, never persistent disk. Files are created `O_CREAT|O_EXCL` with mode `0600` set explicitly, never left to umask.
- Because `env_file:` paths resolve relative to the compose file, managed targets are referenced by **absolute path**. This is a documented deviation from the habit of rendering next to the project, and it is the whole point: rendering next to the project is what puts secrets in tarball backups, editor file pickers and `.gitignore` roulette.
- **`run` writes nothing.** Values exist only in the child's environment.
- **Stamps and the project config file are non-secret** and live on persistent disk (§ *Change propagation*, § *Project configuration*).

Honest limit, stated rather than implied: the child environment is readable at `/proc/<pid>/environ` and via `ps e`, both gated by a `PTRACE_MODE_READ_FSCREDS` check — same-UID or root. The softer paths are real and must be documented: the environment propagates to every child process, crash reporters capture it, and variables set via `environment:` are stored in the container's config where anyone in the `docker` group can read them with `docker inspect`. Envweave does not claim to defend against a same-UID or `docker`-group adversary on the box.

## Offline behaviour

**Every successful delivering fetch writes a ciphertext snapshot** to persistent disk, encrypted under a key **derived from the service-account token**. No new secret is introduced at rest: the token is already on the box, and whoever can read the token could fetch the same values directly. The snapshot therefore inherits the token file's protection and nothing more — which is the argument for systemd credentials in § *The token on the box*.

Serving from the snapshot is **opt-in per stack**, prints `serving stale from <timestamp>, stamp <hash>` on stderr on **every** serve, and is **refused past a hard maximum age** (concrete value: operations spec). Plaintext derived from a snapshot renders to tmpfs like any other render.

The case this exists for is not convenience. On the target deployment, **Envweave is itself a container in the same compose stack**, so at boot nothing can fetch — the server is not up yet. Pure fail-closed turns a power cut into a manual recovery on every box, to protect against an outage that is already in progress. The house principle is fail *fast* and no *silent* fallback; a loud, opt-in, timestamped, age-bounded stale serve is neither silent nor a default.

Three costs, recorded rather than buried:

1. **Revocation is weakened**, as declared in the amendment above. Snapshot maximum age is the bound.
2. **Offline serves are invisible to the server's audit log.** There is no fetch, so there are no per-key disclosure events. The client MUST keep a local serve log and reconcile it on reconnect, and the ADR states plainly that a box which never reconnects has disclosure with no server-side record.
3. **The snapshot is exactly as strong as the token file.**

*Rejected: pure fail-closed with no cache.* Defensible until the reboot case, which is the case that matters on a single box.

*Rejected: an unbounded snapshot.* Unbounded means revocation never bites, which converts a locked guarantee into a fiction.

*Rejected: leaving a persistent plaintext rendered file to serve as the de-facto offline cache.* This is what happens by default if rendering is allowed on persistent disk, and it is the worst of every option: unencrypted, unversioned, unbounded in age, and silent. It is the reason § *Where plaintext lives* is a hard rule rather than a recommendation.

## The token on the box

Locked upstream and restated: the token reaches the CLI through **exactly two channels, `--token-file <path>` and `ENVWEAVE_TOKEN`**; `--token-file` wins and the collision warns loudly; **no `--token` flag exists**.

**systemd credentials are the documented default for server deployments.** A wrapper unit uses `LoadCredentialEncrypted=envweave-token:/etc/envweave/token.cred` and passes `--token-file ${CREDENTIALS_DIRECTORY}/envweave-token`; the plaintext credential is visible only to that unit, backed by non-swappable ramfs, access-checked per open and not inherited down the process tree by default.

**Envweave ships no unit-file generator.** A generated unit is a thing the project then owns and supports across systemd versions, to save a one-time copy-paste. `doctor` is what changes outcomes instead: it **errors** on a token file readable beyond its owner and **warns** when a systemd-managed stack passes the token as a plain file rather than a credential. A documentation page nobody opens fixes nothing; a check that names the problem fixes it immediately.

The fallback ladder is documented explicitly rather than assuming the best case: TPM2-sealed → `/var/lib/systemd/credential.secret` → plain `0600` file. `LoadCredentialEncrypted=` requires systemd ≥ 250 and the sealed variant requires a TPM; `doctor` MUST NOT error on a box that legitimately has neither.

## Merge, collisions, and loader-control keys

**Fetched values win over the inherited environment.** This is forced, not chosen: if inherited wins, a stale `export DATABASE_URL` in a shell profile silently shadows the managed value and the workload runs on the wrong secret, invisibly.

**A collision whose values differ is a hard error.** Two sources disagreeing about a value the workload is about to run on is the definition of a fail-fast case, and a stderr warning during `docker compose up` scrolls past unread. Identical values are a no-op, so the common harmless case — a systemd `Environment=` line repeating a managed value — does not block a deploy. The escape hatch names the colliding keys explicitly; there is no blanket override flag.

*Rejected: fetched-wins with a warning* (Infisical and Doppler prior art). *Rejected: inherited-wins*, on the shadowing argument above.

### Loader-control keys

Following the threat-model amendment, **both delivery paths refuse to deliver a key whose name is loader-control** — the `LD_*` family, `PATH`, `IFS`, `BASH_ENV`, `ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`, `PERL5OPT` and the rest of the list #25 must enumerate normatively. The refusal is a **loud error naming the key**, never a silent drop: a silent drop is a delivery that quietly did not happen, which is the failure mode this whole ADR is organised against.

Refusal is enforced at **delivery** (both `run` and the renderer), not at **declaration**. A `config` key legitimately named `PATH` for a non-container consumer is not Envweave's to forbid, and the schema ADR ([#12](https://github.com/Dunky13/envweave/issues/12)) is locked. The UI SHOULD warn at declaration time; that is an affordance, not the control.

This bounds the escalation without closing it. An actor holding `publish` can still set an application's own configuration to hostile values — a database URL pointing at a server they control, a webhook target, a feature flag. The amendment says so.

## Authorization, and what an unrevealed workload gets

Nothing here is a new authorization path. **Rendering an env file is a `values export`** and carries #15's disclosure formula in full: `read(E)` ∧ `reveal(E)` for current material, `reveal-history(E)` for a pinned historical revision, one immutable disclosure event per delivered key, the reauthentication term satisfied vacuously because machines do not reauthenticate. Every fetch re-authorizes in-transaction against current policy, uncached. Pinned delivery re-checks the pin's recorded authority principal on every fetch.

A workload service account holds `read` at explicit `(project, environment)` scope, which delivers `config` values and **secret presence only**. Secret plaintext requires the explicit per-project operator opt-in (#15 § *Machine principals*). Therefore, stated plainly because it will surprise every first-time user: **`envweave run` on a fresh service account delivers no secrets.**

**Delivery is all-or-nothing against the resolved delivery manifest.** If the manifest contains secret occurrences the principal cannot reveal, `run` and the renderer **exit non-zero before starting anything**, naming the undelivered keys and printing the opt-in required. The error leaks nothing: `read` already confers knowledge that those keys exist.

`--config-only` is the explicit escape hatch for workloads that genuinely want configuration and no secrets, and it is **recorded in the fetch audit** so that "this workload deliberately takes no secrets" is a visible fact rather than an absence.

*Rejected: deliver what is authorized and omit the rest.* Silent partial delivery in its purest form — the symptom surfaces three layers away inside the application's own connection error, and the operator debugs Postgres instead of Envweave.

*Rejected: refusing to mint a workload credential until the opt-in is on.* Front-loads a decision the operator cannot yet evaluate, and breaks the legitimate config-only workload outright.

**The five-step journey MUST appear in the documentation in full**, because hiding step 4 produces a user who believes the product is broken: mint the service account → grant `read` → `run` fails, naming the secrets it could not deliver → the operator flips the per-project opt-in, acknowledging that a credential holding `reveal` is a standing decryption capability → grant `reveal`, which itself requires `manage-identities(project)` ∧ `reveal` over the whole resulting post-state, plus reauthentication.

## Credential separation on the box

Adoption **writes** — `values import` needs `edit` and `publish`, which no workload credential may hold. So a box running an adopted stack holds two credential artifacts with different authority: the **human CLI session** from `envweave login` (a distinct artifact type per #16) and the **workload service-account token**.

**They never substitute for each other.**

- `run`, render and `sync` accept **only** machine credentials.
- `adopt`, `scaffold`, `import`, `publish` and `login` accept **only** a human session.
- **One exception**: `run` MAY use a human CLI session when **stderr is a TTY**, printing a banner naming the principal and its scope. Non-interactive invocation — systemd, CI, cron — refuses and demands a token file.

The hazard the exception is carved around is precise: a systemd unit silently executing with a developer's full authority, possibly org-scoped `reveal` reaching production, with nothing looking wrong. The TTY test excises exactly that case, and it is the same test #17 already uses for credential *display*, applied to credential *use*. Interactive local use is not an escalation — that developer could `values export` the same material by hand — and forbidding it would force the persona this project optimizes for first to mint a service account before running `npm run dev`.

*Rejected: hard separation with no exception.* Cleaner on paper; taxes local development to prevent something local development does not do.

## Adoption

**`envweave compose adopt` rewrites the compose file in place**, after writing a backup: it inserts `env_file:` entries and stamp labels into the selected services, creates the managed stamp block in `.env`, writes the project configuration file, and emits the `scaffold --from .env` command that begins the definitions flow. The YAML round-trip MUST preserve comments, key order and formatting; mangling a hand-tuned compose file is the failure mode that matters, and it is this project's responsibility to avoid, not the user's to repair.

Definitions onboarding itself is unchanged and belongs to the source-of-truth ADR ([#13](https://github.com/Dunky13/envweave/issues/13)): offline `scaffold --from .env` — a pure local transform producing all-`config` keys marked `# TODO: classify` — then review, then `apply`, then strict `values import`. `adopt` invokes that flow; it does not replace or shortcut it, and in particular it performs **no auto-classification**: deciding what is secret is a human act.

`doctor` is the verification step after `adopt`, and after every hand edit.

### Recipes

- **`_FILE`-convention images**: `envweave run -- docker compose up -d` with `secrets: { db_password: { environment: DB_PASSWORD } }`. The value travels wrapper environment → in-container file at `/run/secrets/<name>`, never touching host disk, and `uid`/`gid`/`mode` are honoured because the source is `environment:` rather than `file:`.
- **Restart on boot**: a systemd unit with `LoadCredentialEncrypted=` and `ExecStart=envweave run -- docker compose up -d`, which re-fetches on every start.

## Project configuration

A **committed, non-secret** per-project configuration file names the server URL, org, project, environment, and the render targets — each target's runtime path, its key selection (by folder path, which is a client-side selection axis and introduces no domain concept), and the services consuming it.

**It holds no credential, and the specification says so explicitly**, because a file that *could* hold a token eventually does. The token's only channels remain `--token-file` and `ENVWEAVE_TOKEN`.

## Reconciliation with upstream ADRs

- **Threat model ([#8](https://github.com/Dunky13/envweave/issues/8))** — read-only workload credentials scoped to `(project, environment)`; per-fetch audit with credential identity; no plaintext at rest beyond the tmpfs render and the token-derived-key snapshot. **Amended** on environment-variable delivery as a code-execution capability (top of file).
- **Revisions ([#11](https://github.com/Dunky13/envweave/issues/11))** — changes apply on restart, never by live process mutation, which Docker does not offer in any case. Pinned delivery is supported and carries the pin's authority re-check.
- **Schema ([#12](https://github.com/Dunky13/envweave/issues/12))** — validation is authoritative at publish; delivery does not re-validate. Loader-control refusal is a delivery-layer control and does not amend the declaration rules.
- **Source of truth ([#13](https://github.com/Dunky13/envweave/issues/13))** — `adopt` funnels into `scaffold` → review → `apply` → `values import` with no auto-declare and no auto-classification; the compose file is not a definitions source and Envweave never reads a repository.
- **Encryption ([#14](https://github.com/Dunky13/envweave/issues/14))** — the offline snapshot is client-side, keyed by derivation from the service-account token, and is not part of the server key hierarchy; it is not a backup and never substitutes for `backup-export`.
- **Permissions ([#15](https://github.com/Dunky13/envweave/issues/15))** — rendering is a `values export` carrying the full disclosure formula; the workload allowlist and the per-project machine-`reveal` opt-in are enforced as written; no machine credential performs any adoption verb.
- **Human auth ([#16](https://github.com/Dunky13/envweave/issues/16))** — CLI sessions are a distinct artifact type and never authenticate an unattended workload; the TTY exception applies only to interactive `run`.
- **Machine identities ([#17](https://github.com/Dunky13/envweave/issues/17))** — `--token-file` and `ENVWEAVE_TOKEN` only, no `--token` flag; conditional fetch presents the authorization-bound cursor and a "current" answer delivers no plaintext and emits one access record; per-key disclosure events are never collapsed or counted. **Amended** on revocation timing by the offline snapshot (top of file).

## Propagations (binding on downstream tickets)

- **Kubernetes ([#19](https://github.com/Dunky13/envweave/issues/19))** — inherits the environment-variable code-execution amendment and the loader-control refusal; MUST reconcile its restart mechanism with the stamp concept (annotation hash there, label hash here, one explanation for both).
- **Architecture ([#22](https://github.com/Dunky13/envweave/issues/22))** — MUST NOT introduce a resident client-side agent for Compose; `sync` is a one-shot process invoked by a timer.
- **Audit ([#24](https://github.com/Dunky13/envweave/issues/24))** — MUST define the event shapes for a delivering fetch, a conditional fetch that delivered nothing, a `--config-only` fetch, an **offline snapshot serve** and its **reconnect reconciliation**, and a refused loader-control key.
- **API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25))** — MUST specify the canonical rendering form (ordering, quoting, line endings) that the stamp hashes; MUST enumerate the loader-control deny-list normatively; MUST document the complete authorization formula for `run`, render, `sync`, `doctor` and `adopt`; MUST specify the CLI login flow, which **cannot be a plain terminal password prompt** — #16 requires WebAuthn wherever the effective reveal window is `0`, and WebAuthn needs a browser origin, so remote `envweave login` is browser-delegated with a loopback redirect, with a terminal prompt viable only for local-account-plus-TOTP.
- **MVP boundary ([#26](https://github.com/Dunky13/envweave/issues/26))** — MUST record explicit in/out decisions for the deferrals below.
- **Operations spec (fog)** — snapshot maximum age; `sync` interval defaults; runtime-directory conventions per init system; per-principal fetch rate limits as they apply to `sync`; the reconnect reconciliation window for offline serve logs.
- **Workload refresh (fog)** — narrowed by this ADR: Compose restart-triggering is `sync` invoking `docker compose up -d`, with correctness resting on the stamp rather than on `sync` being present. What remains fog is whether Envweave ever triggers restarts it was not invoked for.

## Deferred (recorded, not dropped)

- **Local agent daemon** — revisit only with dynamic secrets or a watch story needing a resident process.
- **Swarm secrets** — wrong persona.
- **CI deploy-time injection** — falls out for free (same CLI, same token) and becomes a documented recipe; it is not a v1 deliverable because an unattended reboot restarts containers with whatever the last deploy left, breaking changes-apply-on-restart.
- **Compose-native `secrets:` with a `file:` source** — degenerates to the rendered path with added friction.
- **`--watch` auto-restart beyond `sync --watch`** — no separate watcher.
- **Short-lived / just-in-time workload tokens at deploy time** — a later addition on top of the locked lifetime rules, not a v1 shape.
