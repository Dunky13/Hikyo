# Envweave Docker Compose integration (ADR, locked 2026-07-31)

Context: the v1 persona ([#3](https://github.com/Dunky13/envweave/issues/3)) is a self-hosting developer running Docker Compose on a single box, and Compose-first delivery is part of the wedge. The Compose research ([#6](https://github.com/Dunky13/envweave/issues/6), [compose-delivery.md](../research/compose-delivery.md)) surveyed five mechanisms — exec wrapper, rendered dotenv, local agent daemon, Compose-native secrets, deploy-time CI injection — plus systemd credentials as a hardening path, and left five questions open for this ticket: offline fallback, merge/override policy, token shape on the box, export staleness, and restart ergonomics. Every authorization question is fixed upstream: the permission ADR ([#15](https://github.com/Dunky13/envweave/issues/15)) fixes the workload allowlist, the disclosure-by-proxy rule and the `values export` formula; the machine-identity ADR ([#17](https://github.com/Dunky13/envweave/issues/17)) fixes the token format, the two delivery channels, conditional fetch and per-key audit. This ADR fixes **which delivery paths ship, how a value change reaches a running stack, what happens on disk, what happens offline, and how a stack is adopted**.

## Declared amendments

Five, stated up front. This ADR does not claim conformance anywhere it changes locked text.

> **1. Amends the threat model ([threat-model.md](./threat-model.md), [#8](https://github.com/Dunky13/envweave/issues/8)) — environment-variable delivery is an integrity capability, not only a disclosure one.** Environment variables are interpreted by the consuming runtime, and some of them redirect what it executes: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PERL5OPT`, `PATH`. It follows that a principal holding **`edit` ∧ `publish`** on an environment — the pair needed to author a value and commit it, not `publish` alone — can obtain **code execution inside every workload that consumes those variables as environment**, without holding `reveal` and without touching the compose file. § *Loader-control keys* fixes a defence-in-depth mitigation; it is explicitly **not** a boundary, and the residual — hostile values in the application's *own* configuration keys, which no name list can catch — belongs to the permission model as a workload-integrity risk rather than to a deny-list here.

> **2. Amends the machine-identity ADR ([machine-identities.md § Lifetime](./machine-identities.md), [#17](https://github.com/Dunky13/envweave/issues/17)) — revocation timing.** That ADR states *"revocation bites at the next fetch, never at expiry."* The offline snapshot (§ *Offline behaviour*) **weakens** it on this path: a revoked workload keeps receiving the last delivered values from local ciphertext until the box reaches the server again. The snapshot's hard maximum age is the only thing that makes revocation eventually bite, which is why an unbounded snapshot is rejected. The guarantee becomes: *revocation bites at the next fetch, and at latest at snapshot expiry* — with the honest caveat in § *Offline behaviour* that expiry rests on a clock the client does not fully control.

> **3. Amends the threat model ([#8](https://github.com/Dunky13/envweave/issues/8)) again — audit durability during offline serve.** That ADR requires a durable audit record **before** a fetch completes, and #15 requires one immutable event per disclosed key. An offline serve reaches the server for neither. This ADR does not pretend otherwise: it moves the obligation client-side (§ *Offline behaviour*), requiring one durable, immutable, per-key local record fsynced **before** plaintext is released, and authenticated reconciliation on reconnect. A box that never reconnects has disclosure with no server-side record, and that is the accepted cost of the fallback.

> **4. Amends the source-of-truth ADR ([source-of-truth.md § Non-goals](./source-of-truth.md), [#13](https://github.com/Dunky13/envweave/issues/13)) — the no-restart sentence.** That ADR states *"Compose has no reconciler at all… no Envweave publish causes a Compose service to restart"*, while the same document delegates *"restart and reconciliation behaviour → Compose (#18)"* and says Compose *"owns restart/watch semantics"*. This ADR exercises that delegation and therefore **narrows the sentence**: `envweave compose sync`, when the operator installs its timer, does cause a Compose service to restart after a publish. What #13 rules out and this ADR **inherits unchanged** is *Compose GitOps reconciliation* — no Git watching, no Git↔DB convergence, no bidirectional controller. `sync` reconciles delivered values against running containers; it never reconciles a repository against anything.

> **5. Extends the encryption ADR ([encryption-model.md](./encryption-model.md), [#14](https://github.com/Dunky13/envweave/issues/14)) — a client-side key it does not currently cover.** That ADR fixes the server key hierarchy and the AEAD used at every layer. The offline snapshot and the stamp key are **client-side** artifacts outside that hierarchy, but they are not exempt from its rules: § *Offline behaviour* fixes a versioned XChaCha20-Poly1305 container with a domain-separated HKDF and a normative AAD tuple, matching #14's primitive choice rather than inventing one.

Granularity note: this is the wayfinding-level Compose ADR. It fixes the delivery paths, the change-propagation mechanism, on-disk behaviour, offline behaviour, the merge rules and the adoption flow. Mechanism-level detail is delegated: concrete verb names, flags, exit codes and the complete per-verb authorization formulas → API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25)); event shapes → audit ([#24](https://github.com/Dunky13/envweave/issues/24)); snapshot maximum age, sync interval defaults, runtime-directory conventions and generation-retention counts → operations spec (fog); the resident-process question → architecture ([#22](https://github.com/Dunky13/envweave/issues/22)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## Two delivery paths, both supported

**1. `envweave run -- <command>`** — fetches, merges into the child environment, `exec`s. Zero plaintext on disk in the happy path.

**2. Rendered env file consumed by `env_file:`** — Envweave renders a dotenv file; Compose injects its contents into the container. This is the path that removes per-variable plumbing.

The distinction that must lead the documentation is mechanism, not preference:

- `run` populates the *host* environment, which Compose uses for **interpolation only**. A variable present in `run`'s environment is **invisible to containers** unless the compose file references it — `${VAR}`, or an `environment: VAR` pass-through. This is the single most common way a user concludes Envweave does not work.
- `env_file:` injects file contents **directly into the container**. Paths resolve relative to the compose file, so managed targets are referenced by **absolute path** (§ *Where plaintext lives*).

*Rejected: `run` as the only supported deploy path.* It fails on its own terms: the rendered path without `env_file:` — i.e. `--env-file`, which also feeds interpolation only — imposes exactly the same per-variable plumbing as `run` while adding plaintext on disk. The rendered path earns its place **only** through `env_file:`.

*Rejected: rendered dotenv as the primary path.* Inverts the plaintext trade-off to buy compose-file ergonomics.

*Rejected: Compose-native `secrets:` with a `file:` source.* Non-swarm Compose implements it as a bind mount of a host file, with no store and no encryption, and the reference documents that `uid`/`gid`/`mode` are silently ignored for file sources, defaulting to world-readable. It degenerates into path 2 with added `_FILE` friction. The `environment:` source is different and **is** recommended, as a recipe on top of path 1 (§ *Recipes*).

*Rejected: Swarm secrets.* The real secret store, and the wrong persona.

## Dotenv encoding and the Compose version floor

Normative here, not deferred, because it is a correctness property of path 2 rather than a formatting preference.

**Compose parses `env_file` values by default**: unquoted and double-quoted values undergo interpolation, `$` expressions expand, escape sequences (`\n`, `\r`, `\t`, `\\`) are processed in double quotes, single quotes are literal, and surrounding spaces are stripped. A secret containing `$`, a quote or a backslash is therefore **silently transformed** — a delivered value that is not the stored value, which no amount of canonical rendering on our side repairs.

Consequently:

1. **Every Envweave-rendered `env_file:` entry MUST use `format: raw`**, which passes values as-is including quotes and `$`.
2. **The minimum supported Compose version for path 2 is 2.30.0**, the release that introduced `format: raw` ([docker/compose#12179](https://github.com/docker/compose/pull/12179)). `doctor` detects the running Compose version and **refuses path 2 below the floor**, naming the version, rather than delivering mangled secrets.
3. **`run` (path 1) has no such floor** — it never goes through dotenv parsing — and is the documented answer for older Compose.
4. **The canonical rendered encoding is normative and MUST be round-trip tested in CI** against the full value domain the schema admits: every UTF-8 sequence except NUL, which #12 already rejects for the `execve` path. The test asserts *stored bytes equal delivered bytes* for `$`, quotes, backslashes, leading and trailing whitespace, and embedded newlines. Where `raw` cannot represent a value — embedded newlines are the candidate — the renderer **refuses that key by name** rather than delivering a truncated or altered value, and the refusal is reported as a delivery failure, not a warning.

The exact byte-level grammar is #25's to write down; the properties above bind it.

## No Docker socket

**Envweave never mounts, reads or connects to the Docker socket.** No component — server, CLI, or any future agent — is configured with `docker.sock`.

Three independent grounds:

1. **The operation does not exist.** A running container's environment cannot be changed. `docker container update` alters cgroup resources and the restart policy only; environment is fixed at `execve`. Every "apply the new env to the running container" design reduces to **destroy and recreate**, which is restart-triggering, not delivery.
2. **Socket access is host root on the default deployment.** Docker documents that daemon access gives "root access to the machine hosting the daemon". *Qualified honestly*: this is the **rootful** default, including membership of the `docker` group. Under rootless Docker the daemon and its containers run in an unprivileged user namespace, so the escalation is to that user, not to host root — still a full compromise of every workload on the box, which is sufficient. The threat model bounds server compromise at *full control-plane compromise*; the socket extends it to the host's container estate. A socket proxy does not help meaningfully: recreate requires container create, start and remove, which is the full-power set. A genuinely policy-enforcing authorization plugin could be narrower, and the decision still stands on grounds 1 and 3.
3. **It fights Compose's own convergence.** Compose reconciles by comparing the `com.docker.compose.config-hash` label against the current service definition. An external actor recreating containers behind Compose's back must either write a hash it did not compute — lying about what the container was built from — or have its work reverted on the next `docker compose up`.

*Rejected: a label-watching agent daemon with the socket mounted.* Raised explicitly during grilling. Its only achievable form is a recreate loop, and it duplicates a job Compose already does correctly.

*Rejected: a local agent daemon generally (Vault Agent / Infisical Proxy shape).* v1 has static secrets and changes-apply-on-restart, so lease renewal, templating and client caching have nothing to do; the one thing an agent buys is delivered by a passive snapshot at no operational cost.

## Change propagation — render generations and the stamp

**`envweave compose sync`** is a **one-shot** host process invoked from a systemd timer. It performs a conditional fetch carrying the authorization-bound cursor (#17), and on a change writes a new render generation and invokes `docker compose up -d`. Compose performs the recreate.

**There is no `--watch` and no resident client process.** An earlier draft offered one; it is withdrawn, because #22 is told not to introduce a resident Compose agent and a long-lived watcher is exactly that under another name.

Delivery correctness must not depend on `sync` being installed, because users type `docker compose up -d`. It therefore rides on Compose's own convergence.

### The stamp is keyed, never a content digest

**The stamp is `HMAC(local stamp key, versioned canonical encoding of the target's rendered content)`, 128 bits, version-prefixed.**

A bare content digest is forbidden, and not merely inadvisable: the revision ADR fixes the change token as keyed precisely because *"a bare digest over content is a function of secret plaintexts, so a low-entropy secret is brute-forceable offline by anyone holding the digest"* — and it fixed that for the Kubernetes annotation case, which is this case with a different label key. An earlier draft of this ADR used a bare content hash and additionally proposed committing it, which would have published the oracle. Both are withdrawn.

- **The local stamp key is random per installation**, 256 bits, generated on first use, stored `0600` in the Envweave state directory beside the snapshot key, and **domain-separated by HKDF from the same local key material** (§ *Offline behaviour*) so there is one local secret to protect, not two.
- **The key is deliberately local, not server-issued.** The server's change token is per `(org, project, environment)` and cannot be sliced per render target without a server-side per-key token, which #11 does not define and this ticket may not invent. A local key gives per-target granularity with the same unforgeability property, and its blast radius is nil: whoever reads the state directory also holds the token and the snapshot, so they can read the values outright.
- **Stamps are consequently box-local and are never committed.** The managed stamp block is generated locally and `adopt` adds it to `.gitignore`. A fresh clone has no stamps and fails loudly (below) until `envweave compose render` runs — which is correct: an unprovisioned checkout has no values either.

### The stamp is the generation id, and it appears in the path

**The stamp names the render generation, and the rendered file's path contains it.** There is exactly one mutable artifact on the box.

```yaml
services:
  api:
    env_file:
      - path: /run/envweave/acme-web-production/${ENVWEAVE_GEN_API:?run 'envweave compose render' first}/api.env
        format: raw
    labels:
      envweave.stamp: "${ENVWEAVE_GEN_API:?run 'envweave compose render' first}"
```

`ENVWEAVE_GEN_API` is defined in a managed block of a **generated, gitignored** env file that Compose auto-loads for interpolation. The Compose specification fixes that *"any values in a Compose file can be interpolated with variable substitution"*, so a path is an ordinary interpolation site.

Two properties follow, and both matter more than they look:

- **Correctness rests on the path, not the label.** Because the generation id is *in the `env_file` path*, a new generation changes the resolved service definition outright, so Compose's config hash moves for a reason that has nothing to do with whether it hashes file *contents*. The version-dependent behaviour that made § *Dotenv encoding* necessary is therefore not load-bearing here at all. The label is retained for inspection — `docker inspect` answers "which generation is this container running" — and is deliberately redundant.
- **Values and stamp cannot disagree.** They are the same string. There is no ordering between "write the values" and "write the stamp" to get wrong, because the generation directory is immutable and the pointer to it is a single file.

*Rejected: a `current` symlink plus a separate stamp variable.* This was the first draft and it is not crash-safe: an atomic rename protects one pathname, so a crash between swinging the symlink and regenerating the stamp block leaves new values under an old stamp — Compose does not recreate, and the staleness is silent and permanent. Adding a lock does not fix it, because the failure is a crash, not a race. Putting the generation id in the path removes the second artifact instead of trying to synchronize it.

**The `:?` required form is mandatory, not stylistic.** Compose's default `.env` loading is bypassable — `--env-file`, `COMPOSE_ENV_FILES`, `COMPOSE_DISABLE_ENV_FILE`, a different `--project-directory`, or a shell variable of the same name all change or defeat it. Without `:?`, an undefined stamp interpolates to the **empty string**, which is a stable label value: Compose would then never recreate, and the failure would be silent and permanent. With `:?`, every one of those bypass paths turns into a refusal to start, naming the fix.

**Honest residual, stated rather than papered over:** a user who overrides the stamp variable deliberately, or points `--env-file` at a stale copy, defeats the mechanism. `doctor` detects it; nothing prevents it. The guarantee is *no silent staleness*, not *no staleness*.

### Restart blast radius follows consumption

Because the stamp covers one target's content, a publish touching keys a service does not consume leaves its stamp unmoved and Compose does not recreate it. With a single stack-wide token, rotating one API key would restart every service in the stack including the database — a self-inflicted outage on the most routine operation in the product.

### Target membership is by immutable key id

A render target names the keys it delivers by the **immutable key ids** the schema ADR already assigns. Folder path is a **convenience at `adopt` time only**: `adopt` expands a folder selection into the id set and records the ids.

This is not bookkeeping. Folder path is non-semantic server-side — the schema ADR fixes that it "cannot change what any environment delivers" — and it is therefore **absent from the delivery manifest**, so moving a key between folders does **not** invalidate the conditional cursor. A client that resolved membership from live folder state would be told "current", keep its old target composition, and silently deliver the wrong key set. Binding to ids keeps folder movement exactly as non-delivery-affecting as the schema ADR says it is. `doctor` reports ids in the target that no longer exist, and ids whose folder no longer matches the selection `adopt` recorded, as drift for a human to resolve.

### Generations, atomicity and locking

A fixed render path updated in place cannot be made crash-safe: rendering before stamping leaves new values under the old label, so `up -d` does not recreate; stamping before rendering recreates with old values under the new stamp. Both are silent.

- Each render writes a **generation directory named by its stamp** — every target file for that fetch, written fresh, fsynced, then never mutated. Generation directories are immutable.
- **The generated stamp file is the single commit point.** It is written to a temporary path, fsynced, and moved into place with one **atomic rename**. Before that rename the new generation is invisible to Compose; after it, it is fully in effect. There is no second artifact to keep in step, and therefore no crash window in which values and stamp disagree.
- A **per-project writer lock** serializes `sync`, `render` and `adopt`, so two concurrent writers cannot interleave generations. A crash before the rename leaves an unreferenced generation directory, which recovery garbage-collects; no partially applied state is observable at any point.
- **A generation is complete or absent.** Recovery treats a generation directory lacking its completion marker as unreferenced, whatever its age, so a torn write is never adopted by a later cursor check.
- Retention of superseded generations is bounded (count in the operations spec) so a rollback does not require a fetch. **GC never removes the generation named by the current stamp file**, and never removes a generation while the writer lock is held by another process.

### Missing or stale stamps are errors

`envweave compose doctor` reads the resolved project and **fails loudly** when any of the following holds: a service consumes an Envweave-rendered target without the generation variable in its `env_file` path; any use of that variable omits the `:?` form; the generation the resolved config interpolates to is not the one named by the current stamp file; that generation directory is absent, incomplete, or lacks its completion marker; the stamp does not correspond to the server's current manifest for that target; the running Compose version is below the path-2 floor; `format: raw` is missing; the token file is readable beyond its owner; or target membership has drifted from the recorded key ids. **Agreement on one side and disagreement on another is a failure, not a pass** — the check is that config, stamp file, generation on disk and server manifest all name the same generation. `sync` runs the same checks before its first render.

This closes the research doc's open question on export staleness: **staleness is a check, not a documentation matter.**

## Where plaintext lives

- **Rendered values are written only to a runtime directory backed by tmpfs** — `RuntimeDirectory=` under systemd, otherwise `$XDG_RUNTIME_DIR` or an explicitly configured path. Never the compose project directory, never the git worktree, never persistent disk. Files are created with mode `0600` set explicitly, never left to umask.
- Managed targets are referenced by **absolute path**, because `env_file:` resolves relative to the compose file. This is a deliberate deviation from rendering next to the project, which is what puts secrets into tarball backups, editor file pickers and `.gitignore` roulette.
- **`run` writes nothing.** Values exist only in the child's environment.
- **The stamp block and the project config file are non-secret** and live on persistent disk. The stamp block is gitignored anyway, because it is box-local.

Honest limit: the child environment is readable at `/proc/<pid>/environ` and via `ps e`, both gated by `PTRACE_MODE_READ_FSCREDS` — same-UID or root. The softer paths are real and must be documented: the environment propagates to every child process, crash reporters capture it, and variables set via `environment:` are stored in the container's config where anyone in the `docker` group can read them with `docker inspect`. Envweave does not claim to defend against a same-UID or `docker`-group adversary on the box.

## Offline behaviour

**Every successful delivering fetch writes a ciphertext snapshot** to persistent disk. Serving from it is **opt-in per stack**, prints `serving stale from <timestamp>, generation <id>` on stderr on every serve, and is **refused past a hard maximum age** (value: operations spec). Plaintext derived from a snapshot renders to tmpfs like any other render.

The case this exists for is not convenience. On the target deployment **Envweave is itself a container in the same compose stack**, so at boot nothing can fetch — the server is not up yet. Pure fail-closed turns a power cut into a manual recovery on every box, to protect against an outage already in progress. The house principle is fail *fast* and no *silent* fallback; a loud, opt-in, timestamped, age-bounded stale serve is neither silent nor a default.

### Snapshot cryptography

Fixed here rather than deferred, per amendment 5:

- **XChaCha20-Poly1305**, matching #14's primitive, with a **version prefix** on the container.
- Key = **HKDF from a local 256-bit snapshot key** with a distinct domain-separation label from the stamp key's. The snapshot key is random per installation, stored `0600` in the state directory, and — where systemd credentials are in use — loadable as a credential alongside the token.
- **AAD binds the container to its context**: instance identity, org, project, environment, credential identity, resolved revision or pin, the authorized delivery projection, the render target set, issuance time and expiry. A snapshot is therefore not transplantable across environments, projects, principals, or projections.

**The snapshot key is deliberately not derived from the service-account token.** An earlier draft derived it from the token to avoid introducing a secret at rest. That was wrong on two counts: rotating the token would make every prior snapshot undecryptable exactly when the box most needs it, and **OIDC federation has no stable bearer token at all** — the credential is a rotating ID token, so a token-derived key is unconstructible on the credential kind #17 recommends. A separate local key costs one more secret in a directory that already holds the token and, under rootless or systemd-credential deployments, is protected identically. The trade is stated, not hidden: the snapshot is a values cache at rest, and the state directory is now the thing that protects it.

### Expiry, clocks and rollback

- **Issuance and expiry are server-asserted and integrity-protected in the AAD**, not client-chosen — the client cannot mint itself a younger snapshot without the key.
- The client keeps a **monotonic high-water mark** of the newest issuance it has seen and refuses an older snapshot, so a plain file rollback does not resurrect a superseded generation.
- **Honest bound**: an attacker who can roll back the filesystem *and* the high-water mark, or move the system clock backwards, can extend the stale window. That attacker also reads the state directory, and therefore reads the values directly — so this is not a new capability, and the amendment-2 guarantee is stated with the clock assumption visible rather than assumed away.

### Audit during offline serve

Per amendment 3, the obligation moves client-side and does not evaporate:

- **One durable, immutable, per-key local record**, written and fsynced **before** plaintext is released — the same before-completion ordering the threat model requires of the server, and the same per-key cardinality #15 requires. No counters, no collapsing.
- Each record carries the **credential identity that served it**, including where that credential has since been revoked, so reconciliation attributes correctly rather than dropping the events it most needs.
- **Reconciliation on reconnect is authenticated and idempotent**; the server records them as offline-served disclosures, distinguishable from live fetches. A revoked credential's records are still accepted for reconciliation — refusing them would discard exactly the evidence of the window the amendment exists to bound.
- Local log loss, corruption, or a box that never reconnects are stated failure modes with no recovery: disclosure occurred with no server-side record.

*Rejected: pure fail-closed with no cache.* Defensible until the reboot case, which is the case that matters on a single box.

*Rejected: an unbounded snapshot.* Unbounded means revocation never bites, which converts a locked guarantee into a fiction.

*Rejected: a persistent plaintext rendered file as the de-facto cache.* What happens by default if rendering is allowed on persistent disk, and the worst of every option: unencrypted, unversioned, unbounded, silent. This is why § *Where plaintext lives* is a hard rule.

## The token on the box

Locked upstream and restated: the token reaches the CLI through **exactly two channels, `--token-file <path>` and `ENVWEAVE_TOKEN`**; `--token-file` wins and the collision warns loudly; **no `--token` flag exists**.

**systemd credentials are the documented default for server deployments.** A wrapper unit uses `LoadCredentialEncrypted=` and passes `--token-file ${CREDENTIALS_DIRECTORY}/envweave-token`; the plaintext is visible only to that unit, backed by non-swappable ramfs, access-checked per open, not inherited down the process tree by default. The snapshot and stamp keys are loadable the same way.

**Envweave ships no unit-file generator.** A generated unit is a thing the project then owns across systemd versions, to save a one-time copy-paste. `doctor` changes outcomes instead: it **errors** on a token file readable beyond its owner and **warns** when a systemd-managed stack passes the token as a plain file rather than a credential.

The fallback ladder is documented explicitly: TPM2-sealed → `/var/lib/systemd/credential.secret` → plain `0600` file. `LoadCredentialEncrypted=` requires systemd ≥ 250 and the sealed variant requires a TPM; `doctor` MUST NOT error on a box that has neither.

## Merge, collisions, and loader-control keys

**Fetched values win over the inherited environment.** Forced, not chosen: if inherited wins, a stale `export DATABASE_URL` in a shell profile silently shadows the managed value and the workload runs on the wrong secret, invisibly.

**A collision whose values differ is a hard error.** Two sources disagreeing about a value the workload is about to run on is the definition of a fail-fast case, and a stderr warning during `docker compose up` scrolls past unread. Identical values are a no-op. The escape hatch names the colliding keys explicitly; there is no blanket override flag.

*Rejected: fetched-wins with a warning* (Infisical and Doppler prior art). *Rejected: inherited-wins*, on the shadowing argument.

### Loader-control keys — defence in depth, not a boundary

Per amendment 1, both delivery paths refuse by default to deliver a key whose name is loader-control. **This is defence in depth and the ADR says so**: runtime-controlled execution is open-ended — JVM, Ruby, Perl, Git, TLS, plugin-path and credential-provider variables all exist, and an application's own configuration keys can redirect behaviour with no special name at all. A name list cannot be the boundary, and presenting it as one would be theatre.

**The baseline list is fixed here** rather than deferred, because a mitigation whose content is undecided is not a mitigation: `LD_*`, `PATH`, `IFS`, `ENV`, `BASH_ENV`, `SHELLOPTS`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`, `GIT_*`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`. #25 may extend it; it may not shrink it silently.

**Refusal is overridable per target, explicitly.** A blanket delivery-time refusal on a name list turns a successfully published, schema-valid state into an undeployable one — a reliable denial of service, and a wall for the legitimate case of a `config` key genuinely named `PATH`. The project config file therefore carries a per-target acknowledgement naming each such key; without it, delivery fails loudly naming the key. Acknowledging is an operator act recorded in the config, not a flag buried in a command line, and never a silent drop — a silent drop is a delivery that quietly did not happen.

Refusal is enforced at **delivery**, not at **declaration**: a `config` key legitimately named `PATH` for a non-container consumer is not Envweave's to forbid, and #12 is locked. The UI SHOULD warn at declaration time; that is an affordance.

## Authorization, and what an unrevealed workload gets

Nothing here is a new authorization path. **Rendering an env file is a `values export`** and carries #15's formula in full:

- **Current material**: `read(E)` ∧ `reveal(E)`.
- **Historical material** (a pinned non-current revision): `read(E)` ∧ `reveal-history(E)` — **both conjuncts**, per #15's rule that a principal holding `reveal-history` without `read` cannot export, plus the pin's recorded authority principal re-checked on **every** fetch.
- One immutable disclosure event per delivered key, recording the revision for historical material. The reauthentication term is satisfied vacuously for machine principals, which do not reauthenticate.

Every fetch re-authorizes in-transaction against current policy, uncached.

A workload service account holds `read` at explicit `(project, environment)` scope, delivering `config` values and **secret presence only**. Secret plaintext requires the explicit per-project operator opt-in. Therefore, stated plainly because it surprises every first-time user: **`envweave run` on a fresh service account delivers no secrets.**

**Delivery is all-or-nothing against the resolved delivery manifest.** If the manifest contains secret occurrences the principal cannot reveal, `run` and the renderer **exit non-zero before starting anything**, naming the undelivered keys and printing the required opt-in. The error leaks nothing: `read` already confers knowledge that those keys exist.

`--config-only` is the explicit escape hatch for workloads wanting configuration and no secrets. It is **a distinct authorized projection, not a client-side filter** — the server delivers the config projection and the request is recorded in the fetch audit, so "this workload deliberately takes no secrets" is a visible fact rather than an absence, and the mode cannot be used to probe for the existence of material the principal could not otherwise see.

*Rejected: deliver what is authorized and omit the rest.* Silent partial delivery — the symptom surfaces inside the application's own connection error and the operator debugs Postgres instead of Envweave.

*Rejected: refusing to mint a workload credential until the opt-in is on.* Front-loads a decision the operator cannot yet evaluate, and breaks the config-only workload outright.

**The five-step journey MUST appear in the documentation in full**: mint the service account → grant `read` → `run` fails, naming the secrets it could not deliver → the operator flips the per-project opt-in, acknowledging that a credential holding `reveal` is a standing decryption capability → grant `reveal`, which itself requires `manage-identities(project)` ∧ `reveal` over the whole resulting post-state, plus reauthentication.

### Cursor rules

The conditional cursor is local state and can desynchronize from local delivery state, which the server cannot see. Normative:

- The stored cursor is bound to **credential identity, environment, pin generation, authorized delivery projection, delivery mode (`--config-only` or not), and the render-target id set**. Any change to any of these invalidates it.
- **A cursor is presented only while the generation that produced it is the one currently named by the stamp file, and that generation is present and complete.** Mere existence somewhere under retention is not enough: a superseded generation kept for rollback, or a torn one missing its completion marker, must not make a cursor eligible. After a reboot the tmpfs render is gone while a persistent cursor would still read "current" — the server would answer "current", deliver no plaintext, and rendering would be impossible. On any failure of that three-part test the client performs a **full authorized fetch**, with its per-key disclosure events.
- **A cursor is never advanced after a rejected or failed render** — including the all-or-nothing manifest refusal, a loader-control refusal, an encoding refusal, or a crash before the metadata rename.
- Repeated cursor-less fetching by one credential is a signal the server surfaces, per #17.

## Credential separation on the box

Adoption **writes** — `values import` needs `edit` and `publish`, which no workload credential may hold. A box running an adopted stack therefore holds two credential artifacts with different authority: the **human CLI session** from `envweave login` (a distinct artifact type per #16) and the **workload service-account token**.

**They never substitute for each other.**

- `run`, render and `sync` accept **only** machine credentials.
- `adopt`, `scaffold`, `import`, `publish` and `login` accept **only** a human session.
- **One narrow exception**: `run` may use a human CLI session when **all** of the following hold — an explicit `--use-human-session` flag is passed; stderr is a TTY; the command **enumerates the environment and key set** it is about to disclose and the human confirms it; and the normal human reauthentication ceremony runs, bound to that enumerated set exactly as any other `values export` would be.

**TTY alone is not the control, and an earlier draft that treated it as one is withdrawn.** A PTY is allocatable by CI runners, `script`, tmux and service managers, so `isatty()` proves neither human presence nor intent; and the comparison to #17's display rule was invalid, because routing output away from a log is a different control from selecting which authority a command runs under. The flag supplies intent, the enumeration supplies the protected unit #16 requires, the reauthentication supplies the ceremony, and the TTY test remains only as a cheap additional refusal of the unattended case.

The hazard being closed is precise: a systemd unit silently executing with a developer's full authority, possibly org-scoped `reveal` reaching production, with nothing looking wrong.

*Rejected: hard separation with no exception.* Taxes local development to prevent something local development does not do — the developer could `values export` the same material by hand.

*Rejected: the TTY test alone.* Forgeable, and it omits the disclosure ceremony a human `values export` owes.

## Adoption

**`envweave compose adopt` rewrites the compose file in place**, after writing a backup. Order is normative, because it is a correctness property rather than a workflow preference:

1. **Scaffold first.** `adopt` runs the definitions flow against the *untouched* `.env` — offline `scaffold --from .env` producing all-`config` keys marked `# TODO: classify`, then review, `apply`, and strict `values import`, exactly as #13 fixes. No auto-classification: deciding what is secret is a human act.
2. **Only then** does it insert `env_file:` entries (with `format: raw`) and stamp labels into the selected services, create the generated stamp file, and add it to `.gitignore`.

Reversing that order imports `ENVWEAVE_STAMP_*` as application configuration, because `scaffold` reads the file `adopt` just wrote into. The managed block is **normatively excluded** from `scaffold` input regardless, as belt and braces.

**No claim is made that any `.env` is safe to commit.** An existing project `.env` routinely holds plaintext values; adding a non-secret block to it changes nothing about that. Only the *generated stamp file* is non-secret, and it is gitignored anyway because stamps are box-local.

The YAML round-trip MUST preserve comments, key order and formatting. Mangling a hand-tuned compose file is the failure mode that matters, and avoiding it is this project's responsibility. `doctor` is the verification step after `adopt` and after every hand edit.

### Recipes

- **`_FILE`-convention images**: `envweave run -- docker compose up -d` with `secrets: { db_password: { environment: DB_PASSWORD } }`. The value travels wrapper environment → in-container file at `/run/secrets/<name>`, never touching host disk, and `uid`/`gid`/`mode` are honoured because the source is `environment:` rather than `file:`.
- **Restart on boot**: a systemd unit with `LoadCredentialEncrypted=` and `ExecStart=envweave run -- docker compose up -d`, re-fetching on every start.

## Project configuration

A **committed, non-secret** per-project configuration file names the server URL, org, project, environment, and the render targets — each target's runtime path, its **key id set**, the services consuming it, and any per-target loader-control acknowledgements.

**It holds no credential, and the specification says so explicitly**, because a file that *could* hold a token eventually does. The token's only channels remain `--token-file` and `ENVWEAVE_TOKEN`.

## Reconciliation with upstream ADRs

- **Threat model ([#8](https://github.com/Dunky13/envweave/issues/8))** — read-only workload credentials scoped to `(project, environment)`; per-fetch audit with credential identity; no plaintext at rest beyond the tmpfs render. **Amended twice**: environment delivery as an integrity capability, and audit durability during offline serve.
- **Revisions ([#11](https://github.com/Dunky13/envweave/issues/11))** — changes apply on restart, never by live process mutation. The stamp honours the keyed-token rule: no bare content digest reaches a label, an annotation, or a file.
- **Schema ([#12](https://github.com/Dunky13/envweave/issues/12))** — validation is authoritative at publish; delivery does not re-validate. Folder path stays non-semantic: target membership is by immutable key id, so folder movement changes no delivery. NUL exclusion is inherited by the dotenv encoding rules.
- **Source of truth ([#13](https://github.com/Dunky13/envweave/issues/13))** — `adopt` funnels into `scaffold` → review → `apply` → `values import`, scaffold-first, with no auto-declare or auto-classification; Envweave never reads a repository. **Amended** on the no-restart sentence; the Compose-GitOps non-goal is inherited unchanged.
- **Encryption ([#14](https://github.com/Dunky13/envweave/issues/14))** — **extended** with a client-side keyed container using the same primitive; the snapshot is not a backup and never substitutes for `backup-export`.
- **Permissions ([#15](https://github.com/Dunky13/envweave/issues/15))** — rendering is a `values export` carrying the full formula including `read(E)` in both the current and historical cases; workload allowlist and per-project machine-`reveal` opt-in enforced as written; no machine credential performs any adoption verb.
- **Human auth ([#16](https://github.com/Dunky13/envweave/issues/16))** — CLI sessions never authenticate an unattended workload; the human-session exception carries an enumerated protected unit and the reauthentication ceremony.
- **Machine identities ([#17](https://github.com/Dunky13/envweave/issues/17))** — `--token-file` and `ENVWEAVE_TOKEN` only; conditional fetch presents the authorization-bound cursor and a "current" answer delivers no plaintext; per-key disclosure events never collapsed. **Amended** on revocation timing.

## Propagations (binding on downstream tickets)

- **Kubernetes ([#19](https://github.com/Dunky13/envweave/issues/19))** — inherits the integrity amendment **only for environment-variable delivery**; a Secret projected as files carries a different, narrower risk that #19 must state separately. Inherits the loader-control baseline for env delivery, and MUST reconcile its restart mechanism with the stamp concept — annotation there, label here, one explanation for both, and neither a bare content digest.
- **Architecture ([#22](https://github.com/Dunky13/envweave/issues/22))** — MUST NOT introduce a resident client-side agent for Compose; `sync` is one-shot, timer-invoked. MUST provide the local state directory's protection model.
- **Audit ([#24](https://github.com/Dunky13/envweave/issues/24))** — MUST define event shapes for a delivering fetch, a conditional fetch that delivered nothing, a `--config-only` fetch, a refused loader-control key, an **offline per-key local record**, and its **authenticated reconnect reconciliation** including records served by a since-revoked credential.
- **API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25))** — MUST specify the canonical rendered encoding and its CI round-trip test; MUST pin and verify the Compose version floor; MAY extend but MUST NOT shrink the loader-control baseline; MUST document complete authorization formulas for `run`, render, `sync`, `doctor`, `adopt`; MUST specify the CLI login flow, which **cannot be a plain terminal password prompt** — #16 requires WebAuthn wherever the effective reveal window is `0`, and WebAuthn needs a browser origin, so remote `envweave login` is browser-delegated with a loopback redirect, with a terminal prompt viable only for local-account-plus-TOTP.
- **MVP boundary ([#26](https://github.com/Dunky13/envweave/issues/26))** — MUST record explicit in/out decisions for the deferrals below.
- **Operations spec (fog)** — snapshot maximum age; sync interval defaults; runtime-directory conventions per init system; generation retention count; state-directory protection and backup guidance for the local stamp and snapshot keys; per-principal fetch rate limits as they apply to `sync`; the reconnect reconciliation window.
- **Workload refresh (fog)** — narrowed: Compose restart-triggering is `sync` invoking `docker compose up -d`, with correctness resting on the stamp rather than on `sync` being installed. What remains fog is whether Envweave ever triggers restarts it was not invoked for.

## Deferred (recorded, not dropped)

- **Local agent daemon and any resident watcher** — revisit only with dynamic secrets.
- **Swarm secrets** — wrong persona.
- **CI deploy-time injection** — falls out for free (same CLI, same token) as a documented recipe; not a v1 deliverable, because an unattended reboot restarts containers with whatever the last deploy left, breaking changes-apply-on-restart.
- **Compose-native `secrets:` with a `file:` source** — degenerates to the rendered path with added friction.
- **Server-issued per-key delivery tokens** — would let the stamp be server-keyed rather than locally keyed, removing the local stamp key. It requires extending #11's change-token model at per-key cardinality, which is not this ticket's to invent.
- **Short-lived / just-in-time workload tokens at deploy time** — a later addition on top of the locked lifetime rules.
