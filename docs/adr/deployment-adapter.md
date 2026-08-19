# Wenv deployment-module seam & Forgejo reference adapter (ADR, locked 2026-08-03)

Context: positioning ([#3](https://github.com/Dunky13/wenv/issues/3)) fixes outbound secret-sync "deployment modules" as a pluggable surface shipping in v1 with exactly one reference adapter (Forgejo). The threat model ([#8](https://github.com/Dunky13/wenv/issues/8)) fixes the trust boundary (server→provider, never server→module: modules are in-process trusted server code), the SSRF/egress posture for tenant-configured destinations, INTENT/OUTCOME auditing around external effects, and retry-with-deduplication. The permission ADR ([#15](https://github.com/Dunky13/wenv/issues/15)) fixes the authorization formulas (`manage-adapters(project)` ∧ `reveal(E)` for every synced environment + reauthentication for configure/widen/trigger), the recorded authority principal with atomic reassignment on any routing mutation, per-push re-authorization, and write-only outbound credentials. The architecture ADR ([#22](https://github.com/Dunky13/wenv/issues/22)) fixes the outbox machinery (job identity, authority principal, dedup key, lease, terminal states, INTENT/OUTCOME linkage) that adapter jobs run on. The audit ADR ([#24](https://github.com/Dunky13/wenv/issues/24)) fixes the `adapter` event category and delegates the final field spellings here. The API/CLI ADR ([#25](https://github.com/Dunky13/wenv/issues/25)) closes the verb taxonomy with one declared join point: adapter verbs land here, under its grammar. What every one of those ADRs delegated to this ticket is the rest: **the seam contract, the sync state model, the trigger model, ownership and adoption at the provider, target shape and key scoping, the Forgejo adapter concretely, multi-environment delivery into a flat provider namespace, drift honesty, and teardown.** This ADR fixes those.

Granularity note: this is the wayfinding-level deployment-module ADR. It fixes the seam interface, the converge semantics, the ownership model, the Forgejo mapping and its refusal rules, and the CLI spellings that join #25. Mechanism-level detail is delegated: concrete retry/backoff curves, queue depths, page sizes, ledger row bounds, snippet formatting and every other concrete duration or quota → operations spec ([#32](https://github.com/Dunky13/wenv/issues/32)); the adapter configuration screens and sync-status surfaces → the workload-integration prototype ([#31](https://github.com/Dunky13/wenv/issues/31)); in/out confirmation of named post-v1 items → MVP boundary ([#26](https://github.com/Dunky13/wenv/issues/26)); the exact Forgejo version floor pin and endpoint conformance → implementation, validated against this ADR's rules. Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## The seam — an in-process Go interface, not a plugin API

**A deployment module is compiled-in, trusted server code behind one Go interface.** The threat model already fixes this: the security boundary is server→provider, never server→module; third-party adapter contributions arrive as pull requests under mandatory security review, not as runtime-loaded plugins. There is no dynamic loading, no RPC plugin protocol, no adapter marketplace (presumptively out of MVP, confirmed at #26). "Pluggable" is a statement about the interface's neutrality — a second adapter (GitHub, GitLab) implements the same four operations without touching the core — not about runtime extensibility.

The interface has **four operations**, and the split is load-bearing:

| Operation | Network | Secret material | Purpose |
|---|---|---|---|
| `ValidateConfig` | none | none | static shape check of adapter/target configuration at configure time |
| `TestConnection` | provider | none | credential + destination-identity + version-floor probe; refuses below floor **by name** |
| `Plan` | provider (**secret-name list only**) | none | value-blind change set: create/update/delete/conflict **by (surface, effective name)** |
| `Sync` | provider (write) | yes, per push | converge the target to the manifest; prune ledger-owned orphans; per-key outcome |

**`Plan` is value-blind by construction — and for variables, provider-blind too.** Forgejo's secret list returns names and timestamps only, so the secret surface is planned against a provider name list with no value claims: "update" means *the name exists and will be re-pushed*, nothing more. **The variable surface is different, and the adapter's design treats it as radioactive: Forgejo's variable list and get endpoints return the stored *values*** (`data` is serialized in the list response — verified in Forgejo v16 source). An adapter that lists variables under `manage-adapters` alone would pull every provider variable value — including unrelated or provider-side-misclassified sensitive values — into Wenv's buffers on a plain-capability verb. So **the adapter never issues a variable read of any kind**: no GET, no list, ever. Variable-surface plans are computed from the ledger alone and report unowned-name conflicts as *unknown until sync*; the conflict is detected at `Sync` time by the write itself (§ Forgejo mapping: POST-create fails on an existing name, deterministically, without reading anything back). The one-way rule (§ One-way) is thereby structural — the code paths that could read a value do not exist — rather than a policy the implementation must remember.

**What `Sync` receives** is the delivery manifest the schema ADR fixed — `(key id, canonical name, classification, value)` tuples for the target's enumerated key set at the environment's current published revision — plus the target configuration (destination, prefix, adoption state). The manifest is assembled inside the job's authorized transaction at push time, never cached beside the outbox row; plaintext exists only in the push attempt's operation scope per #22's crypto boundary.

*Rejected: a fifth `Prune` operation.* Full-state converge owns deletion (§ next); a separate prune verb is a second way to delete, and two ways to do one thing is how one of them goes unaudited.

## Sync semantics — full-state declarative converge

**Every sync converges the target to the current manifest: compute the full effective name set, write all of it, prune ledger-owned orphans.** No delta bookkeeping, no per-key change cursor. The job is idempotent — re-running a converge is always safe — which is what makes the outbox's retry-with-deduplication trivial rather than a correctness hazard.

*Rejected: incremental delta push.* Deltas need a per-target cursor that must survive missed events, reordering, and crash-mid-push; at the v1 scale envelope (≤10k entries) the full set is small, and an idempotent converge makes the failure story one sentence instead of a state machine.

**Ordering: writes before prunes.** A rename inside one revision is delete-old + create-new; writing first means a CI run that starts mid-sync sees a superset of the target set, never a hole. The sentinel pair (§ Ownership) is written first of all on a target's first sync.

**Partial state is physically unavoidable and the ADR says so.** The provider API is per-name PUTs with no transaction. A converge that fails partway leaves the target part-old, part-new. There is no rollback: the provider is non-transactional, and re-pushing prior values would be a fresh disclosure decision wearing an undo costume. Instead:

- the outbox job stays non-terminal and **the whole converge retries** under backoff (idempotent, so retry is re-converge);
- the target carries a visible sync status — `converged@revN` / `converging` / `failed` with failing effective names listed **by name** — surfaced in UI and CLI. **The token is `converged`, deliberately not `synced`: it claims exactly "the last converge to revision N was acknowledged by the provider" — a statement about Wenv's writes, never about current provider state, which is unreadable and may have drifted the moment after (§ One-way);**
- per-push audit INTENT/OUTCOME records land exactly as #8/#24 fix them, correlated by outbox job id.

**Supersede: newest revision wins — under a fence, not a hope.** The outbox dedup key is the target; the job's goal is *converge to the environment's current published revision*, not *apply revision N*. A publish of revision N+1 while the N-job is queued or running marks the N-job terminal `superseded` (no further pushes) and the N+1 job is enqueued — one converge in flight per target, ever.

**The stale-write fence.** "One converge in flight" is not free: the outbox lease (#22) is crash recovery, and a lease cannot recall an HTTP request already on the wire. Without more, a slow N-push can land *after* the N+1 converge finished and silently restore stale plaintext — and the same race hits routing mutations, credential replacement, teardown, and scrub while a push is in flight. So this ADR adds what the outbox deliberately left to the domain:

- **Every target carries a monotonically increasing generation**, bumped by any routing mutation, adoption commit, teardown, and enqueue of a newer converge. A job records the generation it was enqueued under.
- **Provider writes hold an exclusive per-target lease *across each external request***: one in-flight provider write per target, ever. A superseding job, a scrub, or a mutation-triggered fence **waits for the in-flight request to reach a terminal or explicitly indeterminate outcome** before proceeding — it never fires alongside it.
- **A job whose recorded generation is no longer current stops at its next step boundary** (the same boundary as the per-step re-authorization check — one gate, two predicates). It performs no further provider writes and terminates `superseded`.
- **Teardown is a generation bump plus a tombstone**: the adapter/target row, its credential, its ledger, and its recorded authority principal survive until the scrub job reaches a terminal state — deleting them earlier would leave the scrub nothing to run as. `--keep-remote` tears down without a scrub job and releases immediately.

**Re-authorization is per sensitive step, exactly as locked.** Before every secret read and every outbound push — first attempt, retry, teardown scrub — the job re-checks the recorded authority principal's current `manage-adapters(project)` ∧ `reveal(E)`; loss of either aborts the remaining sensitive steps with a terminal audit outcome (#15's rule applied literally, on #22's machinery).

## Triggers — on-publish and manual, nothing on a clock

**Two triggers, closed set for v1:**

1. **On-publish.** A publish whose affected environment set intersects a target's environment enqueues that target's converge automatically. This is a standing delegation: the job runs under the adapter's **recorded authority principal**, re-checked per push — the machinery #15 built exists precisely for this shape. No reauthentication fires at publish time; the publish's own authorization already gated the state change, and the standing authority gates the propagation.
2. **Manual.** `adapter sync` — an explicit trigger — carries #15's full formula: `manage-adapters(project)` ∧ `reveal(E)` for every environment the adapter syncs, plus reauthentication. Use cases: first sync after configure, repair after provider-side tampering, re-push after a failed converge exhausted attention rather than retries.

*Rejected: scheduled reconcile.* No read-back exists (§ One-way), so a schedule fires blind — a fresh secret read and an outbound push per interval per target that can never observe the drift it exists to heal, widening the standing-disclosure surface for zero signal. Provider-side tampering is healed by the next publish or a deliberate manual sync, and the sentinel (§ Ownership) tells the human staring at Forgejo where to trigger it.

*Rejected: manual only.* "Publish, then remember to push" reintroduces stale CI secrets — the exact failure adapters exist to kill.

## Ownership — a server-side ledger, never inference

Forgejo secrets carry no labels, no annotations, no owner field. **The only ownership record is Wenv's ledger, and its identity is `(target, provider surface, effective name)`** — surface included, because Forgejo's secrets and variables are independent namespaces: the same name exists twice (the sentinel does so deliberately), and a reclassification keeps the name while switching surfaces. Without the surface in the key, `secret → config` reclassification writes the new variable and leaves the old secret at the provider forever — it is not in `ledger − desired` because the *name* never left. With it, reclassification is mechanical: write the new surface, prune the old, one converge.

**The destination is an immutable numeric id, never a path string.** At configure time the adapter resolves the repository/organization to Forgejo's numeric id and stores both; every subsequent provider operation verifies the id still matches what the path resolves to, and a mismatch — repository transferred, renamed-and-recreated, deleted-and-reused — is a hard, named refusal, not a write to whatever now lives at the old path. Path strings drift; ids do not.

**Ownership claims are reserved before the call, not recorded after it.** The provider is non-transactional, so "write ledger transactionally with the OUTCOME" has a hole: Forgejo accepts the PUT, the OUTCOME/ledger transaction fails, and the retry now sees a provider name the ledger does not hold — `exists, unowned` — permanently disowning Wenv's own successful write. Instead the claim follows the INTENT/OUTCOME shape the threat model already fixes for external effects:

1. **Reserve** — the ledger row is written in state `reserved` under a **global uniqueness constraint on `(provider origin, destination id, surface, normalized effective name)`**. The constraint is instance-wide, so two projects racing for one name cannot both reserve it; the loser's refusal is tenant-safe (`exists, unowned` — never naming the owning org or project, which would be a cross-tenant existence oracle). **A reservation is a claim among Wenv tenants and nothing more — it carries zero overwrite authority at the provider.** Without this, a crash between reservation and request opens a capture window: a third party creates the name in the gap, and a retry that treats the reservation as ownership silently overwrites a value Wenv never wrote.
2. **Dispatch** — transactionally with the push's INTENT record, immediately before the provider request, `reserved` becomes `dispatched`. Only the transition proves absence first, per surface: a **secret** write from `reserved` re-checks the fresh name list from this converge attempt (name appeared since → conflict refusal, reservation released); a **variable** write from `reserved` goes through POST-create, whose failure-on-existing *is* the absence check. From `dispatched`, retries may overwrite (secret PUT; variable PUT-update on a POST that reports existing — the plausible cause is our own landed write), because the request may genuinely have landed.
3. **Confirm** — transactionally with the terminal OUTCOME, `dispatched` becomes `owned` (or is released on a refused/failed write that provably did not land).
4. **Indeterminate** — an OUTCOME-transaction failure after the provider call leaves the row `dispatched` with an INTENT and no OUTCOME: exactly the reconciliation case the threat model names. The next converge treats `dispatched` rows as *presumed written* — it may overwrite and confirm them, never disowns them — and the reconciliation path is a re-converge, which is idempotent.

The prune set is `owned ∪ dispatched` minus the current desired set, per surface — never bare `reserved` rows, which claim nothing at the provider — and pruning is **strictly ledger-bounded: a `(surface, name)` the ledger does not hold is never deleted, ever**, regardless of how Wenv-shaped it looks. The ledger needs nothing from the provider beyond the secret-surface name list; the variable surface is never read at all (§ The seam).

**Accepted residual, stated not hidden: the dispatch window cannot be closed on this provider API.** Forgejo offers no conditional write for secrets (PUT is unconditional create-or-update, values are unreadable) and no compare-and-swap anywhere, so "check absent, then write" is irreducibly two steps: a third party creating the name between the `dispatched` commit and the request — or between the secret name-list re-check and the PUT — is captured on the (re)try, and no read can afterwards distinguish that from Wenv's own landed write. The bounds are stated honestly, including the one that is not small: in the common case the window is the process-local gap between the `dispatched` commit and the next HTTP call — milliseconds — but **a crash in that gap leaves the row `dispatched` with an INTENT and no OUTCOME for as long as reconciliation takes to run, and the reconciling converge *is* the retry that would capture a third-party name created meanwhile**; the lease single-flights Wenv's own writes and bounds nothing a third party does. What remains true regardless: variables don't share the window on first write (POST-create *is* atomic check-and-create — theirs exists only on retry-after-dispatch), every entry into it leaves a durable INTENT, and the exposure is per-name, single-flight, on a destination the adapter's authority principal was already authorized to overwrite wholesale. Eliminating it requires a provider-side conditional write, which is a Forgejo feature request, not an Wenv design choice.

### Conflict and adoption

**A manifest name that already exists at the provider but is absent from the ledger is a conflict, refused deterministically** — `Plan` and `Sync` fail that name as `exists, unowned`. Silent overwrite would capture a name some other process or team hand-maintains; the Kubernetes ADR refused exactly this shape (created, never adopted), and the refusal transfers.

But here, unlike a fresh Kubernetes Secret, **onboarding an existing repository means every name conflicts** — the common first run is a repo whose secrets were hand-pasted, being brought under management. Hard refusal with no path forward forces the user to hand-delete every provider secret first, which is silent-overwrite-by-hand with extra steps. So:

**Adoption is explicit, per target, enumerated, reauthenticated, audited — and bound to what was actually seen.** The actor acknowledges adoption of an enumerated `(surface, name)` list on that target — an action carrying the full mutation formula (`manage-adapters(project)` ∧ `reveal(E)` + reauthentication, since adoption widens what Wenv manages and will overwrite at the destination). **The acknowledgement is bound to a producing conflict artifact, the target generation, and the destination id, and the commit revalidates all three** — a stale acknowledgement (the target was re-pointed, the config mutated, the repo transferred since the observation) is refused rather than replayed, because "adopt what I saw" must not become "adopt whatever is there now". **A conflict artifact comes from either place a conflict can actually be observed, since the two surfaces observe differently:** the **secret** surface's artifact is a `Plan` (its name list shows the conflict pre-write); the **variable** surface cannot be planned against the provider — the adapter never reads it — so its artifact is the **recorded sync conflict**: a POST-create that failed on an existing name durably records `(surface, name, destination id, target generation, job id)` as a conflict finding in the target's sync status, and `adopt` accepts exactly those recorded pairs. Same binding, same revalidation, zero value read-back either way. **Acknowledged pairs enter the ledger directly as `owned`**, transactionally with the adopt commit and its audit event — not as reservations, whose transitions prove *absence*, which an adopted name by definition fails. Adoption *is* the overwrite authority: a reauthenticated human decision, bound to the observation artifact, to bring an existing provider name under management. The next converge PUTs them like any owned name. There is no adopt-all flag that outlives the enumeration, and a later conflict on a new name is a new refusal.

Cross-project and cross-org collisions land on the global uniqueness constraint with no special case — **the constraint covers every ledger insert, `reserved` rows and adoption's direct-`owned` rows alike**: whoever claims `(origin, destination id, surface, name)` first holds it; the second claim fails tenant-safe. The race two ledgers could not see — both observe the name as available, both write, both record ownership — cannot happen, because the claim precedes the provider write on every path and the constraint is instance-wide. (Configure-time destination rules make collisions rare — § Targets — but the constraint is the backstop that makes them safe.)

### The sentinel — a signpost, not a lock

**On a target's first sync, the adapter writes one sentinel name to both provider surfaces: `MANAGED_BY_WENV` as an Actions variable and as an Actions secret** (per-target prefix applied like any other name — § Multi-environment). Two surfaces because Forgejo's secrets and variables are separate namespaces with separate settings pages, and the human about to hand-add a secret is looking only at the secrets list.

- **The variable's value is a breadcrumb** — instance URL, org/project/environment, adapter id — readable by design: the person staring at Forgejo learns *where* this repository is managed, not merely *that* it is.
- **The secret's value is the same breadcrumb**, unreadable by the provider's own rules; it exists to occupy the name slot in the secrets list.
- Sentinels are **ledger-owned**: created first on first sync, pruned on teardown like any owned name.
- **`MANAGED_BY_WENV` is a reserved name**: an Wenv key whose effective name would collide with a target's sentinel is refused by name at declaration-time validation against configured targets, and at `Plan`/`Sync` unconditionally.

Stated honestly: Forgejo offers no mechanism to *prevent* manual additions. The sentinel is discoverability — it converts "why is this secret wrong" into "this repo is managed at that URL" — and the conflict refusal (not the sentinel) is what keeps manual additions from being silently captured.

## Targets — connection plus targets, explicit key subsets

**An adapter (project-owned) = provider type + Forgejo base URL + one write-only outbound credential.** Under it, **targets**: each target = **one environment → one destination** (repository or organization) + per-target state — enumerated key subset, optional name prefix, adoption acknowledgements, ownership ledger, sync status. Converge, trigger, status, and audit correlation are all per target. #15's authority principal and atomic reassignment ride on the adapter as the durable configuration; every routing mutation — destination, credential, environment selection, **key-set widening**, prefix change — reassigns authority to the acting principal under the full formula.

**Destination granularity: repository-level and organization-level Actions secrets/variables, both in v1.** The API shape is identical (`/repos/{owner}/{repo}/actions/…` vs `/orgs/{org}/actions/…`); org-level covers the shared-credential pattern (registry credentials) that otherwise gets hand-pasted into every repo. An org-level destination is a **wide destination** — every repository in the Forgejo org can read what lands there — and the configure flow says so; under #15 the width is a routing fact carried by the authority rules, not a separate permission. User-level secrets are not a v1 destination (no use case names them; the surface is additive later).

**Org-target status is a storage-level claim, and the ADR says exactly that.** Forgejo resolves a workflow's secrets and variables owner-first, repository-second — **a repository-level entry of the same name shadows the org-level one** (verified in v16 source, both surfaces). Wenv writes and observes only the org namespace, so `converged@revN` on an org target means *the last converge of the org-level store to revision N was acknowledged* — it cannot and does not claim what any given workflow received: a stale or hostile repo-level shadow wins silently and invisibly, and provider-side drift after the converge is undetectable by design (§ One-way). The docs state this beside the org-target instructions in those words. *Rejected: repo fan-out shadow detection* — enumerating every repository's secret list per converge is an unbounded read that still races the next repo-level write; a detection that can be stale the moment it completes must not upgrade the status claim it exists to qualify. The sentinel breadcrumb is the human-facing mitigation: the person debugging "wrong value in CI" finds `MANAGED_BY_WENV` at the org level and knows to check for repo-level shadows.

**Key scope is an explicit subset, bound by immutable key ids.** Target membership enumerates key ids — the Compose ADR's rule verbatim: ids, so renames follow automatically; folders are adopt-time convenience only and are **never** live-resolved into membership. A CI repository rarely needs the whole environment, and a whole-env default would park the production database password in every wired repo as standing remote state. **Widening the subset is a routing mutation** (more plaintext to the destination): authority reassignment + full formula + reauthentication. **Narrowing stays plain** (`manage-adapters` alone) per #15's symmetric limit — requiring `reveal` to shrink a blast radius would be a self-inflicted incident-response delay. The configure flow may offer "select all current keys" as an affordance, but it is an act of enumeration — the ids are copied into membership at that moment; nothing binds to "all" as a living set.

*Rejected: live `all`/folder-bound membership.* Every later key addition would silently widen what lands remote without the widening formula ever firing — the Compose ADR killed live folder resolution for delivery targets on exactly this shape, and the disclosure stakes are higher here (the destination is off-box and standing).

**A targeted key's name and classification are pinned — the definitions edit is refused, not silently propagated.** Id-bound membership makes renames *follow automatically*, and that is precisely the hole: a key's effective name selects its remote slot, and its classification selects the provider surface, so **renaming or reclassifying a targeted key changes where plaintext goes** — a routing mutation in #15's exact sense — executed by a definitions editor holding neither `manage-adapters` nor `reveal`, under an authority principal who approved a different routing. Disclosure-by-proxy through someone else's standing authority. Two repair shapes exist: make the definitions edit carry the adapter mutation formula (couples `definitions-edit` to adapter grants and fires reauth from inside an unrelated flow), or **refuse the edit while the key is targeted** — this ADR picks refusal. Renaming or reclassifying a key that is a member of any adapter target is **refused by name, listing the adapters and targets that pin it**; the supported flow is *narrow* (remove from targets — plain capability, converge prunes the old slot) → edit → *re-add* (widening — full formula + reauthentication + authority reassignment). The widening formula fires exactly where the routing actually changes, held by someone entitled to route. Deletion of a targeted key needs no pin: it is a narrowing, and the next converge prunes its slot. This is a constraint this ADR adds on top of the schema ADR's edit rules (an *extension*, not an amendment — #12 never promised unconditional rename), and the definitions-edit error surface must carry it (propagation to #31).

**Destination collision rule: within a project, effective name sets on one destination must be disjoint, checked at configure time.** Keys are defined once per project, so two environments share the *same canonical names* by construction — two unprefixed targets from env A and env B into one repository is guaranteed total collision. The rule is stated on effective (post-prefix) names: same destination + same effective name reachable from two targets → configure-time refusal, not a `Plan` surprise. Two unprefixed targets on one destination collide trivially (both claim every shared name, sentinel included) and are therefore refused; distinct prefixes make the sets disjoint and are the supported multi-environment shape (§ next).

## Multi-environment delivery into a flat namespace

Forgejo has no equivalent of GitHub's "environments": a repository's secret store is one flat, case-insensitive namespace. The common CI topology — one repo building dev, stage, prod — therefore cannot be served by canonical names alone.

**The per-target structural name prefix.** A target carries one optional `name_prefix` (e.g. `PROD_`, `STG_`), applied uniformly to **every** name the target writes — keys and sentinel alike. The effective name is `prefix + canonical name`, validated whole against the provider grammar. This is deliberately **not** a per-key rename table: one structural transform per target, deterministic, with zero mapping state to drift. The refusal rules (§ Forgejo mapping) evaluate effective names; the ledger stores effective names.

**The canonical-name invariant.** The prefix exists **only in the provider namespace**. The running process — CI step, deployed app, local dev — always sees canonical key names: `process.env.DATABASE_URL`, never `process.env.PROD_DATABASE_URL`. The strip is explicit in the user's workflow, where Forgejo requires explicit wiring anyway:

```yaml
env:
  DATABASE_URL: ${{ secrets.PROD_DATABASE_URL }}
  LOG_LEVEL:    ${{ vars.PROD_LOG_LEVEL }}
```

The documentation carries this loudly at target-configuration time: **wiring a prefixed target means adapting workflows.** The parity note is stated beside it: `wenv run`, rendered env files, and the Kubernetes operator all deliver canonical names, so the application itself never branches on environment — only the workflow wiring does. So thirty keys are not hand-typed, **`adapter target show --format workflow` emits exactly that mapping block** — names only, no values, ordinary stdout under #25's per-verb-format rule.

**Preview environments: one shared `preview` environment, and per-PR uniqueness is CI's job.** The recommended modeling is a single Wenv environment (e.g. `preview`) pushed under a `PREVIEW_` prefix like any static environment; every preview-n deployment consumes the same set. Values that differ per PR — the preview URL, the PR number — are CI-computed and never Wenv-managed. This is guidance, not enforcement: environments stay user-defined.

**Where push structurally cannot work, the answer is federation-fetch, and the ADR says so as positioning, not apology.** Adapter push is static bootstrap delivery: standing secrets for repositories whose workflows need them at workflow start. Ephemeral per-PR environments with genuinely distinct values — an environment born and dying per pull request — can never be served by static adapter configuration. The first-class path is the machine-identity ADR's Forgejo OIDC federation, shipped in v1: the CI job presents its ID token and fetches resolved values at runtime, with zero standing secrets at the provider at all. The documentation presents the two as a gradient — *if your job can fetch, federate; push what must exist before the first fetch* — and the Forgejo adapter's own docs open with that sentence.

## The Forgejo adapter, concretely

**API surface: Forgejo REST v1.**

| Operation | Endpoint (repo-level; org twin under `/orgs/{org}/…`) |
|---|---|
| write secret | `PUT /repos/{owner}/{repo}/actions/secrets/{name}` (body `{"data": …}`, 201 create / 204 update — one create-or-update verb) |
| delete secret | `DELETE /repos/{owner}/{repo}/actions/secrets/{name}` |
| list secret names | `GET /repos/{owner}/{repo}/actions/secrets` (names + timestamps, never values) |
| create variable | `POST /repos/{owner}/{repo}/actions/variables/{name}` (body `{"value": …}`) — **fails if the name exists**; that failure *is* the variable-surface conflict signal |
| update variable | `PUT /repos/{owner}/{repo}/actions/variables/{name}` — **only ever issued for ledger-owned names**; returns not-found on an absent name (then re-converge creates) |
| read/list variables | **never called.** Forgejo's variable GET/list responses carry the stored values (§ The seam); these endpoints do not exist to this adapter |
| delete variable | `DELETE /repos/{owner}/{repo}/actions/variables/{name}` |

The POST/PUT split is not API trivia — it is the enforcement of ownership on a surface the adapter refuses to read: POST-create for names the ledger does not own (an existing name fails the create → deterministic `exists, unowned` refusal with zero read-back), PUT-update only for names it does. The secret surface needs no such split because its list endpoint is safe (names only) and its PUT is create-or-update against a plan that already saw the name list.

**The value transits plaintext inside TLS, and the ADR says so.** Unlike GitHub's client-side libsodium sealed box, Forgejo receives the value in the request body and encrypts server-side. The protections are the TLS channel and the provider's own at-rest encryption — which is exactly the boundary #8 already draws (server→provider over verified TLS, provider is an attacker class whose responses are untrusted input). No pretense of end-to-end encryption to the runner is made anywhere in docs.

**Classification maps to the provider's own split: `secret` → Actions secret, `config` → Actions variable.** The secret/config distinction is the product's core thread, and Forgejo happens to draw the same line (encrypted write-only store vs readable store). CI reads `${{ secrets.X }}` and `${{ vars.X }}` respectively. One manifest, one converge, one authorization formula — the trigger formula already carries `reveal(E)` regardless of the mix, because the manifest is assembled from the same delivery pipeline.

*Rejected: secrets-only sync.* Halves the value — users regress to hand-maintaining variables beside the adapter. *Rejected: everything-as-secrets.* Hides config from CI logs/UI for no gain and contradicts the classification the whole product carries.

**Naming: identity mapping plus the structural prefix, refuse-by-name for everything else — and identity means Forgejo must be able to store the name unchanged.**

- Effective name = `name_prefix + canonical key name`, no other transform, no per-key rename table.
- **Forgejo stores names uppercase** (verified in v16 source: secret and variable names are upper-cased before storage). Identity mapping therefore requires the effective name to *already be* uppercase: **a non-uppercase effective name is refused by name**, never silently upper-cased — the Compose ADR's byte-exactness posture applied to names, and it makes case-collision analysis trivial (all stored names are uppercase; two effective names that collide case-insensitively are refused at configure/`Plan` as one named error).
- Shared grammar (verified against current docs and v16 source, re-pinned at implementation): alphanumeric + underscore, must not begin with a digit, must not start with the reserved prefixes **`FORGEJO_`, `GITHUB_`, `GITEA_`**.
- **The refusal grammars are per surface, because Forgejo's are**: the name `CI` is banned for **variables** (Forgejo's variable validator enforces it; the secret validator does not). So a `config` key whose effective name is `CI` is refused by name; a `secret` key named `CI` is legal and delivered. Encoding the provider's real rules beats a tidier uniform ban that wrongly refuses a valid secret.
- **Values containing `\r` are refused by name — both surfaces.** Forgejo's API contract normalizes line endings to LF on secrets and variables alike; a value with interior CRLF would come back changed after a "successful" sync, which is the silent transformation the schema ADR's byte-exact delivery rule forbids. Same pattern as the Compose ADR's unrepresentable-value refusals: named key, stated reason, no hidden base64 costume (an encoding scheme would be a consumption-semantics change smuggled in as transport).
- `MANAGED_BY_WENV` (effective, i.e. post-prefix) is reserved per target and per surface (§ Sentinel).

In practice refusals are rare: Wenv key names are already env-var-shaped for the `execve` delivery path, and secret values with CRLF are unusual. But rare is not never, and the failure is a named refusal, not a mystery.

**Version floor: the earliest Forgejo release shipping both Actions secrets *and* variables CRUD — v1.21 by current documentation, with the exact release pinned during implementation against the Forgejo changelog.** `TestConnection` and the configure flow probe the API and **refuse below the floor by name** ("this Forgejo lacks the variables API; adapter requires ≥ v1.21") — the Compose ADR's 2.30-floor/doctor-refusal pattern transferred. No degraded secrets-only mode for older instances: a capability split that varies silently by provider version is the kind of surprise this project refuses by charter.

**Outbound credential: a scoped Forgejo personal access token, and nothing else in v1.** Docs prescribe the minimal scope set (write on the destination's secrets/variables administration surface; exact scope names pinned at implementation against Forgejo's token-scope taxonomy). No OAuth application flow, no basic auth. At rest it is envelope-encrypted like every protected asset (#8); through the API it is **write-only**: `adapter credential set` replaces, list/show return redacted presence and metadata only, nothing ever returns the value, and recovering a lost token is Forgejo's problem, not Wenv's (#15, restated as the adapter's concrete behaviour).

**Egress posture: #8's bounds restated as the adapter's concrete behaviour.** HTTPS only; default-deny of all non-global and special-use destination ranges (loopback, link-local/metadata, RFC1918, IPv6 ULA, CGNAT, multicast/reserved) with exceptions grantable only by the **instance operator** at deployment configuration — never by tenants or org admins (the homelab case — a Forgejo on RFC1918 — is exactly this operator-level exception, made deliberately); DNS-rebinding-safe resolution validating the dialed IP; configured proxies either enforce the same policy or are refused for adapter traffic; **no redirect following** on any adapter request; response-size caps; provider responses treated as untrusted input; provider error bodies sanitized before logging and **never echoed with secret material** — the write path's request body is never included in any error, log, or audit payload.

## One-way, value-blind — and honest about it

**Push only. No value read-back, ever — structurally, not by policy.** The asymmetry temptation is real: variable values *are* readable, so the adapter could value-diff the config half while name-checking the secret half. Refused twice over. First, the honesty argument: it yields an "in sync" claim that is true for exactly the half that does not matter and unverifiable for the half that does. Second, the disclosure argument that R1 review sharpened into structure: Forgejo's variable read endpoints return stored values, so *any* variable read pulls third-party provider values into Wenv's buffers under a plain-capability verb — the adapter therefore has **no variable read path at all** (§ The seam), and the secret surface's only read is a names-and-timestamps list. One uniform, honest statement: **provider-side value drift is undetectable; the remedy is converge — idempotent, always safe.** `Plan` shows name-level drift on demand (secret surface: provider list vs ledger vs manifest; variable surface: ledger vs manifest, conflicts surfacing at sync); the docs state the limit in those words; and the declined scheduled reconcile does not reappear wearing a drift-detection costume.

Wenv remains the source of truth per the source-of-truth ADR: nothing an adapter observes at a provider ever flows back into values, and a provider is never a candidate source.

## Teardown — scrub by default, orphan by choice

**Deleting an adapter, removing a target, or unmapping its environment enqueues a final converge-to-empty: prune every ledger-owned effective name, sentinels last.** Deletion stays under plain `manage-adapters` per #15's symmetric limit — destructive, not disclosing — and the scrub job runs under the recorded authority principal like any converge, with the per-step re-check applying to its provider writes.

- **`--keep-remote` orphans instead**: ledger-owned names are left in place and **loudly enumerated by name** in the command output and audit record; the ledger rows are marked released (the names return to unowned — a future target must adopt them explicitly). The legit case: handing management back to humans without a delivery gap.
- **A dead credential cannot scrub.** If the outbound credential no longer authenticates, teardown completes Wenv-side with a terminal warning enumerating the orphaned names. The Kubernetes ADR's operational rule transfers verbatim: **remove targets while the credential still authenticates — revoking the credential first strands remote state**, because a dead credential can never make the contact that cleanup requires.
- Narrowing — a key leaving the subset, an environment's key deleted — is ordinary converge pruning, no special case.

## Authorization formulas — one interpretation, no amendment

#15's table gates **configure, widen, trigger** on `manage-adapters(project)` ∧ `reveal(E)` for every synced environment + reauthentication, and leaves delete/narrow/list plain. This ADR slots its operations into that table without amending it:

| Operation | Formula |
|---|---|
| `adapter create` / `update` (routing mutation) / `target add` / subset **widen** / prefix change / `credential set` | full formula + reauth; atomic authority reassignment |
| `adopt` (acknowledged adoption) | full formula + reauth — widening what Wenv manages and will overwrite |
| `sync` (manual trigger) | full formula + reauth (#15 verbatim: trigger) |
| on-publish converge | standing delegation under recorded authority, re-checked per push — no new grant |
| `plan`, `test`, `show`, `list`, `target list` | `manage-adapters(project)` alone — disclose nothing, push nothing, mutate nothing |
| `delete`, `target remove`, subset **narrow**, credential **revoke** | `manage-adapters(project)` alone (#15's symmetric limit) |

The one point needing stating rather than citing: **`plan` and `test` make outbound provider calls under the adapter credential but carry no secret material and mutate nothing** — they are reads of the provider's name list. They sit with `list` on #15's plain side. This is an interpretation within #15's stated split (disclosing/routing vs destructive/observing), not a widening of it.

## Audit events — final spellings (delegated here by #24)

Category `adapter`, closed action set for v1, all through the outbox linkage where a job exists (`correlation_id` = outbox job id per #24):

| `category.action` | outcome values | notes |
|---|---|---|
| `adapter.configure` | success/denied/failure | create, update, target add/remove, prefix or subset change; payload names the mutation class; routing mutations record the authority reassignment (old → new principal) |
| `adapter.credential_replace` | success/denied/failure | never any token material, prior or new |
| `adapter.credential_revoke` | success/denied/failure | custody destroyed; queued/running jobs fail their next provider call terminally |
| `adapter.adopt` | success/denied/failure | the enumerated adopted `(surface, name)` pairs, the conflict-artifact id (plan id or recorded sync-conflict id), target generation |
| `adapter.inspect` | success/denied | `show`/`list`/`target list` — formula is `manage-adapters`, not bare `read`, so #24's `audited: none` permit is structurally unavailable |
| `adapter.plan` | success/denied/failure | provider contact (secret-name list) under the adapter credential; names and dispositions in payload |
| `adapter.test` | success/denied/failure | connection + destination-identity + floor probe |
| `adapter.sync_requested` | success/denied | the trigger itself, with origin (manual vs on-publish); distinct from the pushes it enqueues |
| `adapter.push_intent` | intent | durable before **each provider write request** (value writes and prunes alike) |
| `adapter.push_outcome` | success/failure/unknown | terminal per provider write request; `unknown` reserved for indeterminate external fate (#24's registry restriction) |
| `adapter.key_delivered` | success | **one immutable event per key whose value was written**, per #15's per-key cardinality — the converge's OUTCOME correlates these, it never replaces them (no "pushed 40 secrets", ever) |
| `adapter.abort` | failure | mid-job authorization loss or generation fence stop: which conjunct failed, never which grants exist (#24's non-enumeration rule) |
| `adapter.scrub` | success/failure | teardown converge-to-empty; `--keep-remote` records the orphaned `(surface, name)` pairs instead |
| `adapter.superseded` | success | job N marked terminal because N+1 enqueued; bookkeeping event, no external effect |

Sentinel writes and prunes are ordinary provider requests within their converge (no distinct action). Refused and pruned names ride in the correlated OUTCOME payloads as `(surface, effective name, disposition)` — **names and dispositions only, never values**; delivered keys get their per-key events. #24's envelope (actor/authority split, scope chain, IP+UA, `origin: adapter-job`) applies unchanged; these spellings complete the delegation, and the actions beyond #24's illustrative list exist because #24's own default-deny completeness rule demands events for every operation this ADR introduces whose formula exceeds bare `read` — compliance with the registry mechanism, not amendment of it.

## CLI verbs — joining #25's closed taxonomy at its declared join point

Spellings only; grammar (context resolution, output classes, artifact eligibility) is #25's, unchanged. All verbs are human-session verbs: the formulas carry reauthentication where they carry it, and #15 keeps `manage-*` off every machine allowlist, so no adapter verb is reachable by a machine credential.

```
wenv adapter create | list | show | update | delete [--keep-remote]
wenv adapter credential set | revoke         # set: write-only replace, no get exists;
                                                 # revoke: destroys custody — running jobs fail
                                                 # their next provider call; scrub becomes
                                                 # impossible (remove targets first)
wenv adapter target add | remove | list
wenv adapter target show [--format workflow] # names-only mapping snippet
wenv adapter adopt --target <t> <NAME>…      # acknowledged adoption, enumerated, artifact-bound
wenv adapter plan [--target <t>]             # value-blind; names and dispositions
wenv adapter sync [--target <t>]             # manual trigger
wenv adapter test                            # connection + destination-id + floor probe
```

Every output in this family is names, dispositions, statuses, and timestamps — never values — so all of it is ordinary stdout with `-o json` additive per #25; the print-triad is never involved. `adapter show` includes per-target sync status (`converged@revN` / `converging` / `failed` + failing names, plus recorded variable-surface conflict findings awaiting adoption) and redacted credential metadata.

## Reconciliation with upstream ADRs

- **Threat model (#8)** — trust boundary, SSRF posture, INTENT/OUTCOME, retry-with-dedup: adopted as written; § Forgejo restates the egress bounds as concrete adapter behaviour.
- **Permission ADR (#15)** — formulas, authority principal, atomic reassignment, per-push re-check, write-only credentials: adopted as written; § Authorization adds one interpretation (plan/test are plain-side), no amendment.
- **Machine identities (#17)** — federation-fetch positioned as the first-class path for ephemeral/per-env consumption; the adapter never mints or holds Wenv credentials, only the outbound provider token.
- **Compose ADR (#18)** — id-bound target membership, refuse-by-name byte-exactness (extended from values to names), floor-and-refuse version posture: patterns transferred and cited.
- **Kubernetes ADR (#19)** — created-never-adopted transferred with one declared divergence: **an explicit, enumerated, reauthenticated adoption path exists here** because onboarding an existing repo makes conflict the common case, not the exception; the dead-credential operational rule transfers verbatim.
- **Architecture (#22)** — outbox machinery consumed as fixed; no new job kinds beyond the adapter converge and scrub.
- **Audit (#24)** — § Audit events completes the delegated spellings under the registry's own completeness rule.
- **API/CLI (#25)** — § CLI verbs joins the taxonomy at the declared join point; spellings only.
- **Source of truth (#13)** — one-way push preserves DB authority; a provider is never a source.
- **Schema ADR (#12)** — byte-exact delivery honoured by refusing what Forgejo would transform (`\r` values, non-uppercase names) rather than transforming to fit; **extended, not amended**: a targeted key's name and classification are pinned (edit refused by name while targeted) — #12 never promised unconditional rename, and the pin routes the real routing change through #15's widening formula.

## Propagations (binding on downstream tickets)

- **Workload-integration prototype ([#31](https://github.com/Dunky13/wenv/issues/31))** — MUST render: target configuration with prefix + explicit key-subset selection (enumeration affordance, no live-all), the conflicting-names adoption flow (artifact-bound acknowledgement, both surfaces' artifact kinds), per-target sync status with failing names and the org-target storage-level qualifier, redacted credential display, the workflow-snippet affordance, and **the pinned-key refusal surface** — a definitions editor renaming/reclassifying a targeted key sees which adapters and targets pin it and the narrow→edit→re-add path.
- **Operations spec ([#32](https://github.com/Dunky13/wenv/issues/32))** — retry/backoff curve and attempt bounds for converge jobs, outbox queue depth and concurrency for adapter jobs, provider response-size caps, ledger growth bounds, breadcrumb field format, and the documented Forgejo minimal-scope token recipe.
- **MVP boundary ([#26](https://github.com/Dunky13/wenv/issues/26))** — confirm in/out: second adapter (GitHub/GitLab), user-level destinations, adapter marketplace/dynamic plugins (presumptively out), value-drift detection (out by this ADR's argument unless redrawn).
- **Synthesis ([#27](https://github.com/Dunky13/wenv/issues/27))** — this ADR is the integration-spec input for the deployment-module chapter; the federation-vs-push gradient sentence belongs in the product docs' delivery overview.

## Deferred (recorded, not dropped)

- **Second reference adapter** (GitHub Actions: sealed-box write path; GitLab: CI variables API) — the seam's neutrality is asserted against them but only proven by building one; MVP-boundary decision.
- **User-level Forgejo destinations** — additive if a use case names itself.
- **Provider-side drift signal** (e.g. comparing variable values, webhook-driven conflict detection) — declined in v1 by the uniform value-blind argument; revisit only with a mechanism that is symmetric across classifications.
- **Adapter-initiated preview-env provisioning** — out of scope; previews are modeled as one shared environment, per-PR uniqueness is CI's.
