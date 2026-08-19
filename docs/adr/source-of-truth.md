# Wenv source of truth & the role of Git (ADR, locked 2026-07-30)

> **Amended by the flat-model ADR ([flat-model.md](./flat-model.md), 2026-08-06, [#40](https://github.com/Dunky13/wenv/issues/40), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** the definitions bundle drops the per-environment `base` field (closed schema rejects it at parse); `apply` runs no cycle check; plans pin `(bundle digest, schema revision, per-environment value revisions)`; the database-authority sentence covers environment value entries; the reveal escalation reads per that ADR's re-delivery gate. Detail in its ripple register.

Context: Wenv's target user is a self-hosting developer who very likely already runs Flux, Argo, or Renovate and treats a pull request as the review gate for everything else in their stack. The schema ADR ([#12](https://github.com/Dunky13/wenv/issues/12)) already fixed that **the database is authoritative for the schema and a Git file is export, never authority** — because validate-and-materialize must be a single serializable transaction per project, which cannot span a Git repo ([schema-model.md § Authority](./schema-model.md)). It explicitly delegated **schema import and any Git sync** to this ticket, with the standing constraint that any import MUST funnel through the publish pipeline. This ADR fixes the direction of travel between Git and Wenv, the shape and safety boundary of the Git-committed artifact, the conflict and drift rules, and the honest limits of Wenv's GitOps story.

**Refines the schema ADR's export rationale.** [schema-model.md § Authority](./schema-model.md) justified read-only export as satisfying "the real developer desire to review a schema change beside the code that consumes it". Export alone does not satisfy it: a pull request cannot reject a publish that already committed, nothing obliges anyone to export or commit, and byte-stability makes a diff *legible* without making review *load-bearing*. A read-only export is **audit evidence**, not a review gate. This ADR supplies the missing half — an authenticated file→DB write path — so that the reviewability property the schema ADR claimed actually holds.

**Amends the schema ADR (extends #12):** the **value-literal keywords** — `const`, `enum`, `examples` — are **prohibited on `secret` keys**, at any depth, rejected at declaration time. See § *The safety boundary of the bundle*.

Granularity note: this is the wayfinding-level source-of-truth ADR. It fixes authority, direction, the artifact's scope and safety boundary, identity and absence semantics, the plan/apply lifecycle, the Git-governed project mode, drift reporting, and the v1 non-goals. Mechanism-level detail is delegated: the concrete canonical serialization and the full command surface → API & CLI ([#25](https://github.com/Dunky13/wenv/issues/25)); the write-scoped machine credential class → machine identities ([#17](https://github.com/Dunky13/wenv/issues/17)); where `definitions-edit` and `apply` sit on the capability ladder → RBAC ([#15](https://github.com/Dunky13/wenv/issues/15)); plan quotas, expiry, and bundle size bounds → operations spec; Forgejo credentials, branch and pull-request creation, and webhooks → deployment-module seam ([#28](https://github.com/Dunky13/wenv/issues/28)); restart and reconciliation behaviour → Compose ([#18](https://github.com/Dunky13/wenv/issues/18)) and Kubernetes ([#19](https://github.com/Dunky13/wenv/issues/19)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## Authority: the database, always — Git supplies candidates

**The Wenv database is the source of truth** for keys, schema declarations, environment topology, layer values, revisions, and materialized snapshots. Nothing in a Git repository is ever authoritative, and Wenv never reads a repository.

Git participates in exactly one way: a file in a repository may be a **candidate** — a proposed desired state that a human or a CI job submits to Wenv through an authenticated, validated, authorized write. Only a successful publish in the database creates truth. The file is an input to a request, never a source of state.

*Rejected: split authority* (schema in Git, values in the DB) — already ruled out by the schema ADR's serializability argument. *Rejected: bidirectional sync* — a controller continuously reconciling Git against the DB owns merge conflicts on the one artifact that gates every publish, plus a winner-selection rule for the case where both sides moved. That is the SOPS drift problem this ticket exists to avoid. *Rejected: export-only* — concedes the review property, per the refinement note above.

## The definitions bundle

The Git-committed artifact is a **definitions bundle**: a canonical, byte-stable, lossless, versioned serialization of a project's *shape*.

**In scope:**

- **Keys** — name, folder path, `secret|config` classification, immutable key id, deprecation state.
- **Schema declarations** — type, constraints, `any_of` alternatives, JSON Schema documents on `json` keys, presence rules (`required_in` / `forbidden_in` as `{mode, ids}`), key groups.
- **Environment topology** — the environment list, each environment's stable identifier, and its optional single `base` pointer.

**Never in scope:** values of any classification, resolved snapshots, delivery manifests, validation verdicts computed against instances, instance paths, change tokens. A definitions bundle carries no value-derived data whatsoever.

Folders need no separate representation — the domain model makes them organizational only, so a folder path rides on its key.

### The safety boundary — what the bundle guarantees, and what it does not

**The guarantee is: a definitions bundle contains no managed value and no value-derived data.** Nothing Wenv stores as a Value, nothing computed from one, no resolved snapshot, no verdict against an instance, no delivery manifest. That property is structural and total — it holds regardless of who exports, what they are authorized for, and how the project is configured.

**The bundle is not, and cannot be, guaranteed free of secret *text*.** Declarations contain author-supplied free text — key names, descriptions, deprecation notes, `pattern` (which can encode an exact literal as easily as a shape), and JSON Schema documents on `json` keys whose keyword allowlist is still being fixed by the operations spec. A developer who types a live token into a description has put a live token in the bundle, and no structural rule can prevent that without making the bundle lossy, which § *Format requirements* forbids. This is the same exposure as a token pasted into a source comment, and it is managed the same way: **a definitions bundle is documentation-class material and must be treated as public from the moment it is exported.** The UI states this where declarations are authored, and the docs state it beside `definitions export`.

Two rules narrow the gap where the *system's own semantics* invite a value into a declaration:

1. **No values, ever** (above). A bundle containing a managed value is malformed, not permissioned.
2. **The value-literal keywords are prohibited on `secret` keys.** The normative set is exactly **`const`, `enum`, `examples`** — every keyword whose payload *is* a literal instance value. (`default` is not listed because the schema ADR already forbids schema defaults outright; if that is ever reversed, `default` joins this set.) Rejected at declaration time with the fix named ("use `pattern`, or declassify the key"). This is not a general leakage control; it is targeted at the fields where the declaration vocabulary *asks* the author to write down the very values the key holds. The schema ADR already treats a value-dependent rule on a secret key as disclosure territory, reveal-gating changes to one because the pass/fail bit is an extraction oracle; writing the values out is the same disclosure by a slower route.

   The prohibition is **recursive over the whole declaration** of a `secret` key: the key's own constraints, every `any_of` alternative, and every subschema at any depth of a JSON Schema document on that key. `pattern` is deliberately **not** in the set — it is retained as the supported way to express a shape, and § above already states it can carry a literal, which is part of the acknowledged residual risk rather than something this rule claims to prevent.

The consequence is that `definitions export` needs **no permission gate**, because it discloses nothing the exporter could not already read from the declaration surface. It is **not** a licence to skip a secret scanner in CI: scanning the bundle is worthwhile for the same reason scanning source is, and for exactly as long as free text exists in it.

*Rejected: prohibit every literal-bearing declaration field across all classifications* — it would close the remaining channels, but it makes the declaration vocabulary unusable (no descriptions, no patterns, no JSON Schema) and collides with the lossless-bundle requirement. *Rejected: claim Git-safety by construction* — an earlier draft of this ADR made that claim on the strength of rule 2 alone. It was false, and a false safety claim is worse than an acknowledged residual risk, because it is the one that stops people scanning.

*Rejected: allow the rules, gate the export behind `reveal` and stamp the artifact* — makes Git-safety a runtime property the operator must keep true, failing silently until the commit lands. *Rejected: allow the rules, redact them on export* — actively unsafe under the desired-state semantics below: a redacted `enum` is not a hole in the artifact, it is an instruction to delete the rule. Redaction and desired-state cannot coexist.

### Command separation

`definitions export` (shape, commit-intended) and `values export --format dotenv` (managed plaintext, reveal-gated, never commit-intended) are **distinct commands with distinct names**. Two operations both called "export", one routinely committed and one catastrophic to commit, is a command-confusion foot-gun. Direct file output into a detected Git worktree warns; shell redirection cannot be prevented, so command separation and response typing are the primary controls, not path checks.

### Format requirements

Beyond the schema ADR's byte-stable / lossless / versioned requirements, the bundle must be readable as *desired state*, not only writable as a dump:

- **Names are the portable logical handles.** A bundle carrying neither server-owned ids nor a base revision is a valid template that applies cleanly to a fresh instance.
- **Server-owned ids are optional and explicit.** `export` always emits them.
- **An exported bundle records the revision it was exported from**, so drift can be classified (§ *Drift*) and staleness refused (§ *Plan and apply*). A bundle that was never exported — `scaffold` output, a hand-authored template — carries **no base revision**, which makes it an *additive* bundle rather than desired state (§ *Additive bundles*).
- **Making a portable template strips both the server-owned ids and the base revision.** Both are instance-scoped: an id names a row in *that* database, and a base revision names a point in *that* project's history. Carrying either to a second instance is meaningless at best and dangerous at worst — revision identifiers from two projects can compare equal by coincidence, which would let a foreign bundle pass the base-equals-current check in § *Plan and apply* and be applied as authoritative desired state, deleting by omission. Stripping ids without stripping the base is therefore a malformed template, rejected at parse time rather than silently planned. `definitions export --portable` emits the stripped form directly so the operation is one command rather than a hand-edit anyone can get half-right.
- **The format carries an explicit version, and unknown fields are rejected**, loudly, naming the version mismatch. Silently ignoring an unrecognized field lets a newer server's export apply to an older server with fields quietly dropped — under desired-state semantics that is data loss, not forward compatibility.

## Identity and absence

**Matching is a set operation over final state, resolved in a fixed order.** Entry-at-a-time matching is ambiguous: given `id-1` currently named `A`, a bundle holding `{id: id-1, name: B}` *and* `{name: A}` can be read as a rename plus a create, or as two entries both claiming `id-1`, depending on evaluation order. Different implementations would reject, coalesce, overwrite, or create from one file. The algorithm is therefore fixed here:

1. **Id-bearing entries bind first.** Each entry carrying a server-owned id binds to that identity. An id present in the bundle but not found in the database is a **hard error** — a stale file — never a silent create.
2. **Bound identities leave the name-matching pool.** They can no longer be matched by name by any other entry.
3. **Remaining entries match by name**, against unbound identities only.
4. **Entries matching nothing are creates.**
5. **Final state is validated globally before anything executes**: two entries binding the same identity, or two entries resolving to the same final name, are a **hard error** naming both entries.

Renames are consequently evaluated as **one final-state set**, not as a sequence of individual renames — so a swap (`A`→`B`, `B`→`A`, both id-bearing) resolves correctly instead of colliding halfway through. The worked example above resolves deterministically: `id-1` binds and becomes `B`; the entry named `A` finds no unbound identity called `A` and is a create.

Names are the portable handle, so a portable template (ids *and* base revision stripped, per § *Format requirements*) applies cleanly to a fresh instance — every entry is a create — and, applied to the instance it came from, matches by name at step 3 rather than duplicating. Environments follow the same algorithm via their stable identifier: renaming `prod` to `production` must not read as delete-and-create.

**Absence is deletion.** A key or environment present in the database and absent from the bundle is **deleted**. The bundle is desired state, not a patch — this is what allows `check` to report *equal* meaningfully, and it prevents the worse lie where a key deleted in the UI silently reappears on the next apply from an older file.

Two guards make the destructive direction explicit rather than quiet:

- **`apply` refuses any plan containing a deletion unless `--allow-delete` is passed.** The plan renders each deletion concretely ("deletes `STRIPE_KEY`, live in 3 environments").
- **Deleting an environment that holds any live occurrence is refused unconditionally** — no flag overrides it. Dropping an environment discards every value in it; that is not a thing a flag should make quiet. The environment must be emptied explicitly first.

These compose with, and do not replace, the existing protections: the inheritance and revision ADRs already make live **pins** block deletion of the keys they pin.

### Additive bundles

Desired-state semantics require a known base: "absent means delete" is only meaningful relative to the state the author was looking at. Two legitimate bundles have no such base — `scaffold` output, which never contacted a server, and a portable template, which was authored against a *different* instance and therefore has both its ids and its base revision stripped (§ *Format requirements*). Reading either as desired state would delete the target project's entire contents.

A bundle **carrying no base revision is additive**:

- Entries that match nothing are **created**.
- **Omission means nothing.** No deletion is derivable, so `--allow-delete` is meaningless and passing it is an error rather than an escalation.
- **Modifying an existing entry is rejected**, naming the conflict. An additive bundle may not silently overwrite a declaration it was never computed against — that is the reversion hole from § *Plan and apply* arriving by a different door.

An additive bundle therefore applies cleanly to a fresh project (everything is a create) and refuses, loudly and specifically, to guess on a populated one. The route from additive to desired state is one `definitions export`, which stamps the current base; from then on the project is in the normal desired-state loop and deletions become expressible.

## Plan and apply

The write path is a two-step, human-reviewable, non-reconciling transaction:

```
wenv definitions plan  --file wenv.yaml   →  immutable plan id
wenv definitions apply --plan <plan-id>
```

**`plan` refuses a bundle that is not based on current state.** Where the bundle records a base revision (§ *Format requirements*), `plan` rejects unless that base equals the project's current definitions revision, with the fix named ("re-export and rebase"). A bundle carrying **no** base revision is not stale — it is additive, and § *Additive bundles* governs it. Without this rule the pinning below protects only against *concurrent* movement, not *prior* movement, and the destructive sequence is trivial: pipeline applies revision 20; a second job checks out an old tag holding a revision-15 bundle; that bundle plans cleanly against revision 20 because the plan is internally fresh; `--allow-delete` is in the script; everything added between 15 and 20 is deleted. The same hole silently reverts modifications, not just deletions — a stale `pattern` overwrites a newer one with no signal. Requiring base-equals-current is the same non-fast-forward refusal Git itself makes, and it needs no override flag: an intentional rollback is expressed by exporting current state and reverting the *content* in the repository, which produces a bundle with a current base and old content.

**`plan`** then parses the bundle, diffs it against current state, and produces an **immutable plan** pinning the file's canonical digest together with the schema revision, the layer revisions, and the base-graph revision it was computed against. It returns the impact preview the inheritance ADR already requires — reveal-gated identically, so a CI identity without `reveal` sees status and provenance rather than plaintext.

**`apply`** re-checks every pin. If the file digest or any pinned revision moved, the apply is **rejected** with a re-plan instruction. There is no auto-merge, no winner selection, no retry loop, no polling, and no watcher: the user rebases by re-exporting current state and regenerating the plan. This is the whole of the conflict-handling design, and it is sufficient precisely because the concurrency invariants are already locked elsewhere — publish is serializable per project, stale versions are rejected on freshness, and every affected environment gets preview, authorization, validation, and atomic materialization.

**`apply` is a publish, not a second path into the data.** It runs the same pipeline with a file as input instead of the UI: same serialization, same cycle check, same atomic multi-environment materialization, same per-affected-environment publish authorization evaluated immediately before commit. A plan is **not** an authorization grant — authorization is evaluated at apply time against the applier.

**Reveal escalation is inherited, not waived.** Two locked rules reach `apply` unchanged: changing a value-dependent rule on a `secret` key requires `reveal` and is rejected without evaluating it (schema ADR); and a publish that makes an environment begin delivering a `secret` occurrence the publisher did not supply requires `reveal` on that key (inheritance ADR, as amended by the schema ADR) — which a base-pointer edit or a presence-rule change in a bundle can trigger. Consequently such a bundle can only be applied by an identity holding `reveal`. This must not be special-cased away, and the resolution is **not** to give CI `reveal`:

- **The default is a human applier.** A reveal-requiring apply is **routed to a human** holding `reveal`; the CI identity's apply fails with the specific entries that triggered it named. The overwhelming majority of definition changes — adding a key, tightening a `config` constraint, renaming — trigger nothing and flow through CI untouched.
- **Granting `reveal` to a machine identity is an explicit, documented, per-project operator opt-in**, never a default and never implied by granting `apply`. A build runner holding `reveal` is a standing decryption capability sitting in the most-attacked box in the system.
- **`plan` reporting is a usability affordance, not a control.** It tells an honest operator why their apply will fail; it does nothing against a compromised runner, which can simply submit its own plans. The control is not holding the credential there in the first place.

Constraint on RBAC ([#15](https://github.com/Dunky13/wenv/issues/15)) and machine identities ([#17](https://github.com/Dunky13/wenv/issues/17)).

Plan persistence is quota-bounded and expiring; concrete values → operations spec.

## Git-governed projects: `definitions_source`

Every project carries **`definitions_source: db | git`**, defaulting to `db`.

- **`db`** — definitions are edited through the UI, CLI, or API as normal. `export` / `check` / `plan` / `apply` all still work; Git is optional.
- **`git`** — definition writes are accepted **only** through `apply`. The UI renders definitions read-only with a banner pointing at the repository.

**Values are unaffected in both modes.** Values are never in Git, and are always edited through the UI, CLI, or API. A project may therefore be Git-governed for its shape and UI-driven for its contents; that is the expected configuration.

Without this flag, the review property is theatre: every merged pull request races a human editing in the web app, and `check` spends its life reporting *diverged*. `git` mode is one column plus one guard at the definitions-write chokepoint the schema ADR already requires exist.

*Rejected: enforce it purely through RBAC* (revoke `definitions-edit` from humans, grant it to CI). It technically works, but it is a permission configuration nobody discovers, and it cannot render the UI affordance — a well-intentioned human holding the capability gets no signal that the project is Git-governed.

## Onboarding under a closed schema

The schema ADR locked **closed schema, no auto-declare** — the typo catch is the product's wedge. Taken naively that means a new user pointing an import at a forty-key `.env` collects forty rejections in their first five minutes.

The path is an **offline scaffold**, not a relaxation:

```
wenv definitions scaffold --from .env   →  a definitions bundle on stdout
```

`scaffold` is a **pure local transform**. It contacts no server, holds no authority, and reads only the file it is given. Because it never contacted a server it cannot stamp a base revision, so its output is an **additive bundle** (§ *Additive bundles*) — it creates, it cannot delete, and it refuses to modify a declaration it was not computed against. The user reviews the generated bundle, commits it, and applies it; `values import` then runs strict, and every key is already declared. A subsequent `definitions export` stamps the base and moves the project into the normal desired-state loop. The worst moment of onboarding becomes the demonstration of the product's thesis — the user's first act is reviewing a generated schema in a pull request and watching accumulated typos surface as diff lines.

Because it never contacts the server, `scaffold` cannot know classification and must not guess: it emits every key as `config` with an explicit `# TODO: classify` marker and refuses to be silent about it. `values import` remains strict — undeclared keys are rejected — and warns that the source `.env` still sits in plaintext on disk after a successful import.

*Rejected: `values import --declare`* — an opt-in flag does not change what it is. It concedes the closed-schema property on precisely the path where it matters most, since a `.env` accumulated over years is the canonical case for catching typos.

Broader migration sources (Compose files, K8s Secrets, SOPS, Infisical/Phase exports, Vault KV) remain fog; this ADR fixes only that they are **value-bearing imports, never Git-sync**, and that each must funnel through the publish pipeline.

## Drift

Unidirectional flow removes winner-selection; it does not remove drift. Because the bundle records the revision it was exported from, four states are distinguishable: **equal**, **file ahead** (candidate not yet applied), **database ahead** (a UI publish the file has not caught up with), and **diverged** (both moved).

`wenv definitions check --file` reports the state with a CI-shaped exit contract — **`0` equal, `1` differs, `2` error** — so a pipeline can gate on it without parsing output. Wenv reports database-versus-file only; it cannot report repository state, because it cannot see the repository. Invoking `check`, and deciding what a `1` means for a given pipeline, is CI's job.

`check` is the **diagnostic**; the gate is `plan`, which refuses anything but a current base (§ *Plan and apply*). So *database ahead* and *diverged* are states `check` will report and `plan` will reject — the pipeline's remedy in both cases is to re-export and rebase. A `git`-mode project should sit at *equal* or *file ahead* permanently; observing *database ahead* there means a definition write reached the database by some path other than `apply`, which is a defect worth alerting on rather than reconciling.

## Provenance

`apply` accepts optional client-supplied **`commit`**, **`ref`**, and **`actor`** strings, stored as revision metadata and surfaced in the UI and the audit trail. They are length-bounded and sanitized, and are **never trusted, never authoritative, and never an input to any decision** — purely a label. The operator asking "why did production's shape change?" gets "commit `abc1234`, merged by @marc" instead of "the CI token did it".

This is the entire extent of Wenv's Git awareness. The server stores no repository URL, no credentials, and no webhook.

## The GitOps story, stated honestly

Wenv's position is:

> **A GitOps-managed delivery declaration, backed by an external Wenv control plane** — with the project's *shape* additionally reviewable in Git via `definitions_source: git`.

Committing an `WenvSecret` gives Flux or Argo review over the *delivery declaration*. The operator then fetches from Wenv and writes a native Secret independently. That is legitimate and directly comparable to External Secrets Operator, but it is **not** Git-governed configuration, and the documentation must not imply it is. Values are never Git-reviewed, by design — they are secrets.

**Compose has no reconciler at all.** `wenv run` fetches at process start; no merge, and no Wenv publish, causes a Compose service to restart. **No Compose GitOps reconciliation in v1** is an explicit, documented non-goal. Whether anything ever triggers a restart belongs to Compose ([#18](https://github.com/Dunky13/wenv/issues/18)).

Kubernetes field ownership — specifically whether the operator's hash-annotation writes conflict with Flux or Argo ownership, and which ignore rules users must configure — belongs to Kubernetes ([#19](https://github.com/Dunky13/wenv/issues/19)) and must be resolved there, not assumed away here.

## Explicit v1 non-goals

Recorded so they are visibly ruled out rather than merely absent: no continuous Git sync, no polling, no webhooks, no repository watching, no branch or pull-request creation by Wenv, no auto-merge, no automatic conflict resolution, no bidirectional controller, no values in Git, and no Compose GitOps reconciliation.

**A database transaction MUST NOT be coupled to the availability of any Git host.** Forgejo credentials, branch and pull-request creation, merge-status verification, webhooks, and adapter execution are the deployment-module seam's ([#28](https://github.com/Dunky13/wenv/issues/28)) concern; if that adapter later creates pull requests, it does so *outside* the publish transaction.

## Propagations (binding on downstream tickets)

- **Schema model ([#12](https://github.com/Dunky13/wenv/issues/12))** — **amended**: the value-literal keywords **`const`, `enum`, `examples`** are prohibited on `secret` keys at any depth, including inside `any_of` alternatives and every JSON Schema subschema. `pattern` is explicitly excluded from the prohibition. Its export requirements are extended by § *Format requirements*; its "review beside the code" rationale is refined by the note at the head of this ADR. Its JSON Schema keyword allowlist MUST enforce this recursive prohibition on `secret` keys, and MUST re-derive the set if the allowlist later admits another literal-bearing keyword.
- **RBAC ([#15](https://github.com/Dunky13/wenv/issues/15))** — MUST place `definitions-edit` and `apply` on the capability ladder, express the `definitions_source: git` guard at the definitions-write chokepoint, and carry the reveal escalation that `apply` inherits, including that granting `reveal` to a machine identity is a separate explicit act never implied by `apply`.
- **Matrix-UI prototypes ([#20](https://github.com/Dunky13/wenv/issues/20), [#21](https://github.com/Dunky13/wenv/issues/21))** — MUST render the `definitions_source: git` read-only state with its pointer to the repository, and MUST state where declarations are authored that free-text declaration fields are exported to Git and are to be treated as public.
- **Machine identities ([#17](https://github.com/Dunky13/wenv/issues/17))** — a CI applier is a **write-scoped, project-scoped** credential class, distinct from the `(project, environment)`-scoped **read-only** workload token the threat model pins. It must not be smuggled into the workload-token type. Where the applier must hold `reveal`, that is a further, separately-granted escalation.
- **Compose ([#18](https://github.com/Dunky13/wenv/issues/18))** — owns restart/watch semantics; inherits "no Compose GitOps reconciliation in v1" as a stated non-goal, and the stale-offline-snapshot question remains open there.
- **Kubernetes ([#19](https://github.com/Dunky13/wenv/issues/19))** — owns operator field ownership versus Flux/Argo and the required ignore rules.
- **API & CLI ([#25](https://github.com/Dunky13/wenv/issues/25))** — owns the concrete canonical serialization satisfying § *Format requirements* (including how a base revision is represented and how its absence is represented), and the `definitions export | export --portable | check | plan | apply | scaffold` and `values import | export` surface, including the `--allow-delete` and exit-code contracts, the stale-base refusal, the ids-without-base parse rejection, and the additive-bundle refusals.
- **Audit ([#24](https://github.com/Dunky13/wenv/issues/24))** — MUST carry provenance metadata on apply-sourced revisions and event shapes for plan creation, apply, rejected-stale-apply, refused deletion, and refused additive modification.
- **Deployment-module seam ([#28](https://github.com/Dunky13/wenv/issues/28))** — owns all Git-host interaction; bound by the no-coupling rule above.
- **Operations spec (fog)** — plan quotas and expiry, bundle size bounds (entries per bundle, bytes), and `scaffold` input limits.
