# Hikyo inheritance & override model (ADR, locked 2026-07-29)

> **SUPERSEDED IN FULL (2026-08-06) by the flat-model ADR ([flat-model.md](./flat-model.md), [#40](https://github.com/Hikyo-Org/Hikyo/issues/40), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure).** The env-matrix prototype ([#20](https://github.com/Hikyo-Org/Hikyo/issues/20), iteration 31) trialed and adopted a flat no-inheritance model; every value is explicit per environment, presence is `set | absent`. Nothing below is normative: consume this document only through the flat-model ADR's ripple register. Kept as the historical record of the superseded semantics and their rationale.

Context: Hikyo resolves a configuration value for a `(project, environment, key)` from a stack of layers. The domain model ([#7](https://github.com/Hikyo-Org/Hikyo/issues/7)) already fixed the *structures*: a **Key** is defined once per project (name, folder path, `secret|config` classification, schema link); a **Value** attaches to a `(key, layer)` where a layer is either **project defaults** or a **specific environment**; an **Environment** is user-defined per project with an **optional single `base` pointer** to one other environment in the same project; **Folders are organizational only** (no folder-scoped overrides in v1); a **Resolved snapshot** is immutable, materialized per `(project, environment)`, carrying the full key→value map, per-key provenance, and a validation verdict. This ADR fixes the **resolution algorithm** and the **override/safety semantics** on top of those structures.

> **Amended by the schema ADR ([schema-model.md § Newly inheriting a secret](./schema-model.md), 2026-07-30, [#12](https://github.com/Hikyo-Org/Hikyo/issues/12)):** § *Delete vs mask* below is **narrowed**. This ADR reveal-gates the impact *preview* but not the *delivery*, which left a legal exfiltration path: a publisher holding publish-on-dev and no `reveal` removes dev's `masked` entry, and Hikyo delivers a shared prod secret into a dev workload they control. A publish that makes an environment begin delivering a `secret` occurrence **the publisher did not supply** now additionally requires `reveal` on that key (and `reveal-history` where the material is server-reconstructed from a historical revision). Gated on **occurrence identity**, not presence — `set` → different-`set` reroutes are covered too.

**Domain-model amendment (extends #7):** this ADR adds a third **Value presence state**. A `(key, environment)` layer entry is now one of **`set`** (holds a value), **`absent`** (no entry — inherit), or **`masked`** (deliberately unresolved here; blocks inheritance). Project defaults hold only `set`/`absent`. This is the one structural change to #7; #7 is annotated with a pointer to this ADR.

Granularity note: this is the wayfinding-level inheritance ADR. It fixes the layer stack, precedence, cycle stance, concurrency invariant, blast-radius guard, authorization boundary, snapshot atomicity, delete/mask semantics, and bounds. Mechanism-level detail is delegated: required-ness / typing / per-key validation rules → schema-model ticket ([#12](https://github.com/Hikyo-Org/Hikyo/issues/12)); when a snapshot is created and the draft→publish lifecycle → revisions ticket ([#11](https://github.com/Hikyo-Org/Hikyo/issues/11)); the per-capability permission ladder that the authorization rule below consumes → RBAC ticket ([#15](https://github.com/Hikyo-Org/Hikyo/issues/15)); the visual matrix and how provenance/impact/mask are surfaced → matrix-UI prototypes ([#20](https://github.com/Hikyo-Org/Hikyo/issues/20), [#21](https://github.com/Hikyo-Org/Hikyo/issues/21)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## Layer stack (bottom → top precedence)

1. **Project defaults** — built-in bottom layer; any key may hold a `set` default value.
2. **Base chain** — the transitive chain reached by following the target environment's `base` pointer, then that environment's `base` pointer, and so on. Nearer ancestors sit higher.
3. **Environment** — the target environment's own entry sits at the top.

Folders contribute **no** layer (organizational only, per #7). There is exactly one override axis: the environment/base axis.

## Resolution algorithm

For key `K` resolved in environment `E`, walk from the top of the stack downward and **stop at the first decisive entry**:

1. If `E`'s entry for `K` is `set` → that value wins. If it is `masked` → **`K` is unresolved in `E`; stop** (do not walk the base chain).
2. Else (`absent`) walk `E`'s base chain **nearest-ancestor-first** (`E.base`, then `E.base.base`, …). For each ancestor: `set` → its value wins and stop; `masked` → **`K` is unresolved; stop**; `absent` → continue.
3. Else if project defaults holds `set` for `K` → it wins.
4. Else `K` is **unresolved** in `E`.

Strict, total precedence. A `masked` entry is a **floor**: it makes `K` deliberately unresolved for that layer and every descendant that reaches it without an earlier `set`/`masked` of its own — this is how an environment says "this key must not exist here" and how a revocation is expressed (see *Delete vs mask*). **No conditionals, no templating, no computed/derived values, no cross-project references in v1.** Resolution is a pure function of the layer entries in scope; every resolved value is explainable as "came from layer X" (the winning layer), and an unresolved value is explainable as "masked at layer X" or "never set". Provenance recorded per #7 is the identity of the winning/masking layer.

**Termination is not assumed from validation alone (defense in depth):** the walk MUST track visited environments and **fail loud** on a repeat, so a corrupted graph or invariant bug can never cause an infinite walk. Chain length is also bounded (see *Bounds*).

*Rejected:* templating/interpolation and conditional resolution in v1 — they make "why did prod get this value" non-obvious and turn resolution into a mini-language; deferred, not precluded. Cross-project references — out of the single-project override axis; the import story, not the inheritance story.

## Cycle prevention — validated, and concurrency-safe

Each environment's single `base` pointer forms a functional graph (out-degree ≤ 1), which does **not** structurally exclude a cycle (`A.base=B, B.base=A`). Cycles are prevented by **validation at the moment the base is set or changed**: the write walks the prospective chain and is **rejected** if it would make `E` reachable from itself.

**Concurrency invariant (binding):** validation and the base-pointer mutation MUST be a **single serializable operation per project** — either a per-project advisory lock covering the base-graph, or a `SERIALIZABLE` transaction with retry. A naive validate-then-write is forbidden: under MVCC two concurrent edits (`A.base=B` and `B.base=A`) can each read the pre-edit graph, both pass validation, and commit a cycle. Serializing all base-graph mutations per project closes this TOCTOU. Combined with the visited-set check in resolution, acyclicity is enforced at write time and independently guarded at read time.

*Rejected — structural unrepresentability via creation-order constraint* ("base may only point to an environment created earlier"): impossible-by-construction but imposes confusing rigidity (an earlier-created env could never base on a later-created one). Cheap serialized validation is preferred. Decided live by the owner.

## Blast-radius guard — impact preview + authorization + protected flag

Editing a **shared** layer (project defaults, or an environment that is a `base` for others) can change a downstream environment such as `prod`. Three distinct controls apply; they are **not** substitutes for one another (visibility ≠ authorization ≠ classification):

1. **Impact preview (comprehension).** Publishing computes and shows the diff of **every downstream environment the operation actually affects — by value, by provenance, or by topology** — before apply. Provenance-only changes count: re-pointing `prod.base` from `staging-a` to `staging-b` when both currently yield the same `DB_URL` produces no value diff but changes which environment's future edits reach prod, so it MUST appear in the preview. **The preview is subject to reveal authorization, not just publish authorization:** publish permission does not confer secret disclosure. For a **`secret`-classified** key, the preview renders the plaintext value only if the viewer holds **current read/reveal authorization** ([#15](https://github.com/Hikyo-Org/Hikyo/issues/15)), re-checked (with any required reauthentication) **immediately before rendering**, per the threat model's authorize-before-each-disclosure and separate-capability rules ([threat-model.md](./threat-model.md)); otherwise the preview shows only **change status and permitted provenance/topology metadata**, never the value. Without this, a principal who may publish but not reveal could remove an override and read a downstream/protected environment's inherited secret through the preview. `config`-classified keys show values under publish authorization.

2. **Authorization (prevention — binds RBAC [#15](https://github.com/Hikyo-Org/Hikyo/issues/15)).** A publish that alters the resolved snapshot of any environment requires the publisher to hold **publish authorization on every affected environment**, evaluated **immediately before commit** (per the threat model's authorize-before-each-effect rule, [threat-model.md](./threat-model.md)). If the publisher lacks any required downstream grant, the publish is **denied**, not merely previewed. Editing `staging` may not silently publish into `prod` on the strength of `staging` permission alone.

3. **Protected-environment flag (classification).** An environment may be marked **protected**; any publish whose effect reaches a protected environment requires **explicit additional confirmation** on top of authorization. This supplies the reliable "which are production" classification the preview references. *(This reverses the initial 'no flag in v1' lean — Codex cross-review round 1 showed the preview alone cannot identify production or prevent unsafe effects; the owner elected to add both the authorization gate and the flag.)*

**Every resolution-affecting mutation goes through this guard**, not only "layer value edits" — including re-parenting a `base`, changing schema requiredness/validation ([#12](https://github.com/Hikyo-Org/Hikyo/issues/12)), deleting/reclassifying a key, and masking. **Freshness:** a computed preview is bound to the exact layer, base-graph, schema, and authorization revisions it was computed against; if any of those advance before the publisher applies, the preview is **invalidated and recomputed** — a publisher can never apply a blast radius they did not see.

## Publish & snapshot atomicity — the validated unit

`§ Missing-value semantics` below says an invalid snapshot will not materialize; this section fixes **what unit is validated and committed** so mixed generations cannot occur.

- **Snapshots pin their inputs.** A resolved snapshot records the exact **schema revision**, the **layer revisions**, and the **base-graph revision** it was computed from. Its stored validation verdict is immutable **with respect to those pinned inputs** — a later schema or value change cannot retroactively flip a historical snapshot's verdict, and delivery of a pinned snapshot is always "valid against the schema it was built for".
- **Shared publishes are atomic across all affected environments.** A publish that touches a shared layer, the base graph, or a schema **validates and materializes new snapshots for every affected environment in one transaction**. If **any** affected environment would be invalid (an unresolved required key, a failed schema check), the **entire publish aborts** — no environment advances. This prevents "advance `shared`, strand `prod` on a stale snapshot" and "advance valid descendants, leave invalid ones behind".
- **Delivery reads only committed snapshots**, never live layer resolution. A workload fetch resolves to a materialized, pinned, valid snapshot or it fails closed; it never observes a half-applied publish.

## Missing-value semantics — block at publish

A **required** key ([#12](https://github.com/Hikyo-Org/Hikyo/issues/12) owns required-ness) that is **unresolved** in an environment — no `set` in environment/base chain/project defaults, **or masked** at or above it — is an error **at publish time**: per the atomicity rule, the publish that would produce that environment's snapshot **aborts**. Consequences:

- **Save/draft is free** — work-in-progress may hold unresolved/masked required keys; only publishing is gated.
- **Delivery only ever sees valid snapshots** — an invalid snapshot never materializes, so no workload can fetch one. Upholds "validation before delivery" and "fail fast, fail loud": the failure surfaces at publish, to the human, not at deploy time to the workload.

*Rejected: block-at-save* (forbids staging partial work). *Rejected: block-at-delivery* (fails at the worst moment; violates validation-before-delivery).

## Delete vs mask — no silent re-exposure

Removing a value and forbidding a value are **different operations**, because conflating them silently re-exposes inherited secrets:

- **Remove override** sets the `(key, env)` entry to `absent` → the environment falls back to the inherited value. The publish impact-preview surfaces the fallback — the now-inherited value (reveal-gated per *Blast-radius guard*: plaintext only with current reveal authorization for `secret` keys, else status + provenance metadata) and its provenance, and (if it reaches a protected env) demands confirmation — so the fallback is never silent, and never a disclosure back-channel.
- **Mask** sets the entry to `masked` → the key is deliberately unresolved for that environment and its descendants that reach it (see *Resolution algorithm*). This is how "revoke `PAYMENT_KEY` in `prod`" or "`prod` must not carry this key" is expressed. A `masked` required key makes the environment fail publish until explicitly resolved — it cannot silently fall back to a base value.

Deleting a `prod` override therefore no longer silently inherits `staging`'s secret with a passing required-check: the operator chooses *fall back* (preview-surfaced) or *mask* (unresolved, publish-gated) explicitly.

## Bounds (threat model §Availability)

Resolution and impact computation are attacker-triggerable work, so they are bounded: a **maximum base-chain depth** per project, a **maximum environment count** per project, and a **publish-work cap** (affected-environment fan-out) — all enforced with loud errors, values fixed in the operations spec. This keeps a regular user from constructing pathologically deep chains or huge descendant sets to exhaust the server, per the threat model's bounded-work requirement.

## Propagations (binding on downstream tickets)

- **Schema model ([#12](https://github.com/Hikyo-Org/Hikyo/issues/12))** — owns "required"; publish-time validation consumes it, against the *resolved* value, at the pinned schema revision.
- **Revisions ([#11](https://github.com/Hikyo-Org/Hikyo/issues/11))** — MUST provide a publish step carrying the impact preview, the freshness/revision-binding rule, and the atomic multi-environment materialize; shared-layer edits cannot auto-apply.
- **RBAC ([#15](https://github.com/Hikyo-Org/Hikyo/issues/15))** — MUST express per-environment publish authorization and evaluate it against every affected environment immediately before commit; MUST carry the protected-environment flag and its confirmation gate.
- **Matrix-UI prototypes ([#20](https://github.com/Hikyo-Org/Hikyo/issues/20), [#21](https://github.com/Hikyo-Org/Hikyo/issues/21))** — must render per-value provenance (winning/masking layer), the `set`/`absent`/`masked` distinction, and the publish-time impact preview; inheritance is a single environment/base axis, no folder override column.
- **Operations spec (fog)** — fixes the concrete bound values (chain depth, env count, publish fan-out).
