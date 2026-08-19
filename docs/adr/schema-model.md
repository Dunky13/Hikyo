# Wenv schema & validation model (ADR, locked 2026-07-30)

> **Amended by the flat-model ADR ([flat-model.md](./flat-model.md), 2026-08-06, [#40](https://github.com/Dunky13/wenv/issues/40), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** the product adopts a flat value model — no inheritance, no project defaults, presence `set | absent`. § *Newly inheriting a secret*'s trigger list, the defaults section's project-defaults sentence, the dormant-occurrence rule, the base-graph serialization half, and every `(…, layer)` tuple in the closure/pending-version/recompute algorithms (now `(…, environment)`) read per that ADR's ripple register. `required_in`/`forbidden_in` and all other semantics stand.

Context: the domain model ([#7](https://github.com/Dunky13/wenv/issues/7)) fixed a **Key** as defined once per project, carrying a name, a folder path, a `secret|config` classification, and a **schema link**. The inheritance ADR ([inheritance-model.md](./inheritance-model.md)) delegated required-ness, typing, and per-key validation rules to this ticket, and fixed *when* validation bites: at **publish**, on the **resolved** value, at the schema revision **pinned** on the snapshot, with a schema change running the impact-preview + per-affected-environment authorization guard and materializing atomically. The revision ADR ([revision-model.md](./revision-model.md)) delegated the same and additionally **required** this ADR to add **key groups** to the v1 vocabulary. This ADR fixes what a project may declare about a configuration entry, what the schema is as an artifact, and what validation does at each moment.

Granularity note: this is the wayfinding-level schema ADR. It fixes the declaration vocabulary, the presence semantics, the schema's own lifecycle and authority, validation timing and error-disclosure rules, and the closed-schema stance. Mechanism-level detail is delegated: the per-capability permission ladder — including where the **schema-edit** capability sits relative to publish and reveal — to RBAC ([#15](https://github.com/Dunky13/wenv/issues/15)); the concrete export format to the API/CLI surface ([#25](https://github.com/Dunky13/wenv/issues/25)); schema import and any Git sync to source-of-truth ([#13](https://github.com/Dunky13/wenv/issues/13)); the visual affordances to the matrix prototypes ([#20](https://github.com/Dunky13/wenv/issues/20), [#21](https://github.com/Dunky13/wenv/issues/21)); event shapes to audit ([#24](https://github.com/Dunky13/wenv/issues/24)); concrete bound values to the operations spec. Each MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

**Amendments to locked ADRs.** This ADR makes three explicit amendments, each stated in full at the section named:
1. **Inheritance ADR** — a publish that makes a `secret` key **newly resolve** in an environment requires `reveal` on that key, narrowing that ADR's permission for an unprivileged publisher to remove a mask (see *Newly inheriting a secret*).
2. **Revision ADR** — the change token's canonical encoding is a **delivery manifest** of `(key, classification, value)` rather than a bare key→value map (see *The change token covers a delivery manifest*).
3. **Revision ADR** — retention and quota bounds extend to **pending-change versions**, which that ADR made immutable-per-edit without bounding (see *Bounds*).

## The schema is the key catalogue — rules inline on the Key

#7's "schema link" resolves to: **there is no separate schema object.** Every constraint is declared **inline on the Key**, and "the project's schema" is the set of its key declarations. Consequently **the schema revision is the key-catalogue revision** — one artifact to pin, one to diff, one to authorize.

The schema is **project-scoped**. There is no org-level or cross-project shared schema in v1.

*Rejected: named reusable type definitions* (`PortNumber = integer 1..65535`, referenced by keys). Within the positioning envelope (≤10k entries, 1–3 orgs, [#3](https://github.com/Dunky13/wenv/issues/3)) the DRY win is small, while it adds a second editable artifact, an indirection to explain in the matrix UI, and a type library nobody curates. Cleanly additive later — keys would gain an optional type reference — so deferred, not precluded.

### Key identity is an immutable id, not the name

A Key has an **immutable id**, allocated at creation and never reused. The **name** is a mutable label on it. Everything that must survive editing — a pending change's target, a historical value's owner, a group membership, a restore target, an audit record — references the **id**.

- **Names are unique among live keys in a project.** A deleted key's name may be reused by a new key; because identity is the id, a restore or a historical diff is never ambiguous about which key it means.
- **Renaming a key changes the delivered payload's key set**, so it is a content-affecting schema change and runs the full guard (see *Schema lifecycle*).
- **Deleting a key invalidates every pending change referencing it**, loud: those pending versions are marked invalid and cannot be published. Without this, Alice's pending edit to key `K` stays publishable after Bob deletes `K`, and the publish resurrects a key the schema no longer declares.

## Declaration vocabulary (v1)

A Key declaration carries:

**Identity and metadata** — immutable id; name; folder path (#7); `secret|config` classification (#7, reclassification rules below); `description` (free text, may hold a URL — no separate docs field); `deprecated` flag with an optional `deprecation_note`.

**Type** — exactly one of six primitives, or an `any_of` union of them:

| Type | Constraints |
| --- | --- |
| `string` | `minLength`, `maxLength`, `pattern` (RE2), `allow_empty` (default `false`) |
| `integer` | `min`, `max` |
| `boolean` | canonical `true` / `false` only |
| `enum` | `members` |
| `url` | `schemes` (allowlist, e.g. `postgres`, `https`) |
| `json` | optional JSON Schema (see *JSON Schema*) |

**Presence** — `required_in` and `forbidden_in` (see *Presence*).

**Coupling** — at most one **key group** membership (see *Key groups*).

Everything Wenv delivers is a **string on the wire**, so a type is a parse-and-reject rule plus a UI affordance, not a storage format.

*Rejected types:* `float`/`number` (nothing in configuration needs float semantics that `string` + `pattern` cannot express), `email`, `duration`, `ip`, `port`, `date` — each is `string` + `pattern` or `integer` + range. Every type costs a validator, a UI affordance, and a documentation entry; these do not clear that bar. Additive later.

### Lexical semantics — one grammar, no implementation latitude

A validator is only as portable as its lexical rules, so they are fixed here rather than left to a library's defaults:

- **Every value is a byte string that MUST be valid UTF-8, and MUST NOT contain a NUL byte.** Both are rejected at write time. NUL is not a fussy restriction: the primary Compose delivery path is an `execve` environment block ([compose-delivery.md](../research/compose-delivery.md)), which cannot carry NUL, so a value Wenv called valid would be undeliverable.
- **`integer`** matches `-?[0-9]+` — no leading `+`, no underscores, no hex, no exponent. Leading zeros are accepted and preserved verbatim on delivery (the value is a string; `01` is not normalized to `1`). Magnitude must fit **signed 64-bit**; anything wider is rejected rather than silently truncated or promoted to a float.
- **`pattern` is anchored to the whole value** — implicitly `\A(?:…)\z`, never a substring search. An unanchored regex that appears to constrain a value while matching a fragment of it is the classic validation bypass, and making anchoring the default removes the entire class.
- **`url`** must parse as an **absolute** URL with a scheme present in `schemes`; relative references and opaque non-hierarchical forms are rejected.
- **`enum` members** must be non-empty and distinct after the write-time trim. A member of `""` is rejected at declaration, because zero-length values are governed solely by `string`'s `allow_empty` and a second path to legal emptiness would contradict it.
- **`json`** must parse as a single JSON document; **duplicate object keys are rejected** rather than last-wins. Numeric values are validated as JSON numbers but delivered as the original bytes.
- **`boolean` accepts only canonical `true`/`false`.** `1`, `yes`, `TRUE` are rejected loud, never coerced. Coercion is a silent normalization, and it would make Wenv's notion of truthiness differ from that of each consuming language, so a value that validated here could still mean the opposite there.
- **`string` permits interior newlines** — certificates, private keys, and `authorized_keys` blocks live here. Note the interaction with the trim rule below: *interior* newlines are data and are preserved; *trailing* ones are removed like any other edge whitespace. This propagates a multiline-editor requirement to the matrix prototypes.

### `any_of` — bounded unions, deliberately not `oneOf`

A key may declare **`any_of`**: a list of alternative type declarations. The value is valid if it satisfies **at least one** alternative. This covers the case the six primitives handle badly — `WORKERS=4` or `WORKERS=auto`, `TIMEOUT=30` or `TIMEOUT=none` — which `string` + `pattern` can only fake, at the cost of range checks and legible errors.

- **Named `any_of`, never `oneOf`.** JSON Schema — embedded verbatim for the `json` type below — defines `oneOf` as **exactly one** (XOR). Two meanings for one word inside one product is a latent trap for both operators and implementers. Overlapping alternatives are explicitly fine and never an error; there is no XOR semantic anywhere in Wenv's own vocabulary.
- **No nesting.** An alternative may not itself be an `any_of`. Validation stays linear in the number of alternatives and bounded (threat model §Availability), and the UI stays explainable.
- **Errors enumerate every alternative's failure** — rule violated per branch, under the disclosure rules below. A bare "matched none of 2 alternatives" is useless to an operator.
- **`allow_empty` is declared on the `string` alternative**, not on the union.

### JSON Schema for `json`-typed keys — a pinned, bounded profile

A `json` key may carry an optional **JSON Schema**, because parseability alone is weak validation: a malformed-but-parseable `OIDC_CONFIG` still breaks the workload, and validation-before-delivery is the product's wedge ([#2](https://github.com/Dunky13/wenv/issues/2)). JSON Schema is used rather than a hand-rolled subset because a subset is a mini-language we would own and grow forever — the same instinct that rejected templating in the inheritance ADR — and a known library is the standing house rule for this class of problem.

But "we accept JSON Schema 2020-12" is not implementable as stated, and byte/depth/count limits do not bound it: a schema well inside every size limit can drive combinatorial evaluation through nested applicators, and independent Go libraries disagree on formats, vocabularies, and reference resolution. So v1 accepts a **pinned, profiled, budgeted** subset of the real thing:

1. **A pinned library and version, plus a conformance-suite baseline**, named in the operations spec. Two Wenv installations must accept and reject the same schemas; "some 2020-12 validator" is not a contract.
2. **One pinned dialect** — 2020-12, declared, no dialect negotiation. It rides inside the pinned schema revision like every other rule.
3. **A supported profile, enumerated as an explicit allowlist.** The **operations spec owns the enumeration**, and it MUST be a keyword-and-vocabulary **allowlist**, not a denylist — a denylist silently admits every keyword a future dialect or library version adds. Fixed here as binding constraints on that allowlist:
   - `$ref` is **in-document only** — no `http(s)`, no file refs; a remote `$ref` makes the validator an SSRF primitive and puts a third party in the publish path.
   - **Reference cycles are rejected at declaration**, even in-document.
   - `$dynamicRef` / `$dynamicAnchor` are **excluded** — their resolution depends on the dynamic scope, so a schema's meaning stops being statically determinable, which defeats declaration-time bound checking.
   - Keywords whose cost is not statically boundable (`unevaluatedProperties`, `unevaluatedItems`, unbounded `contains`) are **excluded**.
   - `format` is **excluded in v1**. JSON Schema makes it an annotation by default, so an asserted-looking `format` that silently validates nothing is the exact failure mode this ADR rejects elsewhere for unanchored regexes — and which formats a library asserts is the single largest source of cross-library divergence. Use `pattern` instead.
   
   Anything outside the allowlist is rejected loud at declaration rather than ignored, so a schema never appears to enforce something it does not.
4. **An evaluation budget, not just a size budget** — a per-validation step cap and wall-clock deadline, an aggregate per-publish work cap, and caps on error count and error-response bytes. Exceeding any of them fails the operation loud; it never degrades to "assume valid".
5. **Compiled once per schema revision and cached** (bounded cache), never recompiled per validation, so a fetch storm cannot be amplified into CPU.

Starting from a narrow profile is also the reversible direction: widening it later is additive, whereas accepting arbitrary 2020-12 schemas and restricting afterwards breaks stored declarations.

### Regex is RE2, and its gaps are rejected loud

Patterns are Go `regexp` — RE2 — so they are linear-time and carry **no ReDoS risk**, a direct dividend of the Go decision in #3. The cost is no backreferences and no lookahead/lookbehind. Those constructs are **rejected at declaration time with a loud error**, never silently ignored: a pattern that appears to enforce something and does not is worse than no pattern at all.

## Presence — `required_in` / `forbidden_in`, per environment

**Required-ness varies per environment.** A project-wide `required` boolean is broken by the ordinary case: `STRIPE_SECRET_KEY` is required in `prod` and meaningless in `local`, and the inheritance ADR makes a masked required key abort publish too — so a project-wide flag would make every `local` publish fail permanently, and the workaround would be junk secret values in dev, which is worse than no validation.

**Presence is a mode plus an explicit set, not a set of ids alone:**

```
required_in:  { mode: all | none | explicit, environment_ids: [...] }
forbidden_in: { mode: all | none | explicit, environment_ids: [...] }
```

- **`mode: all` is symbolic and covers environments created later.** This is why the shape is a mode rather than a bare id list: had `always` been expanded into the ids existing at declaration time, a newly created environment would silently be exempt from a rule the operator wrote as "always".
- **`mode: explicit`** carries the id set. **`mode: none`** is the default for both.
- A key is **required** in environment `E` when presence resolves to required for `E`; a required key that resolves to anything other than `set` in `E` (i.e. `absent` or `masked`, per the inheritance ADR) aborts the publish that would materialize `E`.
- A key that resolves to `set` in an environment where it is **forbidden** aborts the publish.

**`required` is a predicate about presence only:** it means "resolves to `set`", and says nothing about content. Content rules are the type's business.

`forbidden_in` exists because without it the schema can declare "must exist here" while only a per-environment operator `masked` action can express "must never exist here" — and those are different powers over different time horizons. A `masked` entry is removable by anyone holding publish on that environment; a schema `forbidden_in` changes only under schema authority. "`TEST_PAYMENT_KEY` must never reach prod" is a durable declaration, not an operator chore. It reuses the same environment-set machinery, adds one publish-time check, and adds one declaration-time check.

**Declaration-time conflict rejection where statically decidable** — a key both required and forbidden in the same environment (including via `mode: all` on both), or two members of one key group in that configuration, is rejected at declaration rather than discovered at publish.

**Environment lifecycle is part of the same serialized domain** (see *One serialization domain per project*): deleting an environment cascades its id out of every explicit presence set in the same transaction, and creating an environment validates and materializes it against the current schema revision **before it becomes fetchable**, so an environment is never deliverable in a state no schema check has seen.

**Editing presence rules is a resolution-affecting mutation**, so it runs the inheritance ADR's impact preview and per-affected-environment publish authorization. That ADR already names schema requiredness explicitly; this one confirms it.

*Rejected: required-ness as a layered value*, inheriting down the base chain exactly as values do. Seductively symmetric, but it makes every key carry **two** layered things, each needing provenance, a matrix representation, and impact-preview rows — and it breaks the pinning model, because required-ness would move out of the schema revision into the layer revisions, so "the schema revision this snapshot was validated against" would stop being one pinned input.

## Constraints do not vary per environment

Only **presence** varies per environment. Every other constraint — type, range, pattern, enum members, URL schemes, JSON Schema — is **project-wide**.

The wish this denies is real: `DATABASE_URL` must be `postgres://` in prod while `sqlite://` is fine in dev. The answer is to express the union (`schemes: [postgres, sqlite]`, or an `any_of`) and accept that dev's looseness is also prod's, or to use two keys.

*Rejected: per-environment constraint overrides.* They turn the **schema** into a second matrix, where every constraint needs its own provenance, its own inheritance rules, and its own impact-preview rows — the same cost that rejected layered required-ness, incurred many more times over. "Prod must be postgres" is a **policy** assertion rather than a shape assertion; it belongs to a guardrails feature outside this map's destination. Deferred, not precluded.

## No schema-level defaults

**There is exactly one defaulting mechanism: the project-defaults layer** (#7, inheritance ADR). No `default` field participates in resolution.

A schema `default` would be a second, lower, invisible layer, and it would break the inheritance ADR's central promise that every resolved value is explainable as "came from layer X" — the answer would sometimes be "came from a schema field nobody looked at". Two defaulting paths also means two places to check when an environment has the wrong value.

**What remains is pure UI sugar:** declaring a key may offer "and give it this value as a default", which **writes a project-defaults layer entry** through the normal publish pipeline. Same affordance for the operator, no second resolution path, and the write appears in history like any other.

### Newly inheriting a secret — amendment to the inheritance ADR

The inheritance ADR's "any key may hold a `set` default value" is **not narrowed**: `secret` keys may hold project defaults. Forbidding them would force N copies of one credential and make rotation worse.

What is narrowed is the *other* end. That ADR reveal-gates the impact **preview** but not the **delivery**, which leaves a legal exfiltration sequence: a shared secret default is inherited by `prod` while `dev` carries a `masked` entry; a `dev` publisher holding publish-on-dev but **not** `reveal` removes the mask; `dev` now resolves the secret and Wenv delivers the plaintext into a dev workload the publisher controls. No rule in the prior ADRs stops this, because the publisher never *displayed* the secret — Wenv handed it to their workload instead.

**Amendment (narrows [inheritance-model.md § Delete vs mask](./inheritance-model.md)):** a publish that causes an environment to **begin delivering a `secret` value occurrence it is not already delivering** requires **`reveal` on that key** in addition to publish authorization on that environment, re-checked with any required reauthentication immediately before commit, and audited as a disclosure-class event.

**The gate is on occurrence identity, not on presence.** Presence alone is too weak: an environment that resolves `secret` occurrence `A` and is re-pointed to resolve occurrence `B` stays `set` throughout, so a presence-based rule never fires while a *different* secret is routed to that environment. Every one of these routes is therefore gated:

- removing a `masked` entry so an inherited occurrence reaches the environment;
- adding or re-pointing a `base`, or removing a local override, so a **different** pre-existing occurrence wins;
- a project-defaults write that newly reaches the environment;
- **creating an environment** that inherits secret occurrences — a new environment has no prior snapshot, so it delivers every one of them for the first time.

**The exemption is authorship, and authorship means plaintext the publisher supplied in the request** — not merely an occurrence created during this publish. A publisher who types a new value already holds it, so gating them discloses nothing.

**Every server-derived occurrence is gated, even though the publish creates it.** The distinction is load-bearing because the revision ADR's **rollback** stages a new local `set(v)` reproducing revision N's value from **server-held historical material** — the publisher never supplies that plaintext. Under a novelty-based exemption, a principal with publish-on-dev and no reveal could restore prod's superseded secret into a dev environment they control and read it out of the workload, which is precisely the path this amendment exists to close. So:

- **Restore of a `secret` occurrence requires `reveal-history` on that key** (the revision ADR's distinct historical-reveal capability), in addition to the routing gate above.
- **Any other server-side duplication of stored secret material** — copy from another environment, clone an environment, bulk-apply — is likewise gated on `reveal`, because in each case the server, not the publisher, supplies the plaintext.

The gate therefore binds whenever an environment starts delivering secret material the publisher did not hand over: pre-existing occurrences from another layer or principal, and server-reconstructed ones. Routing a secret to a new place is a disclosure to whoever controls that place, so it is gated like one.

A UI advisory ("this secret is shared by N environments") remains the right belt on the declaration side.

## Values are trimmed, and otherwise byte-exact

**Leading and trailing whitespace is trimmed on every write path** — UI, CLI, API, and any future import — using Unicode whitespace semantics (Go `strings.TrimSpace`), for every type. Trimming runs **before** validation, so a value that is whitespace-only becomes empty and is then rejected by `allow_empty` rather than stored. Trimming applies at write time only, never retroactively to historical values, which remain immutable per the revision ADR.

Beyond that trim, **values are stored and delivered byte-exact**: no Unicode normalization, no case folding, no interior whitespace collapsing.

**Stated limitation, accepted knowingly:** a credential whose true value has significant leading or trailing whitespace **cannot be stored in Wenv**, and the resulting failure surfaces at the consuming service rather than here. Wenv holds credentials it does not generate, so this class exists. The trade was made in favour of the far more common papercut — a pasted token with a stray newline — being impossible rather than merely warned about. *(A per-key `preserve_whitespace` escape hatch was offered and declined by the owner in favour of one unconditional rule.)*

## Closed schema — no auto-declare

**Every value belongs to a declared Key.** Typing a key name that does not exist is a **key creation**, an explicit act, not a silent value write.

Auto-declare-on-first-write is frictionless and would normally win, but it destroys the product's main catch. A typo'd key name is the most common configuration bug there is; under auto-declare `DATBASE_URL` silently becomes a legitimate key holding a value, the workload reads `DATABASE_URL`, receives nothing, and the schema reports everything valid. A closed schema turns that into "this key does not exist in this project" at the moment of the typo.

- **A delivered payload's key set is exactly the declared keys that resolve in that environment, under the schema revision that snapshot pinned.** The qualification matters: a **pinned** revision (revision ADR § Retention) keeps delivering the key set of the schema it was built for, so the guarantee is a property of the snapshot, not a live property of the project. See *Constraints bind future materializations, not delivered copies*.
- **Key creation is cheap, not ceremonial.** It rides in the same publish as the value: one publish carries the schema pending change and the value pending changes together.
- **Key creation requires the schema-edit capability**, and — because creating a key with a value moves delivered content — the publish authorization of every environment whose content it moves. Accepted consequence: a contributor holding publish-on-dev but not schema-edit cannot introduce a key. Whether those are the same role in practice is RBAC's ladder to draw ([#15](https://github.com/Dunky13/wenv/issues/15)), not this ADR's.
- **Near-miss advisory** (propagated to #20/#21): on key creation, warn when the name is within a small edit distance of an existing project key. Non-blocking; it closes the residual case where the typo happens at declaration rather than at value-write.

## Key groups — co-publish closure and all-or-none presence

A **key group** is a named, project-level set of keys, declared inline in the schema. **A key belongs to at most one group.**

The revision ADR fixed the intent: selecting a pending change to any member closes the selection over the whole group, and a group's members may never span two publishes. This ADR fixes the algorithm, because "must change together" has several readings and an implementer needs one.

**Closure algorithm.** Closure is computed over **`(group, layer)` pairs**, because a group's coupling is a coupling of entries, and one selection may touch several layers: a pending change targets a specific `(key, layer)`, so `DB_USER` in project-defaults and `DB_PASSWORD` in `prod` are separate entries that close separately. Each layer closes independently.

Given a publisher `P` and a selected set `S` of pending-change version ids:

1. For each **value** version in `S`, take its `(key, layer)`. Let `Q` be the set of `(group, layer)` pairs where `group` is the group containing that key — under **both** its **pre-change** membership and its **prospective** membership after every schema change in `S` is applied.
   
   **Schema versions are project-scoped and carry no layer**, so they enter `Q` differently: a membership-changing schema version contributes `(g, L)` for each group `g` whose membership it alters, paired with **every layer `L` appearing among the value versions in `S`**. Consequently a selection containing **only** schema versions yields an empty `Q` and closes no value entries — correctly, since it publishes no values and so cannot publish a partial group of them. The membership change's own all-or-nothing completeness is rule 7, not closure.
2. For each `(g, L)` in `Q`, and each member key `K` of `g` under either membership: if `P` owns a live pending change to `(K, L)`, its **latest** version is added to `S`. 
3. Adding versions may introduce further `(group, layer)` pairs; repeat 1–2 to a **fixed point**. Termination is guaranteed because a key belongs to at most one group under each membership and the pair set is finite.
4. **Both memberships are used deliberately.** Closing only over prospective membership would let a publisher remove a key from a group and simultaneously publish a partial change to what the group used to couple; closing only over pre-change membership would let them add a key to a group and publish a change that the new coupling was meant to constrain. Both directions are the coupling the group exists to enforce.
5. **A member with no pending change from anyone is not an error.** The guarantee is that a publisher cannot publish a *subset* of the pending changes to a group — not that every member must be touched on every publish. Rotating `DB_PASSWORD` while `DB_USER` genuinely does not change is a legal publish; the value it must not become is "password rotated, the user change left behind in a draft".
6. **A member with a live pending change owned by another principal aborts the publish, loud, naming the group and the member key.** Never silently split, and never a cross-user hand-off — the revision ADR keeps that outside v1.
7. **Group membership changes are schema pending changes** and participate in the same closure: adding a key to a group, removing one, or creating a group is selected and published like any other schema change, and a publish may not apply half of a membership change.

**All-or-none resolved presence per environment, always on, no flag.** Evaluated at publish on **resolved presence**: in each environment, either every member resolves to `set` or none do; a partial group aborts the publish naming the group. `SMTP_HOST` set in prod with `SMTP_PASS` masked passes every per-key check and breaks mail — the same "schema validity is not operational validity" gap that motivated key groups. Co-publish closure closes the *timing* hole; all-or-none closes the *state* hole. In practice they are always the same set of keys, so this is one concept with no knob.

**At most one group per key** because multi-membership makes closure transitive across groups, so selecting one pending change can drag in a chain the publisher never previewed — inverting the revision ADR's core property that a publisher applies exactly what they saw. At-most-one keeps the closure set statically visible on the key and reduces the UI to one line ("part of group `database`"). Relaxing it later is additive.

**Rejection messages name groups and key names only, never values** — key names are schema, values are not.

**Deleting a key cascades** it out of its group; a group left with fewer than two members is inert and flagged in the UI.

## Validation timing — advisory on save, authoritative at publish

- **Saving a *value* never blocks on validity.** A pending change may hold a type-invalid value (`PORT=banana` saves fine). The draft is the user's scratchpad; blocking save pushes work-in-progress into external notepads, which for secrets is exactly where it must not go. The inheritance ADR's "save/draft is free" is thereby total: `allow_empty` and every type rule are checked on save but **annotate**, they do not reject. (The trim in *Values* is not a validation rule and does apply at save.)
- **Saving a *schema declaration* does block on well-formedness.** A malformed or out-of-profile declaration is not work-in-progress, it is a broken rule: syntax errors, unsupported RE2 constructs, out-of-profile JSON Schema keywords, reference cycles, and bound violations are **rejected at save**. The distinction is: a value may be wrong, a rule may not be meaningless.
- **Every value save validates synchronously and stores an advisory verdict** on the pending change. Cheap — one key, against validators already compiled and cached per schema revision — and it powers the UI: an invalid-draft marker on the matrix cell, and the publish dialog surfacing it *before* the full preview is computed. Nobody meets their first type error at publish time.
- **Advisory verdicts are owner-only.** A pending change's detailed verdict is visible to its owner, or to a principal holding current `reveal` on the key. Everyone else sees only the write-presence marker the revision ADR already permits ("another user has a pending change here"). A detailed verdict on someone else's secret draft is a predicate channel on that draft's plaintext, and closing it costs nothing.
- **Stored verdicts are recomputed when stale**, for the **latest** pending version per `(owner, key, layer)` only — superseded versions are not revalidated, since they can no longer be published.
- **Publish is the authority.** Validation is re-run inside the serialized publish, on **resolved** values, at the pinned schema revision, regardless of any stored draft verdict. A draft verdict is UX and is never the thing a publish trusts.
- **Delivery reads only committed, valid snapshots** (inheritance ADR), or fails closed.

*Rejected: block-on-save for type-invalid values* — inconsistent with a model that already permits unresolved and masked required keys in a draft, and it drives secret drafting off-platform.

### Changing a value-dependent rule on a secret key is a disclosure

**This is the load-bearing security rule of this ADR.** Validation reports whether a value satisfies a predicate, and the *result bit itself* is the leak, entirely independently of whether the error message quotes the value.

The attack: a principal holds schema-edit but not `reveal`. They set `pattern: "^A"` on a `secret` key and attempt a publish. The publish validates every environment against its resolved values and aborts naming the failing environments — so the abort answers "does prod's secret start with `A`?". They repeat with `^B`, `^Aa`, a JSON Schema `const`, an `enum`, a `minLength`, a `min`/`max` bisection. Each attempt is a rejected edit that commits nothing, and together they recover a low-entropy secret or an arbitrary prefix of a high-entropy one without ever holding `reveal`. This is exactly the oracle class the revision ADR's keyed change token and write-presence-only diffs exist to close, arriving through a door those rules do not cover.

**Rule.** Evaluating a **changed value-dependent rule** against an existing `secret`-classified value is treated as a **disclosure of that value**. Such a change therefore requires **current `reveal` on that key**, re-checked with any required reauthentication **immediately before evaluation**, in addition to the publish authorization the change already needs. Without `reveal`, the operation is **rejected without evaluating** — it does not evaluate-then-withhold, because timing and abort/success are themselves the channel.

- **Value-dependent rules** are: type, `min`/`max`, `minLength`/`maxLength`, `pattern`, `enum` members, `url` schemes, `allow_empty`, `any_of` alternatives, and the JSON Schema.
- **Presence rules are not value-dependent.** `required_in`, `forbidden_in`, key-group membership, and all-or-none presence report only whether an entry is `set`, `absent`, or `masked` — which is **write-presence**, already visible without `reveal` under the revision ADR. They need no `reveal`.
- **Metadata is not value-dependent.** `description`, `deprecated`, `deprecation_note`, folder path.
- **Every attempt is audited and rate-limited**, per key and per principal. Rate limiting is defence in depth, not the control — the control is that no predicate result reaches a non-revealer.
- **Consequence, stated plainly:** tightening validation on a secret key is a privileged act. In a project whose secrets are widely `reveal`-restricted, schema-edit alone cannot tighten their rules. That is the correct trade — the alternative is a byte-at-a-time extraction oracle on every secret in the installation.

### Error disclosure — never echo a secret's value, including through paths

A validation error reports the **rule violated**, and for a `secret`-classified key it reports **nothing derived from the instance data** — no value, no prefix, no length, no digest, **and no instance-derived path**.

The path caveat is not hypothetical: a secret `json` value of `{"AKIA…credential…": "x"}` failing `additionalProperties: false` would, under a naive implementation, produce the error path `/AKIA…credential…` — the plaintext, in the error message, in the log, and in the audit record. Array indices and error multiplicity leak structure and length the same way.

For a `secret`-classified key without current `reveal`:

- Errors identify the **schema location** (the keyword that failed), never an instance-derived pointer.
- Instance property names appear **only if statically declared in the schema**; dynamic keys and array indices are redacted.
- Repeated errors are collapsed, and error count and response bytes are capped.

`config`-classified keys report full instance paths and values under ordinary environment read. This holds identically in the UI, server logs, CLI output, and audit records. Declared `enum` members are schema rather than value, so listing them is permitted.

## Schema lifecycle, authority, and authorization

- **The schema carries its own monotonic revision per project.** This is the revision that snapshots pin (inheritance ADR), distinct from the per-`(project, environment)` revision numbers of the revision ADR.
- **A schema edit is an ordinary pending change** owned by a user, with an immutable version id, published through the same pipeline as value edits: same impact preview, same freshness check, same serialized publish. No second code path.
- **A schema publish validates every environment in the project against the new schema revision, and any environment that would be invalid aborts the entire publish**, naming the failing keys and environments — subject to the `reveal` gate above for secret-key rule changes. Straight from the inheritance ADR's atomicity rule, which names schemas explicitly.

### Authorization: semantic changes need per-environment publish authority

**A schema change that can affect validity, delivery, coupling, or routing requires publish authorization on every affected environment**, evaluated immediately before commit, plus protected-environment confirmation where it reaches one — exactly as the inheritance ADR requires of every resolution-affecting mutation. That set is: type and every constraint, presence rules, key-group membership, classification, key creation, deletion, and rename.

**Only non-semantic metadata is exempt** and needs the project-scoped schema-edit capability alone: `description`, `deprecated`, `deprecation_note`, and folder path. These cannot change what any environment delivers or whether it validates.

*An earlier draft of this ADR exempted all "pure" schema changes — those not moving delivered content — from per-environment publish authorization, on the reasoning that fixing a typo should not require prod publish rights. Codex cross-review round 1 showed this both contradicts the locked inheritance ADR ("Every resolution-affecting mutation goes through this guard", which names schema requiredness and validation explicitly) and is unsafe on its own terms: a principal with schema-edit alone could loosen prod's validation, drop a presence protection, or dissolve a key group without prod authority — and could equally tighten a rule to block every future prod publish. The exemption is withdrawn; the owner accepted the reversal.*

### No validated-against pointer: semantic schema changes materialize

A schema change that alters validity **materializes a new snapshot and a new revision for every affected environment**, per the inheritance ADR, even when no value changes. The revision ADR's change token is computed over the delivery manifest, so an unchanged manifest yields an unchanged token and **no workload rollout** — the new revision records that the validation guarantee moved, without disturbing anything.

Non-semantic metadata changes materialize nothing, because there is nothing to revalidate.

*An earlier draft avoided revision churn by leaving unchanged environments on their existing snapshot and advancing a mutable per-environment "validated-against schema revision" pointer instead. Codex cross-review round 1 rejected it: it contradicts the locked inheritance ADR's requirement that a schema publish materialize new snapshots for every affected environment, and it creates two truths for one revision — a snapshot pinned to schema 3 while a mutable pointer claims schema 4 — which history, pins, rollback, and the API would each answer differently, with no way to reconstruct the historical validation state. Withdrawing the authorization exemption above removed the motivation anyway: the only remaining exempt changes are metadata, which need no revalidation at all. The pointer is deleted, not amended.*

### Constraints bind future materializations, not delivered copies

`forbidden_in`, key deletion, and every tightened constraint govern **materialization**. They cannot reach backwards:

- **A live pin blocks a conflicting publish.** A publish that would forbid or delete a key is **rejected, loud, naming the pins** while any live pin (revision ADR § Retention) delivers that key to that environment. The operator releases the pin, or explicitly overrides — the same explicit-override shape the revision ADR already requires for pinning to a revision that fails current validation. Without this, "must never reach prod" is simply false wherever prod holds a pin.
- **Already-delivered copies cannot be recalled.** A workload that has fetched a value holds it. Forbidding or deleting a key stops future delivery and does not undo past delivery, so retiring a secret that reached the wrong environment requires **rotating the credential**. The ADR says so rather than implying an unenforceable guarantee.
- **The closed-schema guarantee is a property of a snapshot**, under the schema revision it pinned — not a live invariant over the project.

### Authority: the database, with a reviewable export

**The Wenv database is authoritative for the schema. A Git file is export, never authority, in v1.**

Git-as-authority fails on a locked invariant: both prior ADRs require validate-and-materialize to be a **single serializable operation per project**. If the schema's truth lives in a Git repo, that transaction spans a system Wenv cannot serialize against, opening a window where the schema moved but no environment was re-validated — plus merge conflicts on the one artifact that gates every publish. That is precisely the SOPS drift/merge problem the source-of-truth ticket is charged with not recreating.

What this ADR commits to so the option stays open:

- **A canonical, byte-stable, lossless, versioned text serialization of the schema.** Byte-stable so two exports of one revision are identical and reviewable in a pull request; lossless so no declared field is partially represented; versioned so the format can evolve without silently breaking consumers.
- **Read-only export ships in v1** — near-free once the canonical serialization exists (which schema-revision diffing wants regardless), and it satisfies the real developer desire to review a schema change beside the code that consumes it.
- **Apply-from-file (import) is the source-of-truth ticket's call** ([#13](https://github.com/Dunky13/wenv/issues/13)), together with direction, drift detection, and conflict handling. Binding requirement from here: any future import MUST funnel through the same publish pipeline — no side door into the schema.
- **The concrete export format** (YAML, JSON, other) belongs to the API/CLI surface ([#25](https://github.com/Dunky13/wenv/issues/25)); this ADR fixes only the requirements above.

## Reclassification between `secret` and `config`

The revision ADR fixed that **historical** values keep the classification in force when they were written. Classification is therefore a property of a **stored value occurrence**, not only of the live key declaration — and reclassification must move the current occurrences explicitly rather than relabel the key and hope.

**Reclassification requires, in every environment holding a live occurrence of the key:** publish authorization, protected-environment confirmation where it reaches a protected environment, and — for declassification — current `reveal` on that key. Scoping matters because one key resolves to *different* values in different environments: `reveal` in dev must not authorize declassifying prod's value.

**"Live occurrence" includes dormant ones.** A `set` layer entry that is currently *shadowed* — by a nearer override, or by a `masked` entry above it — is still a live occurrence, and reclassification re-materializes it too. Otherwise a dormant `secret` occurrence survives a declassification ungated, and the later publish that unshadows it delivers a `secret`-classified occurrence for a key the schema now calls `config` — a routing mismatch that no reveal check ever saw.

**Historical and pinned occurrences keep their write-time classification and are delivered under it.** They are immutable (revision ADR), so reclassification cannot reach them, and a pin therefore keeps delivering the old classification — and, where an adapter routes by it, the old destination. This is **classification drift**, surfaced to operators exactly as the revision ADR already surfaces schema drift on pins, with the same remedies: release the pin, or repin forward. Creating a **new** pin to a revision whose classification disagrees with the current declaration requires an explicit override and is recorded as such, mirroring that ADR's rule for pinning to a revision that fails current validation.

- **`secret` → `config` (declassify)** re-materializes the current resolved occurrence in each affected environment **as a `config` occurrence**, which is what actually makes it readable under ordinary environment read; historical occurrences keep `secret` and stay reveal-gated. It requires `reveal` for every affected environment, re-checked with any required reauthentication immediately before commit, explicit confirmation, and an audit record written durably **before** commit as a disclosure-class event. Without the `reveal` gate, a principal holding schema-edit but not `reveal` declassifies and then reads the plaintext under ordinary read — the same shape as the impact-preview reveal bypass the inheritance ADR closes. You must be able to see a secret in order to stop it being one.
- **`config` → `secret` (tighten)** likewise re-materializes current occurrences as `secret`, and must state what it cannot undo: the value was previously readable under plain read, exportable, and visible in plaintext diffs, and tightening does not un-disclose it. A mandatory advisory — treat this value as exposed, rotate it — plus an audit event. Because classification is sticky to historical occurrences, **the old plaintexts remain visible in history under plain read**; that is correct but surprising, so the UI must state it rather than let an operator assume tightening retro-sealed the record.
- **Audit uses the stricter of the pre- and post-change classification**, so neither direction is recorded under the laxer regime.
- **Reclassification is a schema pending change** through the normal pipeline: same preview, same freshness check, same serialized publish.

### The change token covers a delivery manifest — amendment to the revision ADR

If an adapter routes by classification — mapping `secret` to a Kubernetes `Secret` and `config` to a `ConfigMap` is the obvious design — then a reclassification changes **what is delivered and where** without changing any value, and a token computed over a bare key→value map would not move, so the rollout that relocates the value would never fire.

**Amendment (replaces the canonical-encoding definition in [revision-model.md § Revision identity](./revision-model.md)):** the change token is `HMAC(scoped token key, versioned canonical encoding of the **delivery manifest**)`, where the delivery manifest is the ordered set of `(key, classification, value)` triples the snapshot delivers. Equal tokens then mean identical *delivery*, which is what every consumer of the token actually needs, rather than identical key→value bytes.

This is recorded as an amendment rather than a refinement because it changes the stated `iff`: two snapshots with identical key/value bytes but differing classification now produce **different** tokens, which under the prior wording they could not. The manifest is defined independently of any adapter's implementation, so an adapter that ignores classification simply performs one benign no-op rollout. Nothing has shipped, so the `v1:` scheme prefix is retained rather than burned.

## One serialization domain per project

Both prior ADRs require per-project serialization — the inheritance ADR for base-graph mutation, the revision ADR for publish. Neither names environment lifecycle, and that gap races: transaction A deletes environment `E` and computes its presence cascade from the schema it read, while transaction B adds `E` to a `required_in` set and validates against a graph where `E` still exists. Both commit, leaving a dangling reference or a lost cascade.

**Binding: one serialization domain per project covers the schema, layer entries, the base graph, environment create/delete, presence cascades, snapshot materialization, and revision allocation.** It is acquired **before** preview-freshness and authorization re-checks, and cascade, validation, revision allocation, and commit all happen inside it. A per-project advisory lock or a `SERIALIZABLE` transaction with retry both satisfy this; two independently-serialized domains do not.

## Bounds (threat model §Availability)

Declaration and validation are attacker-triggerable work, so they are bounded, all enforced with loud errors, with concrete values fixed in the operations spec:

**Declaration size** — maximum keys per project; maximum `enum` members; maximum pattern length; maximum `any_of` alternatives; maximum JSON Schema bytes, nesting depth, and subschema count.

**Evaluation work** — maximum instance bytes validated; per-validation step cap and wall-clock deadline; **aggregate per-publish work cap** across `keys × environments × alternatives × JSON evaluation`, so one publish cannot become an unbounded job; error-count and error-response-byte caps; a bounded compiled-validator cache.

**Draft and revision growth (amendment to the revision ADR).** That ADR creates an **immutable version on every edit** and does not bound them, so a client saving one field in a loop grows storage without limit and multiplies the revalidation work of every later schema change. This ADR requires: a per-user and per-project **live-draft quota**; **garbage collection of superseded pending versions** (only the latest version per `(owner, key, layer)` is publishable, and only it is revalidated); a **schema-revision rate limit**; and **canonical-form deduplication** of identical schema declarations. Concrete values belong to the operations spec.

## Propagations (binding on downstream tickets)

- **RBAC ([#15](https://github.com/Dunky13/wenv/issues/15))** — MUST express a project-scoped **schema-edit** capability, distinct from publish and from reveal; MUST gate **declassification** and **changes to value-dependent rules on `secret` keys** on current `reveal`, scoped per affected environment and evaluated immediately before evaluation/commit; MUST gate a publish that makes an environment **begin delivering a `secret` occurrence the publisher did not supply** on `reveal`, keyed on occurrence identity rather than presence, and on **`reveal-history`** where the material is server-reconstructed from a historical revision (restore); MUST place key creation, deletion, and rename under schema-edit **plus** per-affected-environment publish authorization.
- **Source of truth ([#13](https://github.com/Dunky13/wenv/issues/13))** — owns schema import and any Git sync; any import MUST funnel through the publish pipeline. The database stays authoritative in v1.
- **API & CLI ([#25](https://github.com/Dunky13/wenv/issues/25))** — owns the concrete canonical export format, satisfying byte-stable, lossless, and versioned; owns `key add`, schema export, and the pin-conflict override flow.
- **Compose & Kubernetes integration ([#18](https://github.com/Dunky13/wenv/issues/18), [#19](https://github.com/Dunky13/wenv/issues/19))** — own whether delivery routes by classification; MUST consume the delivery-manifest change token; MUST NOT assume a live project invariant where the guarantee is per-snapshot (delivered key set is the pinned schema's). MAY rely on values being valid UTF-8 and NUL-free.
- **Matrix-UI prototypes ([#20](https://github.com/Dunky13/wenv/issues/20), [#21](https://github.com/Dunky13/wenv/issues/21))** — MUST provide a multiline editor for `string`, a free-text editor with alternatives-as-hints for `any_of`, an invalid-draft marker driven by the owner-only advisory verdict, the near-miss warning on key creation, the visible trim on save, the deprecation warning, and the shared-secret-default and post-tightening-history advisories. MUST NOT render a `secret`-classified key's value, or an instance-derived error path, to a principal without current reveal.
- **Audit ([#24](https://github.com/Dunky13/wenv/issues/24))** — MUST define events for schema publish (with the revision), key creation, rename, and deletion, presence-rule changes, reclassification in both directions, changes to value-dependent rules on `secret` keys, a `secret` newly resolving in an environment, and pin-conflict overrides. Disclosure-class events MUST be written durably before commit and recorded under the stricter of the pre/post classification; no event payload may contain a `secret`-classified value or an instance-derived path.
- **Encryption model ([#14](https://github.com/Dunky13/wenv/issues/14))** — MUST account for `config`-classified occurrences being readable under plain read, so a `config` → `secret` tightening cannot retroactively protect what was stored and served as config.
- **Operations spec (fog)** — fixes every concrete value under *Bounds*, plus the pinned JSON Schema library, version, and conformance baseline, **and owns the profile's explicit keyword/vocabulary allowlist** under the exclusions fixed above.
