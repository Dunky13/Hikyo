# Hikyo permission model — RBAC & secret reveal (ADR, locked 2026-07-31)

> **Declared amendment (2026-08-06, [scim-provisioning.md](./scim-provisioning.md), [#38](https://github.com/Hikyo-Org/Hikyo/issues/38), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** (a) every grant row carries one or more **origins** — `manual(granted_by)` (every pre-existing grant has exactly this), `scim(binding, mapping_row, group)`, `lockout-retention(cause)`, or `structural(binding)` (exactly the provisioning connection's system-created `scim-provision` grant, retired atomically with its binding); a row exists while ≥1 origin holds it and is revoked, with the locked session-generation advance, when its last origin is released. **Evaluation is untouched**: authority remains the bare `(principal, capability, scope)` triple, origins are never consulted by `authorize()`, and no deny rule exists. Origin chips join the membership surface **per capability line** — the per-line inspection/revocation property is unchanged. (b) The lockout invariant's refusal binds *human revocation* unchanged; for SCIM-side release, refusal converts to **lockout retention** (the withdrawn `scim` origin is honestly released; a system-owned `lockout-retention` origin holds the row, cured — audited both ways — the moment another org `manage-members` holder exists). (c) The closed capability atom set gains **`scim-provision`** (org scope, machine-only, never grantable to humans), and the normative machine allowlists gain one row: the **provisioning-connection** class → `{scim-provision}`, the grant system-created with its SCIM binding and refused via the grant API. Details in [scim-provisioning.md](./scim-provisioning.md).

> **Amended by the flat-model ADR ([flat-model.md](./flat-model.md), 2026-08-06, [#40](https://github.com/Hikyo-Org/Hikyo/issues/40), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** the closed *dynamically triggered disclosure checks* list reads per that ADR's trigger enumeration (copy/clone/bulk-apply, restore; the unmask and new-environment triggers are unreachable). The scope lattice's downward **grant** inheritance is untouched — different sense of the word. The copy/clone/bulk-apply and pin formula rows stand exactly as written.

> **Declared amendment (2026-08-06, [multi-instance.md](./multi-instance.md), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** (a) one new instance-scope capability atom, **`instance-directory`** — read the directory of connected instances / serve this instance's listing; (b) the rule that no machine principal may hold any instance capability gains its **single named per-class exception**: the instance-connection principal class may hold exactly `instance-directory` and nothing else, enforced by the grant API. No other formula moves; details in [multi-instance.md](./multi-instance.md).

Context: every upstream ADR has deferred its authorization question here. The threat model ([#8](https://github.com/Hikyo-Org/Hikyo/issues/8)) fixed the *stance* — least privilege and deny-by-default **within** an org, capabilities as separate grants rather than bundles, authorization evaluated immediately before **each** sensitive disclosure or external effect, deprovisioning atomic across sessions/credentials/cached authorization. The inheritance ([#10](https://github.com/Hikyo-Org/Hikyo/issues/10)), revision ([#11](https://github.com/Hikyo-Org/Hikyo/issues/11)), schema ([#12](https://github.com/Hikyo-Org/Hikyo/issues/12)), source-of-truth ([#13](https://github.com/Hikyo-Org/Hikyo/issues/13)) and encryption ([#14](https://github.com/Hikyo-Org/Hikyo/issues/14)) ADRs each named capabilities they require to exist (`publish` per environment, `reveal`, `reveal-history`, `schema-edit`, `definitions-edit`, `apply`, the operator set) without fixing the ladder they sit on. This ADR fixes **the grant primitive, the scope lattice, the capability atoms, the role templates, the disclosure rule, the reveal guard, and the evaluation/revocation semantics**, and reconciles the names those ADRs used.

Granularity note: this is the wayfinding-level permission ADR. It fixes what a grant *is*, what capabilities exist, which templates seed them, how disclosure is guarded, and when authorization is evaluated. Mechanism-level detail is delegated: session mechanics, the reauthentication factor itself, password/MFA handling and first-admin bootstrap → human auth ([#16](https://github.com/Hikyo-Org/Hikyo/issues/16)); token formats, service-account lifecycle and the two machine credential classes → machine identities ([#17](https://github.com/Hikyo-Org/Hikyo/issues/17)); the enforcement chokepoint's implementation inside the query layer, and its interaction with tenant scoping → tenant isolation ([#23](https://github.com/Hikyo-Org/Hikyo/issues/23)); the event shapes for grant, escalation, reveal and denial → audit ([#24](https://github.com/Hikyo-Org/Hikyo/issues/24)); the endpoints and CLI verbs carrying each authorization formula → API & CLI ([#25](https://github.com/Hikyo-Org/Hikyo/issues/25)); reveal interaction, remask timeouts and the membership UI → prototypes ([#20](https://github.com/Hikyo-Org/Hikyo/issues/20), [#21](https://github.com/Hikyo-Org/Hikyo/issues/21)); the adapter's outbound credential handling → deployment-module seam ([#28](https://github.com/Hikyo-Org/Hikyo/issues/28)); concrete window defaults, quotas and grant-count bounds → operations spec. Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

> **Amends the revision ADR ([revision-model.md § Historical reveal](./revision-model.md), [#11](https://github.com/Hikyo-Org/Hikyo/issues/11)):** that ADR states "the default administrator role does" hold both `reveal` and `reveal-history`. This ADR **conforms to the outcome and changes the mechanism**: there is no administrator *role* holding capabilities. The `admin` template **seeds** `reveal` and `reveal-history` as **independent, separately visible, separately revocable grants** alongside the administrative ones. A default administrator therefore holds both, as #11 requires; an installation may strip either from a specific administrator without dismantling their administrative authority, and re-adding one is an ordinary audited grant.

## The grant primitive — capability grants, role templates

A **grant** is a triple `(principal, capability, scope)`. That is the only thing stored, the only thing evaluated, and the only thing revoked.

**Roles are templates, not grants.** A closed set of named templates (below) exists purely as an administration affordance: applying one **expands at grant time** into the individual capability grants it names, each of which is then visible on its own line and revocable on its own. Nothing in the system stores "Alice is a maintainer"; it stores the capabilities that template created. This satisfies the threat model's "capabilities are separate grants, not bundles" **at grant time**, not merely at check time — a distinction that matters, because per-capability *checking* does not undo privilege already handed over in a bundle.

Grants are **purely additive**; effective capability is the union of all grants reaching a scope. There are **no deny rules**: absence of a grant *is* denial (deny-by-default), so there is never a precedence puzzle between a grant and a deny, and no rule ordering to reason about.

*Rejected: storing `(principal, role, scope)` and expanding at evaluation.* Smaller data model, but granting one capability from a template would mean inventing a role, revoking one would mean inventing another, and the locked "separate grants" bind would hold only at check time. *Rejected: raw capability grants with no templates at all.* The check is capability-shaped either way; without templates the administration UI is twelve checkboxes per scope per user. *Deferred (fog): custom/user-defined templates.* They need a template editor, a migration story, and a can't-lock-yourself-out invariant — none of it earning its place at 1–3 orgs and ≤25 users ([#3](https://github.com/Hikyo-Org/Hikyo/issues/3)).

## Scope lattice — four levels, additive, inheriting downward

Scopes are **instance → org → project → environment**, matching the domain hierarchy ([#7](https://github.com/Hikyo-Org/Hikyo/issues/7)) minus the levels that carry no authority.

- A grant at a scope applies to that scope **and everything beneath it**. `read` at org scope reads every project and environment in that org.
- **No folder-scoped grants** — the domain ADR already fixed folders as organizational only.
- **No key-scoped grants** in v1. Where an upstream ADR says "`reveal` on that key in environment `E`" ([schema-model.md](./schema-model.md), [revision-model.md](./revision-model.md)), it resolves as: the principal holds `reveal` at `E` **or at a scope above `E`**.

**The key catalogue is project-scoped.** Any environment-scoped grant implies visibility of the project's key names, descriptions, schemas and folder paths — because a per-environment key catalogue would make validation status and cross-environment diffs unreadable, which are the product's reason to exist. Values remain strictly per-environment.

**Honest consequence, stated rather than hidden:** because inheritance flows downward, an org-scoped `reveal` grant reveals in production too. Production protection therefore rests on **granting at project or environment scope** rather than at org scope, plus the protected-environment flag ([#10](https://github.com/Hikyo-Org/Hikyo/issues/10)). The membership UI MUST make the blast radius of an org-scoped grant visible at grant time (binds [#21](https://github.com/Hikyo-Org/Hikyo/issues/21)); an org-scoped `reveal` is not a mistake the system forbids, it is one it must not let a human make unknowingly.

*Deferred (fog): key-scoped or folder-scoped reveal restriction* ("only the DBA may reveal `DB_PASSWORD`"). The natural first extension when someone hits the wall; at this scale it multiplies the grant surface by every key and makes "why can't I see this?" unanswerable without a resolver UI.

*Rejected: org + project scopes only.* Kills the driving persona — the application developer who must see production key names, documentation, validation status and environment diffs **without** reveal rights.

## Capability atoms

| Capability | Scope | Covers |
|---|---|---|
| `read` | env | the environment exists; the project key catalogue, descriptions, schemas, validation status, diffs (write-presence only for `secret` keys); **`config` values** |
| `reveal` | env | current `secret` plaintext, by any route |
| `reveal-history` | env | superseded `secret` plaintext, by any route |
| `edit` | env | change values in the principal's own working state; creates no revision |
| `publish` | env | commit a revision — including rollback, `apply`, and any publish whose effect reaches this environment |
| `pin` | env | create, reassign or release a revision pin for this environment |
| `definitions-edit` | project | the definitions bundle: keys, rules, folder paths, and environment topology (create/delete environments, `base` pointers) |
| `project-settings` | project | protected-environment flag, `definitions_source`, reauthentication window, retention/quota policy |
| `manage-identities` | project | service accounts and their scoped credentials |
| `manage-adapters` | project | deployment-module configuration and sync triggering |
| `manage-members` | org / project | create, modify and revoke grants at or below that scope |
| `manage-projects` | org | create and delete projects |
| `backup-export`, `restore`, `rotate-root-key`, `rotate-master-key`, `rotate-dek`, `reencrypt`, `instance-config` | instance | the operator set ([#14](https://github.com/Hikyo-Org/Hikyo/issues/14)) |

**`backup-export` is deliberately *not* named `export`.** The encryption ADR's `export` produces an age-encrypted backup container, which discloses nothing without the backup identity and the root key. An unqualified `export` capability invites an implementer to authorize a *values* export — `values export --format dotenv`, which is managed plaintext — with it. Those are different powers and now have different names: see § *Value-bearing exports*.

### `read` is not split

Classification **is** the sensitivity boundary. A `config` value is by definition not secret, so a capability that shows a key's name, description and schema while hiding its `config` value protects nothing and doubles the ladder. Per-environment scoping already delivers "sees dev values, not prod values".

**Corollary, binding on the schema model:** *if a value needs hiding, classify it `secret`*. A quietly-sensitive `config` value is a misclassification to fix in the schema, not a permission to invent.

*Rejected: splitting `list` (metadata) from `read-config` (values).*

### `edit` and `publish` are separate

Distinct because the revision ADR already gives per-user working state with others'-pending markers — so `edit`-without-`publish` **is** a propose-and-review flow at zero extra machinery, the closest thing to approvals available without building an approval engine (presumptively out of MVP, [#26](https://github.com/Hikyo-Org/Hikyo/issues/26)). It is also the intended production posture for the application-developer persona: propose a production change, a platform engineer commits it.

Two consequences fixed here:

1. **No prerequisite chaining between capabilities.** `edit` without `reveal` is a valid, supported state — **write-only replacement** (blind rotation): set `DB_PASSWORD` to a new value without ever seeing the old one. Hikyo MUST NOT reject such a grant as incoherent, and the UI MUST support the write-only editing path (binds [#21](https://github.com/Hikyo-Org/Hikyo/issues/21)).
2. **A draft is never a disclosure.** `edit` confers no delivery power; pending values are visible to others as **presence**, and a pending `secret`'s plaintext remains `reveal`-gated exactly as a published one is.

*Rejected: a single `write` capability.* Any contributor able to touch production could publish to production — contradicting the least-privilege bind and deleting the only review path v1 has.

### The definitions side — one capability, and `apply` is not one

`definitions-edit` covers **exactly the definitions bundle** as the source-of-truth ADR defines it: keys, schema declarations, and environment topology including environment creation and deletion (a bundle `apply` creates non-matching environments, so the capability must reach them). The schema ADR's **`schema-edit`** is this capability under an earlier name; the two are the same grant, and `schema-edit` is retired as a term.

**`project-settings` is deliberately split out of `definitions-edit`**, because the protected-environment flag, the reauthentication window and `definitions_source: git` exist **to restrain the definitions-editor**. A guard whose off-switch sits in the hand it restrains is not a guard: whoever can flip `definitions_source` back to `db` can bypass the Git review gate entirely, so that switch must not travel with the capability it governs. Every `project-settings` change is audited; widening a reauthentication window and clearing a protected flag are security-relevant events, not preferences.

Non-semantic metadata (`description`, `deprecated`, `deprecation_note`, folder path) needs `definitions-edit` alone, as the schema ADR already fixed. Key creation, deletion and rename need `definitions-edit` **plus** per-affected-environment `publish`, likewise already fixed there.

## Authorization formulas, not single capabilities

Several operations require a **conjunction** of capabilities across **dynamically resolved** scopes. Every endpoint, CLI verb and job step MUST document one complete **authorization formula**; "the capability for this endpoint" is not a well-formed statement and MUST NOT appear in the API spec.

The formulas this ADR fixes:

| Operation | Formula |
|---|---|
| Read current `secret` plaintext (cell, diff, preview, validation of value-dependent rules, `values export`) | `read(E)` ∧ `reveal(E)` + reauthentication + one disclosure event per key |
| Read superseded `secret` plaintext (history, diff-against-revision, restore preview, historical `values export`) | `read(E)` ∧ `reveal-history(E)` + reauthentication + one disclosure event per key, recording the revision |
| Publish / rollback | `publish(E)` **for every affected environment** + protected-env confirmation for each protected environment reached + every disclosure check the operation dynamically triggers (below) |
| `apply` a definitions bundle | `definitions-edit(project)` ∧ `publish(E)` **for every affected environment** + protected-env confirmation for each protected environment reached ∧ every dynamically triggered disclosure check |
| Copy / clone / bulk-apply value material | `reveal(source E)` for current material, `reveal-history(source E)` for historical material, ∧ `reveal(destination E)` ∧ `publish(destination E)` |
| Create or reassign a revision pin | `pin(E)` ∧ `publish(E)`; **and `reveal-history(E)`** if the target is not the current revision |
| Mint or widen a credential's scope | `manage-identities(project)` ∧ `reveal(E)` for every added environment + reauthentication |
| Configure, widen or trigger an adapter | `manage-adapters(project)` ∧ `reveal(E)` for every environment it syncs + reauthentication |
| Delete a project | `manage-projects(org)` ∧ explicit confirmation naming the project ∧ no protected environment in it |

**Dynamically triggered disclosure checks** are the ones the schema and inheritance ADRs already fixed, restated here as a closed list so no implementer has to rediscover them: a publish that makes an environment **begin delivering a `secret` occurrence the publisher did not supply** requires `reveal` there (occurrence-keyed); one whose material is server-reconstructed from history requires `reveal-history`; **declassification** and **changes to value-dependent rules on `secret` keys** require `reveal` per affected environment, evaluated *before* evaluation; a **base-pointer re-parenting** that routes a `secret` occurrence into a new environment is a newly-delivered occurrence and is gated identically. **`apply` inherits every one of these** — a CI credential holding `definitions-edit` and `publish` cannot route a production occurrence into a development environment it controls, because that re-parenting triggers the reveal check and the credential does not hold `reveal`.

**Protected-environment confirmation for a machine principal** is an explicit field in the immutable plan the source-of-truth ADR already defines, naming each protected environment reached; it is never an interactive prompt and never implied by the presence of `publish`. A plan whose protected set has grown since it was produced is refused at `apply`, exactly as movement of any other pinned input is.

*Rejected: `apply` as its own capability.* It would be a bypass — `apply` without `publish` would publish.

## Value-bearing exports and standing delegations

Three constructs hand out plaintext without a human looking at a cell. Each is a **standing delegation** and is governed as one.

**Exports.** `definitions export` needs no permission gate (the source-of-truth ADR: it discloses only declarations the exporter can already read). **`values export`** carries the disclosure formula in full, with no abbreviated variant: current material requires `read(E)` ∧ `reveal(E)`; historical material requires `read(E)` ∧ `reveal-history(E)`; **both** require reauthentication and per-key disclosure audit, the historical one recording the revision. A principal holding only the `historian` template — `reveal-history` without `read` — cannot export, exactly as they cannot read a cell. **`backup-export`** is an instance capability producing an age-encrypted container and is never a values export.

**Pins.** A pin is a durable delegation to deliver a specific historical revision indefinitely (revision ADR: pins are "durable, authorized, bounded resources" with "an authorization check at creation" — this ADR supplies that check). Creating or reassigning a pin to a **non-current** revision is historical disclosure by delegation: it requires `reveal-history(E)` **at creation**, with reauthentication and audit, because otherwise a principal holding only current `reveal` mints a workload credential, points it at a pin, and reads superseded credentials that may still be live in an external service. Each pin records the **authorizing principal**; **every fetch against a pin re-checks that principal's current `reveal-history(E)`** and fails closed when it is gone. Releasing a pin requires `pin(E)` only.

**Adapters.** Every durable adapter configuration records an **authority principal**, and **any mutation that changes where plaintext goes atomically reassigns authority to the acting principal** — destination or recipient, provider account, outbound credential, environment selection, and delivery routing all count, not merely widening the environment set. Before **every** secret read and **every** outbound push, scheduled, retried or reconciliation-triggered, the job re-checks the recorded authority principal's current `manage-adapters(project)` ∧ `reveal(E)`; if either is gone, the remaining sensitive steps abort with a terminal audit outcome. An adapter MUST NOT run under an ambient system principal — that is exactly how a revoked employee's Forgejo organization keeps receiving production secrets forever.

The reassignment rule is not bookkeeping, it is the defence against **authority laundering**: without it, a principal holding `manage-adapters` ∧ `reveal` briefly can repoint an existing adapter at a destination they control **without touching its environment scope**, leave the previous owner recorded as authority, and keep receiving production secrets after their own grants are revoked — every push re-checking someone else's still-valid authorization. Because reassignment is atomic with the mutation, such a change requires the actor to hold `manage-adapters(project)` ∧ `reveal(E)` for **every** environment the adapter syncs, and it fails if they do not; there is no path that mutates routing while leaving authority behind.

**Adapter outbound credentials are write-only.** The provider token an adapter uses is a protected asset (threat model §Assets). List and get return **redacted presence and metadata only** — never the credential — and replacement never returns the prior value. There is no capability that reads it back in v1; recovering a lost provider token is the provider's job, not Hikyo's.

## The reveal guard — one mechanism, one knob

The threat model already fixed *that* a reauthentication step precedes reveal. This ADR fixes its shape:

**A sliding reauthentication window, configured per environment under `project-settings`, where `0` means every disclosure.** A principal holding `reveal` or `reveal-history` reauthenticates once; disclosures stay unlocked for the window (recommended default 5 minutes, sliding; concrete value in the operations spec). Protected environments are **not a different mechanism** — they are the same knob, and marking an environment protected **caps** its window at the protected default (recommended `0`, per-disclosure) rather than merely suggesting it; raising a protected environment's window above the cap is refused, and every window change is audited.

Invariants that hold regardless of the window:

- **The window gates the reauthentication prompt, never the authorization check.** The capability is re-checked against current policy immediately before every render or delivery. A revoked `reveal` grant stops revealing on the next cell, inside an open window.
- **The gate covers `reveal-history` identically**, and covers every route in the formula table — cell reveal, diff, impact preview, restore preview, `values export`, copy, and pin creation — not only the matrix cell.
- **Every disclosed key emits its own audit event.** Bulk reveal (a matrix "reveal column" action) is permitted and expands to one event per key — the audit trail must never record "revealed 40 secrets" as a single row. Historical disclosure records the revision read.
- **Client-side remasking** (idle auto-remask, clipboard behaviour, no-cache) is a UI obligation owned by [#21](https://github.com/Hikyo-Org/Hikyo/issues/21), not a permission. It is defense in depth, never the boundary.

**Reauthentication does not apply to machine identities** — the token *is* the credential and there is no second factor to re-present. Machine disclosure is instead controlled by the explicit per-project opt-in below, narrow scope, individual revocability, and per-fetch audit.

*Deferred (fog): reason-for-access strings and approval-to-reveal.* A reason field with no reviewer is compliance theatre; approval workflows are presumptively out of the MVP.

*Rejected: two mechanisms* (sliding window for ordinary environments, per-burst reauthentication for protected ones). Identical protection to setting the knob to `0`, at the cost of two code paths on the most security-sensitive path in the product.

## Disclosure by proxy — the governing principle

> **Any operation that causes secret plaintext to leave Hikyo's boundary toward a destination the actor controls is a disclosure, and carries the disclosure capability — whether or not the actor's eyes see the value.**

This is why minting a credential, widening its scope, configuring or triggering an adapter, creating a non-current pin, exporting values, and copying material between environments all appear in the formula table with `reveal` or `reveal-history` attached. Without the rule, a project maintainer holding neither could `curl` production.

The symmetric limit, so the rule does not become a hostage: **revoking** a credential, **deleting** an adapter configuration, **releasing** a pin, **narrowing** any scope, and **listing** any of them stay under the plain capability. These are destructive-but-not-disclosing; requiring `reveal` to revoke a leaked token would be a self-inflicted incident-response delay.

*Rejected: folding `manage-identities` / `manage-adapters` into `reveal`.* Over-collapses — someone must be able to revoke a token or delete a broken adapter without holding secret access.

## Administrative power — bounded where the threat model bounds it

The threat model trusts **org administrators within their own org** and documents that trust publicly. It does not extend that trust to project administrators, so this ADR does not either.

- **Unheld-capability granting is an org/instance power only.** `manage-members` held at **org or instance** scope may grant capabilities the grantor does not hold — the escalation path the threat model already accepts, and the one that keeps a fresh installation bootstrappable. `manage-members` held at **project** scope may grant only capabilities the grantor **currently holds** at or above the target scope. A stolen project-admin account is therefore not automatic full compromise of that project's secrets; it is exactly the authority that account was actually given.
- **The `admin` template seeds `reveal` and `reveal-history`** alongside the administrative capabilities, as separate revocable grants (see the amendment note at the top). A default administrator can read secrets, per the revision ADR; an installation can strip that from an individual administrator without dismantling their administrative authority, and the audit log still distinguishes administration from disclosure because the disclosure events are per-key and the grants are per-capability.
- **The `operator` template does not seed `reveal` or `reveal-history`.** The operator set is crypto custody, not data reading, and the encryption ADR requires those capabilities never be bundled with org administration. An operator holding instance `manage-members` can self-grant — audited, visible, and never silent.
- **Instance scope inherits downward like every other scope.** An instance operator can therefore reach any org's data through an explicit audited grant, never by bundle.

*Rejected: admin holds no reveal at all.* It contradicts the locked revision ADR outright; the amendment above achieves the audit benefit without reversing a locked decision. *Rejected: separation of duties (an admin may not self-grant; a second admin must).* Genuine protection at scale, but single-admin installations are the norm at this project's target size, so it either bricks the installation or is bypassed by creating a dummy second admin — a mechanism that teaches users to defeat it.

## Role templates (v1, closed)

Applying a template creates the listed capability grants at the chosen scope, each independently visible and revocable.

| Template | Applicable at | Creates |
|---|---|---|
| `viewer` | org / project / env | `read` |
| `editor` | org / project / env | `read`, `edit` |
| `publisher` | org / project / env | `read`, `edit`, `publish`, `pin` |
| `revealer` | org / project / env | `reveal` |
| `historian` | org / project / env | `reveal-history` |
| `maintainer` | org / project | `publisher` + `definitions-edit`, `manage-identities`, `manage-adapters` |
| `admin` | org / project | `maintainer` + `project-settings`, `manage-members`, `reveal`, `reveal-history`, and `manage-projects` *(org scope only)* |
| `operator` | instance | operator set + `manage-members` |

**Disclosure is always its own grant, never folded into a level.** `viewer` + `revealer` on production is the SRE who reads but never writes; `publisher` on dev + `viewer` on prod is the application developer this ticket set out to serve. Because `reveal` is always a separate row — including inside `admin` — the membership list always answers "who can read production secrets?" by inspection.

**`reveal-history` implies nothing about `reveal`, and vice versa.** The revision ADR split them deliberately: across a rotation boundary a superseded credential may still be live in an external service, or may unlock decommissioned infrastructure the current one cannot reach.

*Rejected: reveal-carrying variants of each level* (`viewer`, `viewer+secrets`, `editor`, `editor+secrets`, …). Doubles the template count and buries the most sensitive grant inside a compound name.

## Evaluation, revocation, lockout, recovery

1. **One chokepoint, no authorization cache.** Every sensitive operation calls a single `authorize(principal, capability, scope)` that reads current policy from the database **inside the operation's own transaction**. There is **no cross-request permission cache in v1**: at this scale the read is free, and a cache is precisely how "revocation is immediate" quietly becomes false. Should a future cache become necessary, it MUST be invalidated synchronously within the granting/revoking transaction — this ADR reopens rather than being read as permitting a stale-tolerant cache.
2. **Re-authorize before every sensitive step, not once per job.** Long-running or queued work — multi-environment publish, adapter sync, bulk delivery, pinned fetch, `reencrypt` — re-authorizes before **every** secret read and **every** outbound push, against the **recorded authority principal** where the work is a standing delegation. A revocation mid-job aborts the remaining sensitive steps and records a terminal audit outcome.
3. **Revocation is atomic across artifacts.** Removing a principal, or revoking a single capability grant, invalidates in **one transaction**: their sessions, the credentials whose authority derived from that grant, and any in-flight job's remaining authorization. A service account losing `reveal` stops delivering secrets on its next fetch, not at token expiry.
4. **Unauthorized and nonexistent are indistinguishable.** Tenant ownership and authorization are resolved **before** any object-specific error is produced: an environment, key, revision, pin or project the caller may not `read` returns the same status and body shape as one that does not exist, on every route — lookup, mutation, plan, pin, copy, history, delete. Bulk operations MUST NOT leak omitted objects through counts, partial results or differential timing. Validation errors already carry the schema ADR's stricter rule (schema locations, never instance-derived paths).
5. **Lockout invariant.** Removing the last `manage-members` holder at org scope is **refused** — an unadministrable org is a support incident with no in-product recovery. Removing the last instance `manage-members` holder is likewise refused; recovery from that state is the local procedure below, and the API MUST NOT offer it.
6. **Break-glass is local host authority only.** Recovery grants are issued by a CLI invocation on the host that requires local access (server stopped, or a root-owned local socket) **and** access to the root key, has **no network route and no HTTP endpoint**, names its target principal and capability explicitly, and writes a durable recovery audit record. This adds no attacker capability — host plus root key already means full control-plane compromise per the threat model — and it is the only authorization path in the system not evaluated against a grant.
7. **Restored grants are quarantined, not policy.** After a restore the instance boots in the threat model's fail-closed recovery mode, and the authorization layer treats restored grants as **inert data**: ordinary authorization denies everything until an operator, acting under local recovery authority, explicitly commits the reconciled grant set and exits recovery mode. Without this, a restore silently resurrects a revoked administrator's `reveal` the moment credential revalidation completes.

## Machine principals

Service accounts are principals in the same grant table; the credential carries the identity, and there is no second permission language for machines. Credential formats and lifecycle belong to [#17](https://github.com/Hikyo-Org/Hikyo/issues/17). The **allowlists below are normative** — the grant API MUST refuse a capability outside its principal class's list, rather than leaving the restriction to convention:

- **Workload credentials** — `read` at explicit `(project, environment)` scope, plus `reveal` **only** by the source-of-truth ADR's explicit, documented, per-project operator opt-in, plus `reveal-history` **only** where a pin requires it and only under the pin rules above. Nothing else: no `edit`, no `publish`, no `pin`, no management capability. This is the threat model's "read-only, the only v1 workload capability".
- **Automation credentials** (CI `apply`) — `read`, `edit`, `publish`, `definitions-edit` at one project's scope, plus `reveal` **only** under the same explicit per-project operator opt-in as a workload credential, and plus `reveal-history` **only** where a pin requires it under the pin rules above. Never any `manage-*` capability, never `pin` creation for a non-current revision outside that opt-in. **Granting `apply` grants no disclosure**: `reveal` is never implied by `definitions-edit`, by `publish`, or by the two together — it is a separate, deliberate, per-project act, and the UI MUST state at opt-in time that a CI runner holding `reveal` is a standing decryption capability in the most-attacked box in the system (source-of-truth ADR § *Reveal escalation*).
- **No machine principal may hold `manage-members`, `manage-projects`, `project-settings`, or any instance capability** in v1.

## Reconciliation with upstream ADRs

- **Threat model ([#8](https://github.com/Hikyo-Org/Hikyo/issues/8))** — deny-by-default within an org: additive-only grants, no denies. Separate grants not bundles: satisfied **at grant time** by storing capabilities and treating roles as templates. Authorize-before-each-effect: § *Evaluation* 1–2, with standing delegations pinned to a recorded authority principal. Atomic deprovisioning: § *Evaluation* 3. Trusted-admin boundary: unheld-capability granting confined to org/instance scope, where that trust actually exists.
- **Inheritance ([#10](https://github.com/Hikyo-Org/Hikyo/issues/10))** — per-environment `publish` against every affected environment immediately before commit; protected flag and confirmation carried by `project-settings`, with the flag also capping the reauthentication window; reveal-gated impact preview, since `reveal` is never conferred by `publish`; base re-parenting that routes a secret occurrence is a dynamically triggered disclosure check.
- **Revisions ([#11](https://github.com/Hikyo-Org/Hikyo/issues/11))** — `reveal`/`reveal-history` distinct atoms and distinct templates; the default administrator holds both, seeded as separate grants (amendment above). Pin creation supplies the authorization check that ADR requires, with historical pins gated on `reveal-history` and re-checked per fetch. Per-event, per-object authorization for live-update projection follows from the uncached per-capability chokepoint.
- **Schema ([#12](https://github.com/Hikyo-Org/Hikyo/issues/12))** — project-scoped schema editing distinct from publish and reveal: `definitions-edit` (renaming `schema-edit`). Declassification and value-dependent rule changes on `secret` keys, newly-delivered occurrences, and restores appear in the dynamically-triggered list. Key creation/deletion/rename under `definitions-edit` plus per-affected-environment `publish`.
- **Source of truth ([#13](https://github.com/Hikyo-Org/Hikyo/issues/13))** — `definitions-edit` is an atom; `apply` decomposes **and carries every dynamic disclosure check**. The `definitions_source: git` guard sits in the same chokepoint but is **not** a permission — a Git-governed project refuses UI definitions writes regardless of capability, and its off-switch lives in `project-settings`. `definitions export` ungated; `values export` gated per § *Value-bearing exports*. Machine `reveal` as explicit opt-in never implied by `apply`.
- **Encryption ([#14](https://github.com/Hikyo-Org/Hikyo/issues/14))** — the operator set is instance-scoped and excluded from every org template; `export` renamed `backup-export` so it can never be read as a values export. **Project deletion crypto-shreds a project DEK and is irreversible**: `manage-projects` plus explicit confirmation naming the project, refused while any environment in it is protected.

## Propagations (binding on downstream tickets)

- **Human auth ([#16](https://github.com/Hikyo-Org/Hikyo/issues/16))** — MUST supply a reauthentication primitive satisfying the sliding-window gate including a `0`-window mode; MUST rotate sessions on privilege change; MUST make deprovisioning atomic with grant revocation; MUST bootstrap the first administrator via the `admin` template (so `reveal`/`reveal-history` are seeded as separate visible grants) and MUST implement the local break-glass procedure's identity proof.
- **Machine identities ([#17](https://github.com/Hikyo-Org/Hikyo/issues/17))** — MUST implement the two credential classes with the normative allowlists; MUST enforce `reveal` on each environment added when minting or widening; MUST make revocation effective at next fetch, not at expiry; MUST carry the pin authority re-check on pinned delivery.
- **Compose ([#18](https://github.com/Hikyo-Org/Hikyo/issues/18)) / Kubernetes ([#19](https://github.com/Hikyo-Org/Hikyo/issues/19))** — the operator/agent authenticates as a workload principal at explicit `(project, environment)` scope; every fetch re-authorizes, including pinned fetches against the pin's authority principal.
- **Prototypes ([#20](https://github.com/Hikyo-Org/Hikyo/issues/20), [#21](https://github.com/Hikyo-Org/Hikyo/issues/21))** — MUST render the reveal gate (window state, reauth prompt, per-cell disclosure), the write-only replacement path, the membership list with each capability as its own revocable line, redacted adapter credentials, and a blast-radius warning when a grant is made at org scope.
- **Architecture ([#22](https://github.com/Hikyo-Org/Hikyo/issues/22))** — MUST place `authorize()` as a single chokepoint the request and job layers cannot bypass, evaluated in-transaction with no permission cache, and MUST provide the recovery-mode state in which restored grants are inert.
- **Tenant isolation ([#23](https://github.com/Hikyo-Org/Hikyo/issues/23))** — MUST compose scope resolution with tenant scoping in that same chokepoint, and MUST deliver the unauthorized/nonexistent indistinguishability rule at the response layer; a grant lookup crossing an org boundary is an isolation failure, not an authorization result.
- **Audit ([#24](https://github.com/Hikyo-Org/Hikyo/issues/24))** — MUST emit events for: grant created/modified/revoked (self-grants distinguishable), disclosure (one per key, with revision id for historical), credential mint/widen/revoke, adapter configure/widen/authority-change/sync, pin create/reassign/release, `project-settings` changes including window widening and protected-flag clearing, recovery-mode entry/exit and break-glass grants, and **authorization denials**.
- **API & CLI ([#25](https://github.com/Hikyo-Org/Hikyo/issues/25))** — MUST document a complete **authorization formula** per endpoint and verb, never "the capability for this endpoint"; MUST keep `values export` and `backup-export` as separate verbs with separate formulas; MUST NOT expose break-glass over the network.
- **Deployment-module seam ([#28](https://github.com/Hikyo-Org/Hikyo/issues/28))** — MUST carry the authority principal, the per-push re-check, and write-only outbound credentials.
- **MVP boundary ([#26](https://github.com/Hikyo-Org/Hikyo/issues/26))** — custom templates, key-scoped reveal, reason-for-access, and approval-to-reveal are recorded here as fog and need an explicit in/out decision.
- **Operations spec (fog)** — default reauthentication window, protected-environment window cap, pin quotas and expiry, grant-count bounds per org.
