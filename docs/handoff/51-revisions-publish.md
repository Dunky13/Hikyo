# Handoff: #51 revisions & publishing — drafts, snapshots, change token, SSE

Issue: https://github.com/Dunky13/hikyo/issues/51 (parent #41, blocked by #50 — merged).
Specs, all on `wayfinder-docs`: `docs/adr/revision-model.md` (primary, read
through its two amendment banners), `docs/adr/flat-model.md` (its ripple
register governs every `layer` the revision ADR names),
`docs/adr/schema-model.md` (validation timing, key groups, the change token's
delivery manifest), `docs/adr/system-architecture.md` § Real-time,
`docs/adr/mvp-boundary.md` §1.1 + rows C4 and C2,
`docs/adr/permission-model.md` (capability atoms),
`docs/adr/encryption-model.md` (CI invariant 15, token-key rotation),
`docs/adr/api-cli-surface.md` (verb set, output grammar).

Scope: the draft → publish lifecycle. Per-user pending changes with immutable
version ids, selective publish with key-group closure, publish as the sole
authority for validation and for writing delivered state, immutable resolved
snapshots per `(project, environment)`, per-environment monotonic revisions,
the keyed change token, `rotate-token-key`, snapshot fetch, and the SSE
advisory channel with its polling fallback. **Not** in scope and still #52's:
rollback/restore, pins, and payload retention/GC.

## The shape of the slice

Three tables and one rule explain everything else:

    value_entries   the PUBLISHED state. Only the publish pipeline writes it.
    pending_changes per-user WORKING state. `values set` writes it, and nothing
                    reads another owner's material.
    snapshots       the immutable per-environment materialization that delivery
                    reads. Publish is the only thing that creates one.

**Publish is the authority.** Saving is free — a draft may hold a type-invalid
value, may clear a `required_in` key, may sit against a stale baseline. Every
one of those is refused at publish, loud, naming what failed. That is the schema
ADR's "advisory on save, authoritative at publish" made structural: there is
exactly one place where validation decides anything, and it is `materialize`.

### Store (`migrations/{sqlite,postgres}/00019_revisions.sql`)

Four tables, **two retention classes**, split structurally rather than by
policy note:

- `snapshots` + `revision_key_changes` are **lineage**, retained indefinitely.
  Revision number, publisher, timestamp, pinned schema revision, and which keys
  changed. Never a value in any form — not a plaintext, not a length, not a
  digest, not a changed-from marker.
- `snapshot_entries` is **payload**: the value-bearing materialization, and what
  retention policy collects (#52). Collecting it leaves the lineage intact,
  which is the ADR's "a collected revision cannot be restored, diffed by value,
  or revealed" with nothing left to reconstruct it from.
- `pending_changes` is neither: working state, published or discarded.

Three decisions in that migration are load-bearing:

- **There is NO change-token column.** The token is
  `HMAC(scoped token key, delivery manifest)` derived from the *current* root
  token key at read. Storing it would make `rotate-token-key` either a rewrite
  of immutable history or a silent lie. Deriving it is what lets rotation change
  every token while content, revision numbers and pinned inputs stay put — C4's
  criterion, held by the schema rather than by a test.
- **Superseded drafts are collected immediately.** `UNIQUE (chain, environment,
  key, owner)` is the schema ADR's Bounds amendment expressed as a constraint:
  one live version per `(owner, cell)`, so a client saving in a loop cannot grow
  the table at all, and "only the latest version is publishable" needs no flag.
- **Two baseline columns**, because the ADR states two different facts.
  `staged_from_revision` is provenance a client shows ("staged from rev 12").
  `staged_from_entry` is the freshness check: the published value-entry row id
  the cell held at staging time. The rule is stated **per entry** — "the
  published state of any selected entry has advanced" — and per-entry is also
  the only usable reading, since an environment-wide comparison would invalidate
  every outstanding draft whenever any unrelated key published.

`snapshot_entries.value_entry_id` is the pinned value-entry revision. It is
metadata, not a reference — the cell is delete-then-insert, so the row it names
may be gone and the snapshot must keep answering. Hence no foreign key.

Ciphertext on both new value-bearing columns rides the **existing**
`project_field` envelope kind with the row's own id as `owner_row_id`
(`snapshot_entries`/`pending_changes` as `owner_table`). No new AAD kind was
invented: the encryption ADR's six-kind set is closed. These two new tables use
`ProjectFieldAAD`'s owner-coordinate extension to bind environment and key;
snapshot entries also bind snapshot id. A ciphertext lifted onto another draft,
snapshot, key, or environment therefore stops opening even if its row id stays
unchanged.

### Service

- `internal/service/publish.go` — `Publish`, `selectVersions` (key-group closure
  over `(group, environment)` pairs to a fixed point), `checkFreshness`,
  `materialize` (**the** publish primitive), `validateResolved`, `lineage`,
  `republish`, `fanOutSchemaPublish`.
- `internal/service/revisions.go` — `History`, `Show` (derives the change
  token), `Signals` (matrix signals), `Export`, `RotateTokenKey`.
- `internal/service/advisory.go` — the in-process SSE fan-out.

**Every path that advances an environment goes through `materialize`**: a
selective publish, `values declare`, `values copy`, `env create`/`clone`, and a
semantic schema change's fan-out. That is why validation, lineage and the
snapshot have exactly one implementation. `republish` is `materialize` with no
drafts applied — "publish the current state as a new revision" — and it
re-evaluates `publish` on the environment **immediately before commit**, even
where the calling operation already carried a `publish(destination)` conjunct,
because a check performed earlier in the same transaction is not that.

Which verbs stage and which publish:

| verb | effect | formula |
|---|---|---|
| `values set`, `values set --clear` | STAGE only | `edit@env` |
| `values publish` | commits named versions + closure | `publish@env` per affected env |
| `values declare` | writes + materializes | `edit ∧ publish` per destination |
| `values copy` / clone | writes + materializes | the locked copy row, unchanged |
| semantic `key`/`key group` mutation | materializes EVERY environment | `definitions-edit@project` ∧ `publish@env` per environment |
| `env create` / `clone` | materializes revision 1 | `definitions-edit` ∧ `publish@newEnv` |

### Authorization

New operations: `value.stage` (`edit@env` **alone** — `edit` confers no
delivery power and a draft is never a disclosure), `value.publish`
(`publish@env`), `value.export` / `value.export-reveal` /
`value.export-reveal-history` (the locked export triple, each evaluated over
exactly the material it governs), `revision.list` / `revision.show` /
`revision.signals` (all bare `read@env`, audited-none), `advisory.watch`
(`read@project`, connect) and `advisory.event` (`read@env`, per event), and
`crypto.rotate-token-key`.

`rotate-token-key` rides **`rotate-dek`**: the permission ADR's capability set
is closed and names four rotation atoms for five rotation verbs, and the root
token key is a tier-3 key alongside the DEKs — same master, same
one-active-per-scope index, same retirement path.

It reaches the store through **one** new store method, `keys.RotateTokenKey`,
which takes the hierarchy-generation fence, retires the active token key and
inserts its successor. One method rather than the three calls it performs
because `keys.AcquireHierarchyGeneration` and `keys.InsertTier3` are bound to
the boot mint site, and invariant 6 forbids a store method being both
grant-evaluated and site-bound. The site set is closed by the tenant-isolation
ADR, so widening it was not an option either.

### Audit

Three new types: `value.staged` (a draft, carrying the version id a later
`revision.published` names — deliberately its own type, because an investigator
asking "when did this environment start delivering X" must not have to filter
staged edits out of the answer), `revision.published` (one per environment
advanced, with `trigger` saying which act produced it), and
`crypto.token_key_rotated`. Its payload field is spelled `key_version`, not
`token_key_version`: invariant 4's schema half forbids a `token_`-prefixed
field, and the guard is a name-shape rule worth keeping literal.

`value.set` / `value.cleared` moved emitters: they are now emitted from
`materialize`, per cell a pending apply moved, because that is where delivery
actually starts and stops. A schema fan-out moves no content and emits none;
copy/clone keep emitting `disclosure.value_copied`.

### Delivery

`Delivery.Fetch` now reads the environment's **latest committed snapshot** and
fails closed (`ErrNotMaterialized`) where there is none — the flat-model ADR's
"delivery reads only committed, valid snapshots" made structural. The manifest
the change token covers became ordered `(key, classification, value)` triples,
so the token moves when a value moves; presence **left** the manifest, so
tightening `required_in` no longer fires a rollout wave. What the caller
receives is unchanged from #62: names, classifications and presence, no
plaintext — delivering plaintext to a workload is the render path's act
(#18/#63), with its own formula and per-key disclosure records.

One placement is worth knowing about: the project sealer is resolved **before**
the fetch transaction, and a refusal there routes through `recordUnbound` like a
refusal inside it. Without that, moving the sealer ahead of the transaction
would have silently moved every federated refusal off the audited path.

### SSE

`GET /api/v1/orgs/{org}/projects/{project}/events`. Metadata only —
`AdvisoryEvent` has no field that could hold a value or a change token, which is
the cheapest way to keep the rule. Every event is authorized against the
environment it names, **at emit time**, so a grant revoked mid-session bites on
the next event rather than at the next reconnect; unauthorized references are
dropped and an event reduced to nothing is not sent. Bounded per-subscriber
buffer with slow-client disconnect, heartbeat comments,
`Cache-Control: no-cache` + `X-Accel-Buffering: no`, and `Last-Event-ID` replays
nothing. **The polling fallback is `values pending` / `GET …/signals`** — the
same facts pulled under the caller's own authorization, which is the matrix's
ordinary read anyway.

### CLI

`values pending | publish | export`, `revision list | show`,
`rotate-token-key`. `values set` now prints the staged version id and tells the
caller how to publish it. `revision list|show` carry **no** reveal path at all:
history is lineage, and the one verb that reads a snapshot's values is
`values export`, which sits behind the print triad with the other value verbs.
`rotate-token-key` warns before proceeding and needs `--yes`; the warning states
cursor invalidation and one full fetch, **not** a restart wave (#19's
amendment).

## Contradictions requiring disposition

**Schema-edit draft-ification is deferred, and that is a genuine ADR
contradiction, not a clean resolution.** `schema-model.md` line 187 ("one
publish carries the schema pending change and the value pending changes
together") and line 209 ("Group membership changes are schema pending changes"
participating in closure) say schema edits ARE ordinary pending changes. This
slice implements the *effect* — a semantic catalogue mutation validates,
authorizes `publish` on every environment, and materializes a new snapshot for
each — but keeps #49's immediate-mutation shape rather than routing catalogue
edits through `pending_changes`.

Consequences, stated so nobody rediscovers them:

- **Group membership changes cannot participate in closure**, because there is
  no schema pending version for closure to select. Closure runs over value
  versions only. Rule 7 of the schema ADR's closure algorithm is unimplemented.
- **A key creation cannot ride in the same publish as its first value.** The
  operator orders it: declare the key unconstrained, publish the value, then
  apply the presence rule. This is visible in the conformance fixtures and is
  the same order a real operator must follow.
- Under the canonicality rule this reopens the owning ticket. Human tracker
  action, not a code change here.

## Dispositions carried from the orchestrator (accepted)

1. **Pins are #52's**, not a fetch parameter. Snapshot fetch is latest-only;
   `revision show` / `values export` take an explicit revision as an authorized
   *read*, never as delivery pinning.
2. Schema-edit draft-ification deferred — see the contradiction register above.
3. `rotate-token-key` rides `rotate-dek` (closed capability set; tier-3 key).
4. `Declare`/`Copy`/`Clone` publish immediately because their locked formulas
   carry `publish(destination)`; a draft would make that conjunct premature.
   `Set`/`Clear` stage. The asymmetry is deliberate and worth grilling.
5. Delivery still returns no plaintext; the render path is #18/#63's.
6. The SSE connect check is `read@project` and per-event is `read@env`. An
   environment-only-scoped principal therefore cannot open the stream and must
   poll `…/signals` instead. That is the same grant the matrix's key-catalogue
   read already needs, so it excludes nobody who could use the channel — but it
   is a real limitation and the polling fallback is what covers it.

## Other decisions taken in-slice

- **`values export`'s wire eligibility is human-session only.** A machine
  principal *can* export — `read` alone returns `config` plaintext and `secret`
  write-presence — but the route's declared formula is the revealing one, and no
  machine class in the permission ADR's allowlists may hold `reveal` today:
  machine `reveal` arrives through the source-of-truth ADR's explicit
  per-project operator opt-in, which is not modelled yet. Declaring an
  eligibility the registry cannot honour would be a lie on the wire.
- **Deleting a key discards every pending change referencing it** (schema ADR
  § Key identity). Without it, Alice's staged edit stays publishable after Bob
  deletes the key and the publish resurrects a key the schema no longer
  declares. The #50 refusal on published values is unchanged — turning that into
  an authorized cascade is still #49's disposition 4.
- **A `mode: all` required secret absent at source is now unreachable state.**
  #50 fixed a clone that stranded one; under #51 the *declaration* that would
  create the stranding is vetoed first, naming key and environment. The
  conformance scenario asserts the earlier, stronger refusal rather than the
  clone abort it replaced.
- **The sealer for a semantic schema change is resolved before the
  transaction.** Resolving one mints the project data key on first use, and
  minting opens a write transaction that would wait forever on sqlite's single
  write connection for the transaction that asked for it. An earlier draft
  resolved it inside the fan-out and deadlocked the backup drill at the 15 s
  retry deadline; that is the bug this placement exists to prevent.

## Test map

| criterion | test |
|---|---|
| C4 concurrent publish serialization | `conformance: publish_is_serialized_per_project` |
| C4 selective publish + group closure + cross-user refusal | `conformance: selective_publish_closes_over_key_groups` |
| C4 `rotate-token-key` moves only the token | `conformance: rotate_token_key_moves_only_the_token` |
| C2 signals recomputed for exactly the touched environments | `conformance: publish_recomputes_signals_for_touched_environments` |
| C2 semantic schema publish fans out to every environment | same scenario, second half |
| C2 `required_in` absent vetoes publish naming key + environment | `conformance: required_in_absent_vetoes_publish` |
| saving is free; validation moved to publish | `conformance: value_set_delivers_absent_delivers_nothing` |
| demo path: edit → selective publish → CLI snapshot fetch → SSE advisory | `isolation: TestDemoFlow{SQLite,Postgres}` → `runRevisionDemo` |
| the change token moves with a VALUE, and not with a presence rule | `isolation: TestDeliveryChangeTokenTracksTheManifest*` |
| delivery reads only committed snapshots | same file: a fetch before materialization fails closed |
| every registered audit type has an emitter | `isolation: runValueLifecycle` (extended with staged/published/rotated) |
| no rolled-back mutation leaves a draft, snapshot, payload or lineage row | `isolation: fixtureTables` row-diff, extended with the four new tables |

Commands:

    go test ./internal/conformance/ -count=1 -run TestConformanceSQLite
    go test ./internal/isolation/ -count=1 -run 'TestDemoFlowSQLite|TestDelivery'
    # database must be OWNED by the hikyo role (the harness drops tables);
    # wenv_test is owned by role wenv and fails with "must be owner of table"
    HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_51_revisions \
      go test ./internal/conformance/ ./internal/isolation/ -count=1

## Known gaps / deferred

- **Rollback, restore and pins are #52's.** `revision rollback` and the `pin`
  verb group do not exist; `reveal-history` has one operation
  (`value.export-reveal-history`) and no historical-material path beyond it,
  because until #52 there is no restore that reconstructs historical material.
- **Payload retention and GC are #53's** (C6). Nothing collects
  `snapshot_entries` yet; the split that makes collection possible is in place.
- **Schema edits are not pending changes** — see the contradiction register.
- **The advisory channel is in-process.** v1 is a single node; a channel that
  must survive a second node is a different design, not a bigger buffer.
- **No UI for any of this.** The SPA's `useSetValue` was corrected to parse the
  staged-change shape it now receives; the matrix's pending/recently-changed
  rendering is #56/#20's.

## Review round 1

Dispositions accepted:

- The service-layer publish conformance seam follows the #50 precedent documented
  at the head of `internal/conformance/values_test.go`: it controls timing only,
  exposes no material, and keeps both real engines under the service path.
- `pending.stale` remains a broadcast rather than owner-targeted. It is metadata
  only and every event is projected through current per-environment authorization
  before a subscriber can receive it.

Fixes:

1. Copy now re-materializes each destination once after all copied cells land in
   the transaction; key schema fan-outs retain their results and emit post-commit
   advisories. Declare, clone, and create already terminate in `republish`.
2. Publish resolves the selected owner's rows, authorizes every selected
   environment, then reads group closure; a code assertion rejects any closure
   that adds an environment.
3. Group closure checks cross-owner markers on the selected member itself as well
   as its siblings; the conformance case covers the exact same `(env,key)` cell.
4. Pending and snapshot project-field AAD now also binds environment and key;
   snapshot entries additionally bind snapshot id. Cross-metadata transplant
   tests fail with `crypto.ErrDecrypt`.
5. The PostgreSQL serialization scenario pauses the first publish after its
   baseline read, starts the second real transaction, and proves it cannot reach
   its own baseline checkpoint until the first releases.
6. Removed `TokenKeyVersion`; reduced `PendingMarker` to used write-presence
   fields; trimmed both marker queries and regenerated sqlc output.
7. Corrected the two `...Environent` store-operation identifiers to
   `...Environment`; their registered string values were already correct.
8. Extracted semantic schema publication into `schemaPublisher`, including its
   pre-transaction sealer resolution, single fan-out explanation, result capture,
   and post-commit advisory emission.
9. Advisory admission now has per-principal, per-organization, and instance-wide
   caps; the SSE preamble suggests a jittered reconnect delay with `retry:`.
10. A real subscriber connects with project read, is narrowed to one environment,
    receives that environment's event, and receives no event for the unauthorized
    environment.

Declined as judgement calls (Standards-axis smells, dispositioned, not
forgotten): the `(ctx, r, az, caller, p, sealer, kr, scope, now, trigger)`
publish-context data clump stays unbundled — a context struct would hide which
call needs which authority proof, and the explicitness is the point at this
seam; the free-form `trigger` strings stay strings — they are audit payload
prose, not a dispatch domain, and a constant set would add a type for a value
nothing branches on.

## Review round 2 — external scanners on PR #109

Aikido's deep review returned six mediums; two were real, four are rebutted
here so nobody re-litigates them:

- **FIXED — historical export demanded current `reveal`.** `Export` authorized
  `value.export-reveal` before knowing whether the named revision was
  historical, so a `read + reveal-history` holder (the two are independently
  strippable grants) was refused material the formula admits. Now: `read` is
  authorized first, the snapshot decides current-vs-historical, and exactly ONE
  of `export-reveal` / `export-reveal-history` is evaluated. Pinned by the
  `historical_export_takes_reveal_history_not_reveal` scenario, both
  directions, both principals.
- **FIXED — `pending.stale` claimed a fact nobody checked.** The per-key
  advisory on publish is now `cell.changed`: the publisher's transaction never
  reads other principals' markers, so it must not assert their drafts went
  stale. A subscriber holding a draft on the named cell derives staleness from
  its own draft plus the event — same information, no false claim.
- **Rebutted — "human-session routes accept machine credentials"
  (signals/history/export/advisory).** `x-hikyo-artifacts` is contract
  metadata consumed by the CI cross-checks, not a runtime gate — identically
  true of `value.list` and `key.list`, which have declared `human-session`
  since #50/#49. The runtime gate is the formula: machines cannot hold
  `reveal` (closed allowlists), and read-class lineage to a machine holding
  `read` discloses nothing `delivery.fetch` does not.
- **Rebutted — "presence-rule/key-group publish failures expose secret
  write-presence" (two findings).** Write-presence is deliberately not
  oracle-class: the revision ADR closes the VALUE-COMPARISON oracle and states
  "write-presence carries no information about the plaintext". The
  `required_in` veto naming key and environment IS mvp-boundary C2's required
  behavior, and validation never compares values.

Greptile's P2 (committed `openapi-ts-error-*.log` artifacts) is fixed:
removed and gitignored.

Disposition (2026-08-13, maintainer): all four remaining Aikido findings
marked ignored in the dashboard, option (a) — the artifact-class
declared-vs-enforced gap is #113's, a cross-cutting runtime enforcement
ticket, deliberately not folded here.

## Review round 3 — second Aikido deep scan on PR #109

The first scan's four dispositioned findings were ignored in the dashboard
(option a, #113 filed); the next scan surfaced four NEW mediums. Three were
real and are fixed; one is rebutted:

- **FIXED — the SSE stream named other principals' staging actor.**
  `pending.staged` carried `actor_id` to every environment reader, while the
  signals contract deliberately reduces another principal's draft to
  write-presence (no id, no owner, no operation). The stream now projects per
  recipient: the actor survives only on the recipient's own events.
- **FIXED — lineage was a plaintext equality oracle.** `lineage` diffed
  decrypted values, so an edit+publish holder (no reveal) could stage a
  guess, publish, and read "no lineage row" as `unchanged` — the exact oracle
  the revision ADR closes on the diff surface. The diff is now over (key
  name, pinned value-entry id): metadata only, no decryption at all. Every
  real write moves the pinned id, so a republished identical value records
  `edited` (write-presence, truthfully), while schema fan-outs that move no
  content still produce zero lineage rows.
- **FIXED — delivery and publish authenticated on a pre-preflight clock.**
  The sealer preflight can take real time (it may mint a project DEK); both
  paths now read the clock inside the transaction, so a credential expiring
  during the preflight is refused. The same pattern exists at tiny windows in
  older services (identities, ceremony, credential-reset — no preflight sits
  before their transactions); folded into #113's chokepoint pass rather than
  churned here.
- **Rebutted — "change tokens expose secret equality".** "Two snapshots have
  equal tokens iff they deliver identical content" is the revision ADR's
  stated, locked contract — it is WHAT the Kubernetes operator consumes, and
  the keyed scoped HMAC exists precisely so the comparison is meaningful only
  inside the environment that produced it and useless offline. The online
  path (publish a guess, compare tokens) costs one audited revision per
  guess in permanently retained lineage — the least stealthy oracle
  imaginable, and the write-presence lineage fix above records every such
  attempt as `edited`.

## Review round 4 — third Aikido scan

- **FIXED — concurrent token-key rotation race.** Two rotations preparing off
  the same predecessor could interleave commit and adopt so the process
  derived under a retired key. The store retire is now a compare-and-swap on
  the predecessor version (`RetireTier3KeyAtVersion`, both dialects; loser
  gets `ErrRotationSuperseded` -> 409), and the in-memory adopt is
  version-monotonic. The rotate conformance scenario now races two rotations
  and requires a winner, conflict-only losers, and a stable moved token.
- **FIXED (doc) — `changed_in_revision` wire description overstated.** The
  ADR defines "recently changed" as changed in the LAST published revision --
  which is what the code does and the Go doc says. The OpenAPI description
  claimed a per-cell last-change history; corrected to the ADR's semantics.
  Older changes live in the revision list.
- Also this round (from the prior CI run): `ErrStalePending` now wraps
  `domain.ErrConflict` so a stale publish answers the contract's 409 instead
  of an unmapped 500; the web e2e publish bridge polls for the staged version
  id instead of racing the save.

## Review round 5 — fourth Aikido scan

- **FIXED — `DeliveredKey.presence` enum never gained `set`.** The schema's
  own description promised the value when values landed; the service emits it
  since this slice, so strict SDK parsers rejected every delivered key. Enum
  grown, description rewritten, clients regenerated; the api freeze and
  contract fixtures pass.
- The artifact-class finding resurfaced (scanner re-mints per scan); its
  disposition is unchanged -- #113.

## Review round 6 — fifth Aikido scan

- **FIXED — federated delivery accepted a token expiring during preflight.**
  The binding predicate closed over the instant captured at validation time;
  it now reads the clock when the predicate runs, inside the authorizing
  transaction -- the same rule the bearer path got in round 3.

Round 6 correction (sixth scan): the round-6 fix passed a fresh clock into
`CheckBinding`, which never checked expiry at all. `CheckBinding` now
re-checks `exp` against the caller's clock (same skew allowance as
`checkTiming`), so the in-transaction predicate genuinely refuses a token
that expired during the preflight.

## Post-merge follow-up — PR #109

Aikido posted one new thread after PR #109 merged: the authoritative
`CheckBinding` pass rechecked issuer expiry, but not Hikyo's independent
`MaxTokenAge`. A token could cross the one-hour age cap during preflight while
remaining inside its issuer expiry and complete one final delivery.

`CheckBinding` now reruns every predicate in `checkTiming` at the
in-transaction clock before its explicit expiry check. The cross-engine
`FederationTokenAgeCannotExpireMidFlight` fixture advances the shared clock in
`OnValidated`, proving a token that crosses only `MaxTokenAge` receives the
uniform unauthenticated refusal. Its audit event retains the caller-invariant
`token-age` cause rather than collapsing it into the decoy-backed `unbound`
bucket. The other PR #109 threads remain fixed, contractually rebutted, or
tracked by #113 as recorded above.
