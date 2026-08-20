# Handoff: #49 key catalogue & schema validation engine

Issue: https://github.com/Hikyo-Org/Hikyo/issues/49 (parent #41, blocked by #48 — merged).
Specs, all on `wayfinder-docs`: `docs/adr/schema-model.md` **as amended by**
`docs/adr/flat-model.md` (ripple-register entry (a)–(h): no layers, no
project defaults, no `masked`, presence `set | absent`, values attach to
`(key, environment)`, group closure runs over `(group, environment)`),
`docs/spec/domain-model.md`, `docs/adr/permission-model.md`,
`docs/adr/audit-model.md`, `docs/adr/tenant-isolation.md`.

Scope: the **declaration side** of C3 plus C1's key portion. No value rows
(#50), no pending changes / advisory verdicts / publish / snapshots / group
closure / all-or-none evaluation (#51), no grants API (#55), no UI (#56+).

## What exists

### The pure library (`internal/schema`)

Zero repo dependencies: a declaration in, a verdict out. Built TDD-first
(table fixtures written and run red before the implementation), so #50's value
saves and #51's publish consume exactly the rules these fixtures pin.

- `Compile(Declaration)` is the **declaration authority**: exactly one of
  `rule` / `any_of`, the six types, per-type constraint confinement (a
  `pattern` on an integer key is REFUSED, never ignored), enum members
  non-empty/distinct/UTF-8/NUL-free after the write-time trim, URL schemes
  well-formed, RE2 patterns compiled **anchored** (`\A(?:…)\z`) with
  backreference/lookaround refusals surfaced verbatim, `any_of` bounded and
  non-nesting.
- `Compiled.Validate(value, classification)` is the **value authority**:
  `strings.TrimSpace` first, then UTF-8 + NUL, then the type. Integer grammar
  `-?[0-9]+` with leading zeros preserved and signed-64-bit magnitude;
  `boolean` canonical only; `json` a single document with **duplicate object
  keys rejected** (a token walk — `encoding/json` is last-wins); `url`
  absolute, hierarchical, scheme-allowlisted case-insensitively.
- **Error disclosure**: `Failure` carries the failing schema keyword and a
  schema-derived message. For a `secret` key nothing derived from the instance
  is ever READ — not the library's localized message (v6's
  `additionalProperties` message names the offending instance properties), not
  the instance location. It is not redaction after the fact: the data never
  enters the failure. `TestSecretFailuresCarryNoInstanceData` probes with a
  distinctive marker so a leak is detectable by search.
- **JSON Schema profile** (`jsonschema.go`): a Hikyo-owned pre-pass over the
  parsed document, run BEFORE the library sees it. Explicit keyword
  **allowlist**; the ADR's exclusions refused **by name with their reason**
  (`format`, `$dynamicRef`, `$dynamicAnchor`, `unevaluatedProperties`,
  `unevaluatedItems`, `contains`/`minContains`/`maxContains`, plus `$id`,
  `$anchor`, `$vocabulary`, `content*`); `$ref` in-document JSON-pointer only;
  reference cycles refused by DFS over containment ∪ `$ref` edges; bytes,
  depth and subschema count bounded; dialect pinned to 2020-12.
- **Presence** (`presence.go`): `{all|none|explicit}` well-formedness plus the
  statically decidable required∧forbidden conflict, and `CheckGroupPresence`
  for the same conflict across two members of one group.
- **Bounds** are named consts with loud named refusals (`MaxKeysPerProject`
  1000, `MaxKeyGroupsPerProject` 100, `MaxEnumMembers` 64,
  `MaxEnumMemberBytes` 512, `MaxPatternBytes` 512, `MaxAnyOfAlternatives` 8,
  `MaxJSONSchemaBytes` 16384, `MaxJSONSchemaDepth` 16,
  `MaxJSONSchemaSubschemas` 256, `MaxValueBytes` 65536, `MaxVerdictErrors` 20,
  `MaxVerdictErrorBytes` 4096, `EvaluationDeadline` 250ms).

### Store (`migrations/{sqlite,postgres}/00013_key_catalogue.sql`)

Four tables, `class=key chain=org_id,project_id` on all four; `key` added to
the lint scope-class enum mirroring #48's `folder`.

- `key_groups` — named, project-level.
- `keys` — immutable id, name unique among live keys per project, folder
  **path** (a string, not a folder reference: the domain model gives a Key a
  path, and an FK would invent a relationship it does not have), classification
  under a CHECK, description, deprecated + note, canonical declaration JSON,
  the two presence **modes**, nullable `group_id` under a COMPOSITE membership
  FK so a cross-project membership is unrepresentable.
- `key_presence_environments` — the explicit halves, with composite FKs to
  both `keys` and `environments`. The FK buys REFERENTIAL INTEGRITY and nothing
  more: it would refuse an environment delete that left a dangling row, but it
  decides nothing about what the surviving declaration should say. The cascade
  (below) is what keeps the catalogue consistent — collapsing an emptied
  `explicit` mode to `none`, and moving the catalogue revision.
- `project_schema_revisions` — the monotonic per-project counter, its own table
  rather than a column on `projects` (sqlite can neither add a NOT NULL column
  without a default nor drop one, and `projects` cannot take 00009's rebuild
  treatment: environments, folders and grants all reference it). Backfilled at
  0; the row is born and dies **inside** `projects.Create` / `projects.Delete`,
  so there is no window without it and no extra store operation to authorize.

22 catalogue store methods × 2 engines, each proof-verified with its own
`authz.Store*` op under the `catalogue.*` prefix (**not** `keys.*` — that is
the KEYRING's, #43). Constraint violations map to `ErrConflict` through the
existing typed `constraint()` — no string matching added.

### Service (`internal/service/keys.go`)

`Keys` and `KeyGroups`, both at PROJECT depth. Every mutation takes
`Projects.Lock` first: the schema ADR binds ONE serialization domain per
project over the schema, environment lifecycle and presence cascades.
`Environments.Delete` (#48) grew the same lock plus the presence cascade,
which runs before the row delete because the composite FK would otherwise
refuse it.

**Gate scope, stated because it is stronger than the ADR asks.** Both gates
evaluate `reveal@project`. The ADR scopes the check per AFFECTED ENVIRONMENT,
and the permission model resolves "reveal on that key" as "reveal at `E` or
above" — so `reveal@project` implies reveal at every environment in the
project and is strictly stronger than required. It is also the only scoping
available while constraints are project-wide and no value rows exist to make
an "affected environment" meaningful. **#50 must narrow it** when values land:
a principal holding `reveal` on exactly the environments a rule change can
affect should pass, and today would not.

**The reveal gate.** `UpdateDeclaration` computes `rulesChanged` as a
canonical-byte diff (so a constraint field added later cannot escape by being
forgotten in a field list; an unrenderable declaration counts as changed —
fail-closed), and when the key is `secret` runs a SECOND `authorize()` against
`key.secret-rule-change`, whose formula is `reveal@project`. It runs **before
the new declaration is compiled or examined at all**: the conformance suite
proves it by submitting a declaration that cannot compile (RE2 lookahead) from
a reveal-lacking principal and asserting the answer is the uniform nonexistent,
not the validation error. Same shape for declassification
(`key.declassify`). Both gates are unconditional on whether values exist —
conditioning would add a query and a TOCTOU window for nothing, and this slice
has no value rows.

**The ceremony.** `Reclassify` is the only path that writes the classification
column. It refuses a no-op (a ceremony that changes nothing would write a
disclosure-class record for an act that never happened), gates declassification
on `reveal`, writes the disclosure event inside the transaction ahead of the
classification write, and advances the revision.

**The environment-delete cascade does three things**, in the deleting
transaction (`cascadeEnvironmentPresence`): removes the environment's id from
every explicit presence set; collapses any set it EMPTIES from `explicit` to
`none`, because `explicit` with zero environments is a state `CheckPresence`
itself refuses and a stored declaration that cannot be round-tripped through
`UpdateDeclaration` is one nobody can edit again; and advances the catalogue
revision, because catalogue content changed and two distinct catalogue states
under one revision would break "one artifact to pin, one to diff" and the
byte-stable export built on it. It bumps only when it actually touched a row —
deleting an environment no key referenced is not a semantic schema change.

**Responses are composed INSIDE the mutating transaction**, from the row the
mutation produced plus the presence rows read under the same proof. The obvious
alternative — mutate, commit, then call `Get` — authorizes `read@project` in a
SECOND transaction, and the permission model has no prerequisite chaining
between capabilities: `definitions-edit` without `read` is a legal, supported
state, so such a principal would watch their write COMMIT and then be told the
key does not exist. It is also a cross-transaction window through which another
writer's state could leak into "your" response. `readKey` carries that reason.

**`UpdateMetadata` is a real PATCH.** Every field of `KeyMetadataUpdate` is a
pointer, merged over the stored row in-transaction; the CLI sends only the flags
the caller actually typed (`flag.FlagSet.Visit`). With plain values an absent
`folder_path` would arrive as `""` and a caller who set only `--description`
would lose the folder, the deprecation flag and the note in one request — the
silent fallback this project refuses, hiding where it always hides.

Revision discipline: creation, rename, declaration/presence change,
membership change, reclassification, group create/delete advance it; metadata
and group rename do not, which is enforceable because those operations do not
list `catalogue.BumpSchemaRevision` in their store sets.

### Authorization & audit

10 key operations + 5 group operations + the 2 gate operations, all
tenant-class at project depth, `definitions-edit@project` for mutations and
`read@project` (audited-none) for reads. `definitions-edit` is the permission
ADR's atom; that ADR **retires** the schema ADR's `schema-edit` name for the
same grant, so no atom was invented.

The gates are OPERATIONS rather than an inline grant lookup: a second
`authorize()` gets the denial writer, the assurance leg, the formula pin and
the probe contract for free. Their refusal is `ErrNotFound` (tenant-class), so
a definitions-edit holder without reveal sees exactly what they would see for a
key that is not there — which is both the standing unauthorized-≡-nonexistent
rule and the only refusal that is not itself a one-bit oracle.

11 audit types joined the closed registry: `settings.key_{created,renamed,
deleted,declaration_changed,metadata_changed,reclassified,reveal_gate_passed}`
and `settings.key_group_{created,renamed,deleted,membership_changed}`. No
payload carries a value, a declaration body or an instance-derived path; the
folder path is spelled `namespace` per #48's convention. `runCatalogueLifecycle`
in the audit E2E drives every one so the emitter invariant has a real emitter
behind each.

### Contract & CLI

14 operations under a new `keys` tag: key CRUD, plus sub-resource PUTs for
`name`, `declaration`, `classification` and `group` — separate resources
because they are separate operations with separate authorization stories
(rename and declaration are semantic, metadata is not, classification is the
ceremony). `x-hikyo-min-revision: 1` throughout; 3.1 profile + freeze fixtures
pass; TS client regenerated, typechecked, 4/4 contract fixtures.

`hikyo key list|show|create|rename|declare|reclassify|update|set-group|delete`
plus `hikyo key group …`. Syntax is validated before target resolution and
session lookup, `checkTarget`/`checkNoPositionals` on every subverb, a
malformed `--declaration` or presence spelling refused client-side, goldens
re-pinned (help, exit codes, two new `-o json` documents).

### Isolation probes

Ten tenant probes over the key surface, across all three axes (cross-org human,
cross-project machine, capability denial) and covering read, list, create,
rename, declaration change, reclassification, delete and group creation. Every
"genuinely missing" twin is AUTHORIZED-but-missing, per the harness's own rule.

`fixtureTables` and `contentSnapshot` grew the four catalogue tables, so a
refused mutation that commits and then answers `ErrNotFound` is a content diff —
including `project_schema_revisions`, because a pinned input advancing for a
write that rolled back is its own defect.

**A sentinel break found a real fixture bug while proving the probes execute.**
The isolation fixture seeds projects with raw SQL, so it had no
`project_schema_revisions` row — which made every catalogue mutation there fail
on the revision bump with `ErrNotFound`, i.e. the probes were passing for
entirely the wrong reason. The fixture now seeds the row; re-pointing
`key_rename_cross_org` at an authorized principal then fails the assertion, as
it must.

### E2E (conformance, both engines)

Six new scenarios: `key_catalogue_crud` (defined once per project, duplicate →
conflict, name reusable after delete with a NEW id, metadata moves no
revision), `declaration_fixtures_per_type` (run against the declaration as it
comes BACK OUT of the database, including whole-value anchoring — `abc1`
refused by `[a-z]+`), `declaration_rejections_by_name` (NUL in an enum member,
`format`, `$dynamicRef`, `$ref` cycle, remote `$ref`, depth budget,
backreference, lookahead — each asserted to NAME what it refused and to leave
no row), `secret_rule_change_needs_reveal` (the six-part gate matrix),
`presence_rules_and_environment_cascade`, `key_groups_declaration_side`.
Plus `TestOrdinaryUpdateRefusesAClassificationChange` at the transport and the
new key routes in `TestUniformNonexistentAtEveryLevel`.

## Decisions taken in-slice

- **`json_schema` rides the wire as a STRING**, not an embedded object. A
  round trip through `map[string]any` would resolve duplicate object keys
  last-wins and renormalize numbers, turning two rules the ADR fixes
  (duplicate-key rejection, byte bounds) into no-ops. The string carries the
  exact bytes the profile checks.
- **The reveal gate is one authorize() call per gated act**, with formula
  `reveal` alone rather than `definitions-edit ∧ reveal`: the caller has
  already passed `definitions-edit` on the guarded operation, and repeating it
  would make the denial record ambiguous about which half failed.
- **Gate refusals are audited by the denial writer only.** A refused gate rolls
  its transaction back, so a tenant event would not survive; `grant.denied` is
  durable by construction. The success path emits
  `settings.key_reveal_gate_passed`.
- **Declaration validation runs INSIDE the transaction**, after the gate. It
  costs a transaction for a malformed body and buys the "rejected without
  evaluating" property as a testable ordering.
- **A key's folder path is a string with no FK.** A folder rename does not move
  the keys that named its old path; accepted for v1 (folders are display
  grouping) and recorded below.
- **`min_length`/`max_length` count CODE POINTS** (matching JSON Schema, the
  neighbouring vocabulary), while key names and the JSON Schema document count
  BYTES. Stated because the two live one struct apart.
- **`contains` is excluded outright** rather than allowed with `maxContains`.
  The ADR excludes "unbounded `contains`"; a narrower profile is the reversible
  direction it names, and widening later is additive.
- **The `limit_exceeded` message now enumerates all three bounds.** "Fixed
  message per code" means one body; a message that named which cap fired would
  be derived from the request. See disposition 3.
- **A no-op `SetGroup` is an idempotent SUCCESS**, not a refusal: it writes
  nothing, moves no revision and emits no event, matching the no-op declaration
  save. The one operation that refuses its no-op is the reclassification
  ceremony, and only because a ceremony that changed nothing would still write
  a disclosure-class audit record.
- **Gated attempts are audited per key through the ENVELOPE, not the payload.**
  `grant.denied`'s payload is a closed schema shared by every operation and must
  not grow a key field; `TxAuthorizer.AttributeDenials` sets the envelope's
  object type/id, which already round-trips to both audit tables. Key names and
  ids are schema, never values, so this discloses nothing the ADR protects.
- **CLI `create`, not the ADR's `key add`** — one creation verb across the whole
  CLI. Both spellings carried to #27.
- **A no-op declaration save writes nothing at all.** Re-submitting a
  canonically identical declaration returns the current key without touching
  the presence rows or the revision: a no-op that rewrote rows would invalidate
  every pin for nothing.
- **The two gated routes list BOTH operations in `wireRoutes`**, following the
  credential-reset precedent: a route that reaches a second operation at runtime
  must say so, or the registry describes an authorization posture the router
  does not have.

## Disposition items (human) — surfaced at merge gate

1. **The pinned JSON Schema library and its conformance baseline are now
   facts, not spec entries.** `github.com/santhosh-tekuri/jsonschema/v6 v6.0.2`,
   promoted from indirect to direct in `go.mod`; the behavioural half is the
   official suite vendored at
   `json-schema-org/JSON-Schema-Test-Suite@15fe552d6cf76e29cc8165306fb6a72503fd360b`
   (`internal/schema/testdata/jsonschema-suite`, restricted to the files
   covering allowlisted keywords), run in CI by
   `TestJSONSchemaConformanceBaseline` — **656 cases, 37 out-of-profile groups,
   zero mismatches** (it was 725/31 before `uniqueItems` left the profile; the
   suite's `uniqueItems` groups now derive as out-of-profile automatically,
   which is the count moving as it should). Skips are automatic and self-describing: a group whose
   schema the profile refuses is skipped with the profile's own refusal as the
   reason, and the run asserts the profile is neither refusing everything nor
   refusing nothing. The ops spec should adopt these as its named values; the
   profile's keyword allowlist likewise lives in code
   (`internal/schema/jsonschema.go`) where the ADR says the ops spec owns it.
2. **Every bound value in `internal/schema` is this slice's choice**, sane for
   the Pi-4 floor and nothing more — including
   `MaxConcurrentJSONSchemaEvaluations = 8`, the process-wide ceiling on
   in-flight JSON Schema evaluations that makes an abandoned overrun count
   against a bound instead of accumulating. The ops spec owns all of them.
3. **`limit_exceeded` now covers three bounds under one fixed message.** Giving
   each bound its own error code — so the response can name the one that fired
   — is a contract change (`ErrorCode` growth) that belongs to a decision, not
   to this slice.
4. **The per-affected-environment `publish` leg is NOT wired.** The schema ADR
   and the permission ADR both put key creation, deletion, rename and every
   semantic change under `definitions-edit` **plus** per-affected-environment
   `publish`. Every such operation here is gated on `definitions-edit` alone.

   The **atom now exists** — #55 landed the full capability lattice, including
   `CapPublish` — so this is no longer a missing-vocabulary gap. It is deferred
   because the GUARD's semantics are the publish pipeline's, not the
   catalogue's: the ADR requires the check to be evaluated *immediately before
   commit* against the *impact fan-out* (which environments a semantic schema
   change actually affects), and both of those are #51's to define. #55
   deliberately registered no publish formulas for exactly this reason —
   "publish / pin / adapter / values-export / copy: those tickets register
   their own". Wiring the leg here would mean inventing the fan-out rule ahead
   of the ticket that owns it. **Still the largest deliberate gap in the
   slice**, now with a named owner.
5. **Gate attempt limiting is process-local.** `GateAttemptsPerMinute = 20` per `(principal, key)` is this
   slice's value; the ops spec owns it. The bucket is in memory for the same
   reason `internal/admission`'s is — v1 is a single node, and a durable
   throttle table would add a write per refused attempt, amplifying the flood
   it bounds; a multi-node build must replace it. The map is HARD bounded: at
   capacity with nothing evictable a new subject is refused, because an
   unbounded map is the exhaustion vector the limiter exists to prevent.

   **Every attempt is now durably audited**, allowed, denied or limited, through
   the rollback-surviving settlement path (`TxAuthorizer.CaptureAudit`) — the
   denied and limited outcomes are exactly the ones that roll their transaction
   back, so an in-transaction insert would vanish when it mattered most. The
   record carries the key id and name and the gate attempted, and nothing
   derived from a declaration or an instance: it is written outside the
   operation's own authorization scope.
6. **CLI verb set grew again**: `key` with nine subverbs plus a nested `group`
   family. Declared additive under the ADR's own grammar, pre-freeze, exactly
   as #48's `rename`/`show`/`folder` were. #27/freeze must confirm or rename.
7. **`x-hikyo-class` for the two reveal-gated routes is `tenant`**, so their
   refusal is the uniform 404. Confirm that reading is wanted before an
   operator is told "no such key" for a key they can see in `key list`.

## Known gaps / deferred

- **No compiled-validator cache.** The ADR requires one ("compiled once per
  schema revision and cached, bounded"), but its purpose is to stop a FETCH
  storm being amplified into CPU, and no fetch path exists until #50/#51. An
  unused bounded cache is the structure the flat-model ADR forbids ("a
  structure that must not be used is a bug that hasn't happened yet"), and it
  would need a row in the closed cache registry stating a proof gate it does
  not yet have. It belongs with its first consumer.
- **Environment creation does not validate-and-materialize against the schema
  revision.** That needs snapshots (#51). Recorded, not built.
- **Aggregate per-publish work cap** — publish is #51's; the per-validation
  budget exists here.
- **Draft/revision growth bounds** (live-draft quota, superseded-version GC,
  schema-revision rate limit, canonical-form dedup of declarations) — drafts are
  #51's. Canonical form exists and is byte-stable, so the dedup is a byte
  comparison when its caller lands.
- **Schema export format** — #25.
- **Near-miss advisory on key creation** (edit distance to an existing name) —
  non-blocking UI affordance, #56+.
- **`config` → `secret` advisory** ("treat this value as exposed, rotate it")
  is a UI obligation (#56+); the audit record and the ceremony exist here.
- **Folder-path drift**: renaming a folder does not move keys that named its
  old path.

## Verification record

`go build` / `go vet` / `gofmt -l .` clean. `go test ./...` **zero failures on
sqlite**; conformance + isolation + store **zero failures on postgres**
(`HIKYO_TEST_POSTGRES_DSN`, database `hikyo_test_49` — the two postgres reset
helpers grew the four new tables in dependency order). Both runs taken after
every edit, including the two-axis review pass below.

Found while rebasing over #55, fixed in-slice: `conformance.resetPostgres` was
missing #92's four `saml_*` tables (the isolation harness had them; the
conformance copy was missed), so any SECOND local run against the same
database failed re-migration with `relation "saml_providers" already exists` —
latent on main, invisible in CI where the postgres container is always fresh.
The list now mirrors the isolation harness; verified by two consecutive
postgres conformance runs against the same database. sqlc + oapi-codegen regeneration
idempotent; TS client regenerated, `pnpm typecheck` clean, 4/4 contract
fixtures (Node 24 per `.nvmrc`, via fnm). Formula pin, audited-exemptions and
CLI goldens re-pinned as reviewed diffs.

**Assertions proven to execute, not merely to pass.** Two sentinel breaks were
run and reverted:

1. Re-pointing `key_rename_cross_org` at an AUTHORIZED principal fails the
   uniform-response assertion. Before the fixture fix this break did NOT fail —
   which is how the missing `project_schema_revisions` fixture row was found.
2. Injecting a raw in-place `UPDATE keys SET declaration = …` inside a refused
   probe fails the `contentSnapshot` assertion, with both key rows and both
   revision rows rendered — so the snapshot leg fires and the `COALESCE` on the
   one nullable column does not collapse a row to NULL.

**Cross-model R1, R2 and R3 fixes** are summarised in the review record below, each
pinned by a test; the sentinel discipline was applied to the whole-verdict byte
cap, the `uniqueItems` exclusion, the `$ref` expansion bound, the non-blocking
admission, the slot-released-on-completion rule, the settlement-path attempt
record, the hard limiter bound and the strict CLI decode (each fix removed, the
pinning test observed failing, the fix restored). The schema package also passes
under `-race`.

**Two-axis review (standards + spec) findings, all fixed in-slice:** create now echoes the stored
canonical declaration (pinned by a non-canonical-input round-trip test);
`schema.normalize` clones its slices instead of trimming the caller's backing
arrays (pinned); the environment cascade collapses emptied `explicit` modes and
moves the catalogue revision (pinned by a post-cascade round-trip through
`UpdateDeclaration`); `capFailures` always retains one truncated failure so an
invalid verdict never carries zero errors (pinned, sentinel-broken); reveal-gate
attempts are rate-limited per `(principal, key)` and denials name the key in the
audit envelope (both pinned, the attribution sentinel-broken); `--deprecation-note`
reaches the CLI; a no-op `SetGroup` is an idempotent success; the evaluation-deadline
comment now says what it is (post-hoc detection, not a bound). Cleanups:
`checkKeySpec` takes the spec, `overlaps`/`overlapDescription` merged into one
`overlap`, one `keyCreateUsage` const, `RefuseClassificationInUpdate` inlined to
`ErrClassificationInUpdate`.

**Earlier review-pass fixes folded in:**
`UpdateMetadata` made a real PATCH (pointer members, in-transaction merge, CLI
sending only typed flags, conformance asserting both absent-preserves and
explicit-empty-clears); every mutation response composed inside its own
transaction rather than through a post-commit `Get` under a different formula;
ten isolation probes added over the key surface with the fixture bug above; the
two reveal-gated routes listing both operations in `wireRoutes`.

## Cross-model review record

**R1 — Codex `gpt-5.6-sol`, high effort: BLOCKED, 9 findings. All 9 fixed, each
pinned by a test that fails with the fix removed.**

1. *(high)* `default` was in the JSON Schema allowlist — a declaration could
   appear to supply a default while the flat model has no defaulting mechanism
   at all. Moved to the excluded set with that reason; refused by name.
2. *(high)* The evaluation budget was unenforceable. Two halves now: the ADR's
   **step cap** is a declaration-time static work budget —
   `subschemas × MaxValidatedInstanceBytes > MaxEvaluationWork` is refused, and
   `MaxJSONSchemaSubschemas` is DERIVED from it and survives as a STRUCTURAL
   bound, while the work product's first factor is the **expanded
   evaluation-path count over the `$ref` DAG**, because `$ref` reuse expands and
   the declared count therefore bounded nothing; the **wall clock** now abandons
   the wait (`runWithDeadline`) instead of noticing afterwards. Completed across
   R2 and R3 — see those records.
3. *(high, worst)* The rate limiter was an existence-and-classification oracle:
   it answered before authorization, so a reveal-less caller saw the answer
   change at attempt 21 — and only an existing `secret` key ever reaches the
   gate. Authorization now runs FIRST and its refusal is returned unchanged;
   the limiter is still charged and audited, but only a caller who has PASSED
   the gate can observe it.
4. *(high)* `Verdict` carried the trimmed plaintext regardless of
   classification. The value is gone from `Verdict` entirely; the write-time
   trim is `Normalize`, called by the write path and by nothing that reports.
5. *(high)* The CLI silently dropped unknown declaration members, so a
   misspelled `patern` vanished before the contract could refuse it. Strict
   decode with `DisallowUnknownFields` and a required EOF.
6. *(medium)* Not every gate attempt was durably audited. All three outcomes
   now ride the settlement path (see disposition 5).
7. *(medium)* `MaxVerdictErrorBytes` budgeted raw string lengths, not encoded
   bytes. It now measures the JSON encoding, and truncation shrinks until the
   ENCODING fits. Completed in R2 — see the R2 record.
8. *(medium)* The limiter map could grow past its bound. Hard bound, fail
   closed.
9. *(medium)* The conformance baseline was unpinned. Vendored and run in CI
   (see disposition 1).

**R2 — 7/9 verified, BLOCKED on two partials. Both closed.**

- **R1-2 (step cap / bounded timed-out work).** `uniqueItems` is now EXCLUDED
  by name: comparing every array element against every other is quadratic in
  the instance, and it was the one remaining allowlisted keyword that was not
  at-most-linear per subschema — which is precisely why "subschemas × instance
  bytes" was not yet a sound step cap. With it out, the static product IS the
  step cap, and `jsonschema.go` now carries the per-keyword linearity audit
  that says why every survivor qualifies (single-pass assertions; RE2 patterns
  linear with no backtracking; the applicators are the subschemas × instance
  product the bound already counts). Widening later is additive, on the same
  ground as `contains`.

  Residual work from abandoned overruns is now bounded too:
  `MaxConcurrentJSONSchemaEvaluations = 8` slots, acquired before the
  evaluation goroutine starts and released **by that goroutine on completion**,
  never when its waiter gives up — so abandoned work still counts against the
  bound. A free slot is taken without consulting the clock (otherwise a zero
  budget would race the timer); only a full set waits, bounded by the same
  deadline, and failing to be admitted is a loud `budget.concurrency` refusal
  rather than an unbounded queue.

- **R1-7 (verdict envelope).** `encodedSize` now marshals the COMPLETE
  `Verdict`, envelope included; the failure list alone under-counted by the
  envelope's own bytes, so a verdict sized exactly to the cap would have
  shipped over it.

**R3 — verdict envelope verified closed; two refinements of the R2 blocker.
Both closed.**

- **Static step cap was unsound under `$ref` reuse.** An acyclic `$ref` DAG
  reaches the same target through many paths — `allOf: [$ref X, $ref X]`
  doubles per level — so the DECLARED subschema count never bounded evaluation
  work: a document declaring a dozen subschemas can drive thousands of
  evaluations while every structural limit reports it as small. The work
  product's first factor is now the EXPANDED evaluation-path count
  (`profileWalk.checkWorkBudget` / `expandedPaths`): memoized DP over the
  reference graph the profile already builds, saturating at the limit so the
  counter cannot become the expensive part, cycle-free by the existing cycle
  rejection. The declared-node bound survives as a STRUCTURAL limit — it is
  what keeps the graph small enough to compute the expansion over.
- **Admission queued.** Waiting for a slot, even bounded by the deadline, is
  itself the queue the concurrency ceiling exists to prevent. Admission is now
  an immediate non-blocking try-acquire: free slot → proceed, full set →
  immediate loud `budget.concurrency` refusal, zero waiting.

Vendored-suite counts re-checked after both changes and **unchanged at 656
cases / 37 out-of-profile groups / 0 mismatches** — the suite files carry no
pathological `$ref` fan-out, which is what the expansion bound targets.

**Closure verification (gpt-5.6-sol, high): both R3 items CLOSED — overall
verdict CLEAN.** Process note, recorded deliberately: the standing 3-round cap
says post-R3 leftovers go to human disposition, not another loop. Both R3
items were refinements of the same R2 blocker (evaluation-budget soundness),
not new scope, so they were fixed in-slice and verified by a scoped
closure-only Codex pass rather than routed to a ticket — the deviation is this
paragraph, made visible for the merge gate rather than buried in a session
log.
