# Handoff: #50 flat encrypted values + copy / clone / bulk-apply

Issue: https://github.com/Hikyo-Org/Hikyo/issues/50 (parent #41, blocked by #49 — merged).
Specs, all on `wayfinder-docs`: `docs/adr/flat-model.md` (the model),
`docs/adr/encryption-model.md` **as amended by** the flat-model ADR (the value
AAD binds `env_id`), `docs/adr/permission-model.md` (the locked formula table),
`docs/adr/api-cli-surface.md`, `docs/adr/audit-model.md`,
`docs/adr/mvp-boundary.md` (C2's value portion).

Scope: the value half of C2. Value rows at `(key, environment)`, two-state
presence, envelope encryption under the project DEK, the three ergonomic
operations, `values diff`. **Not** in scope and still #51's: drafts / pending
changes, publish previews, snapshots and their pinned inputs, revisions,
restore, the per-affected-environment `publish` fan-out for schema changes.

## What exists

### Store (`migrations/{sqlite,postgres}/00015_values.sql`)

One table, `value_entries`, `class=environment chain=org_id,project_id`.

- **Presence is the row's existence.** `set` is a row, `absent` is no row.
  There is no presence column, because a column with two states and a NULL is
  three states and the third one is the `masked` state the flat model deleted.
  "No fallback source exists" is therefore held by the schema, not promised by
  a service.
- **`ciphertext` is sealed under the project DEK**, kind `value`, AAD binding
  org, project, environment, key, THIS ROW'S id and the field tag. `config` is
  sealed exactly like `secret`: classification is the DISCLOSURE boundary,
  never the storage boundary, and a table where only some rows are encrypted
  makes the reclassification ceremony a re-encryption migration.
- **A write is delete-then-insert with a FRESH id.** The row id is AAD-bound,
  and the encryption ADR forbids reusing an id bound into an AAD. There is no
  UPDATE statement in `queries/*/values.sql` at all.
- **The chain is org+project, with `environment_id` an ordinary addressed
  column** — the shape 00013 gave `key_presence_environments`. Two operations
  must span environments within a project (the key-delete refusal has to NAME
  the environments still holding values; a diff reads two of them), and the
  predicate analyzer requires every chain column as an equality conjunct, so a
  three-column chain would make both unexpressible. Nothing is lost: the
  binding layer binds `environment_id` from the verified proof's chain on every
  environment-addressed method (`envOf`, which REFUSES a proof that resolved no
  environment rather than silently binding "").

Two lifecycle consequences, both deliberate:

- **Deleting an environment deletes its values**, in the deleting transaction.
  They attach to that environment and nothing else, the composite FK would
  refuse the delete while they existed, and refusing until every cell is
  cleared by hand makes an environment undeletable in proportion to how much it
  was used.
- **Deleting a key while ANY environment holds a value for it is REFUSED**,
  naming those environments. Destroying delivered material needs the
  per-affected-environment `publish` leg, which is the publish pipeline's to
  evaluate (#51, and #49's disposition 4). The operator clears the values
  first, which is an act they can already authorize per environment.

### Service (`internal/service/values.go`)

`Values{DB, Keyring}`: `Set`, `Clear`, `Get`, `List`, `Declare`, `Copy`,
`Diff`. Clone-at-creation is `Environments.Clone` (hierarchy.go) delegating its
value half to `cloneInto` here, because the environment row and every copied
value must commit in ONE transaction.

**The three ergonomic operations differ in one thing only: whether the actor
SUPPLIED the plaintext.**

| operation | what moves | authorization |
|---|---|---|
| `Set` / `Declare` | plaintext the caller typed, piped or named a file for | `edit(E) ∧ publish(E)` per destination |
| `Copy` (copy-to = bulk-apply) | stored material, `secret` | `reveal(src) ∧ reveal(dst) ∧ publish(dst)` |
| `Copy`, `config` material | stored material, `config` | `read(src) ∧ publish(dst)` |
| `Environments.Clone` | the source environment's whole set | the copy rows above, destination evaluated on the environment being created |

`Declare` is authorized per DESTINATION and is all-or-nothing: holding the
write formula on two of three environments writes into none of them.

**Validation runs on the write**, and so does the `forbidden_in` refusal:
what commits here is what the environment delivers, so an invalid or forbidden
value is refused at the write rather than deferred to a publish that does not
exist yet. Symmetrically, a key `required_in` an environment REFUSES to be
cleared there, naming key and environment — C2's publish veto, evaluated at the
only moment this slice has.

**Every mutation takes `Projects.Lock` first**, for the catalogue's reason: a
value is validated against the key's declaration, and a concurrent declaration
change must not slip between the read and the write. It costs per-project write
serialization on values, the same ceiling the schema already pays.

### The classification split in the copy formula — the one interpretive call

**The locked row is `reveal(source E)` ∧ `reveal(destination E)` ∧
`publish(destination E)`. It is implemented for `secret` material verbatim, and
for `config` material as `read(source)` ∧ `publish(destination)`.** This is the
single decision in the slice a reviewer should grill, so here is the proof
rather than the conclusion.

The flat-model ADR's clone paragraph reads:

> Creation preflights the copy: `config` values copy freely; `secret` values
> copy only where the source-material gate passes. If any secret that cannot be
> copied is `required_in` the new environment (a `mode: all` rule …), **the
> creation aborts loudly, naming the keys**. Otherwise creation proceeds and
> the uncopied secrets land `absent`, **enumerated by name in the creation
> result**.

and mvp-boundary C2 makes the abort an acceptance criterion.

Under a uniform destination-`reveal` requirement, **both are unreachable**.
Grants inherit DOWNWARD only (`authorize.go: covers`), so `reveal` on an
environment that does not exist yet can come only from a project-or-wider
grant — which necessarily covers every source environment in that project.
Destination `reveal` passing would therefore imply source `reveal` passing, the
source gate could never fail while creation proceeded, and the ADR's "otherwise
creation proceeds …, enumerated by name" plus C2's abort would be text
describing a state no principal can reach.

Two locked texts resolve it in the same direction:

- the re-delivery gate is classification-scoped in its own wording — "a publish
  that causes an environment to begin delivering a **`secret`** value
  occurrence the publisher did not supply requires `reveal`";
- the permission ADR's `read` row carries "diffs (write-presence only for
  `secret` keys); **`config` values**" — `config` plaintext is read-class
  material, so duplicating it discloses nothing to anyone who could not already
  read it.

Mechanism: two destination operations, `value.copy-destination` (`reveal ∧
publish`) and `value.copy-destination-config` (`publish`), the same shape
`credential-reset.org`/`.instance` takes — one surface, two registry rows,
because one formula cannot express two authorization stories. **Each leg is
authorized only when its material batch is non-empty**: a config-only copy
never evaluates `value.copy-source` or `value.copy-destination` at all, or the
unreachability comes straight back.

Asymmetry worth stating once: a SUPPLIED write is `edit ∧ publish` while a
`config` copy destination is bare `publish`. Both come from the locked table
(`edit` is the value-write atom; the copy row names `publish` alone on the
destination), not from a decision here.

### Authorization (`internal/authz`)

Eight operations, all tenant-class at ENVIRONMENT depth:

| operation | formula | note |
|---|---|---|
| `value.read`, `value.list` | `read@env` | audited-none; write-presence + `config` plaintext |
| `value.reveal` | `read@env ∧ reveal@env` | MFA-mandatory for free (`reveal` ∈ `MFAMandatory`), one audit event per disclosed key |
| `value.set`, `value.clear` | `edit@env ∧ publish@env` | a write here IS delivered material; when #51 lands drafts the draft write is `edit` alone and this pair moves to the publish step |
| `value.copy-source` | `reveal@env` | emits the source-side disclosure record |
| `value.copy-destination` | `reveal@env ∧ publish@env` | secret material |
| `value.copy-destination-config` | `publish@env` | config material |

`reveal-history(source E)` — the historical half of the locked row — has no
operation here because this slice stores no historical material. It joins when
revisions do (#51/#30).

### Audit

Four types joined the closed registry: `value.set`, `value.cleared`,
`disclosure.value_revealed` (`surface` = `cell | diff | copy | clone`) and
`disclosure.value_copied` (`operation` = `copy | bulk-apply | clone`,
recording the source environment). One event per key per environment, never a
"revealed N secrets" row. **No payload carries a value in any form** — not the
plaintext, not a length, not a hash, not a changed-from marker: the trail is
readable under `audit-read`, and `audit-read` is not `reveal`.

`runValueLifecycle` in the audit E2E drives all four so the emitter invariant
has a real emitter behind each.

### Contract & CLI

Eleven operations under a new `values` tag, plus `cloneEnvironment`.

**The three reveal paths are POSTs and routes of their own**
(`.../values/reveal`, `.../values/{key}/reveal`, `.../values/diff/reveal`)
rather than a `?reveal=true` flag. Disclosure is an ACT — each writes audit
records before plaintext leaves the server — and the ADR's rule is one verb per
disclosure path, one gate. It also keeps the contract honest: a route's
declared formula is the one it evaluates, so the MFA-403 rule (`only an
MFA-mandatory formula may declare 403`) lands correctly on exactly the reveal
routes.

`cloneEnvironment` is a separate route rather than a flag on
`createEnvironment` because its RESPONSE differs: a clone has to report what it
could not take.

CLI: `hikyo values list|get|set|declare|diff|copy` and
`hikyo env create --clone-from`. `get|set|diff` are the ADR's closed v1
spellings; `--clear` is the flat-model ADR's own declared join; `list`,
`declare` and `copy` join as declared additive spellings, pre-freeze (see
disposition 3).

The ticket's demo is one CLI line per step:

    hikyo key create --name LOG_LEVEL --classification config --declaration '{"rule":{"type":"string"}}'
    echo info | hikyo values declare LOG_LEVEL --envs dev,staging,prod --stdin
    echo debug | hikyo values set LOG_LEVEL --env dev --stdin
    hikyo values diff --left dev --right prod

**No secret reaches argv in either direction.** `values set` takes its value
from a no-echo terminal prompt, `--stdin`, or `--value-file`; there is no
`--value` flag and there must never be one. `values get --reveal` on a `secret`
goes through the print triad (`internal/disclose`): controlling terminal after
confirmation, `--output-file` (O_EXCL, 0600), or explicit `--dangerously-print`.

## Decisions taken in-slice

- **The sealer is resolved after authorization, in its own read transaction.**
  `ForProject` MINTS the project DEK on first use, and it cannot run inside the
  write transaction (the keyring's store adapter opens transactions of its own,
  and sqlite serves writes on a single connection). Resolving it before the
  transaction would let any authenticated principal leave a wrapped-key row for
  an arbitrary `(org, project)` string. `service.sealerFor` therefore runs a
  bare read transaction that evaluates the operation's own formula against the
  addressed scope and touches NO store operation, then resolves the sealer.
  The window carries no state — only a key handle — and the real transaction
  re-authorizes and re-reads everything.
- **`absent` is `ErrNotFound` from the store and a `Set: false` cell from the
  service.** Clearing an already-absent cell is a no-op success: absence is the
  state, and the caller asked for that state.
- **Copying an absent named key is a refusal**, never a silent no-op. Only
  clone tolerates missing/blocked material, because only clone is specified to.
- **`Copy` requires explicit key names.** An empty list quietly meaning
  "everything" is how a mistyped bulk apply becomes an incident; "copy
  everything" is what clone is for.
- **`equal` on a diff row is a POINTER all the way to the wire.** Both sides
  `set` with at least one unreadable leaves it ABSENT, not `false`: whether two
  secrets match is itself material.
- **A revealing read runs in a WRITE transaction**, because it writes its
  disclosure events — the record must be durable before the plaintext leaves
  the server, not after.
- **The protected-destination ceremony is a request field**
  (`confirm_protected`), refused by name (`ErrProtectedDestination`, a distinct
  sentinel: the caller CAN see the environment, so masking it as nonexistent
  would be a lie). A brand-new environment cannot be protected, so clone has
  nothing to confirm.
- **`schema.Presence.Covers`** was added rather than re-deriving mode
  semantics: `mode: all` is symbolic and must keep covering environments
  created later, which is exactly the question the value model asks twice
  ("forbidden here?" gates a write, "required here?" gates a clear).
- **One CI invariant was corrected, not relaxed.** `TestInvariantAuditCompleteness`
  treated an audited-none operation reached by a route as an EXEMPTION for the
  whole route, so a route reaching both `value.list` (silent) and the copy
  operations (audited) reported as "audited AND exemption-pinned". Silent and
  pinned are now tracked separately; a route is fine if it emits events, if
  every operation it reaches is audited-none, or if it is pinned.

## Cross-model review record — codex `gpt-5.6-sol`, high effort

**R1: BLOCKED, 7 findings. All fixed in the R2 batch below** (one line each: what
changed, which test covers it). Non-finding standards cleanups accompanied the
batch and are listed after.

**R2: 6/7 fixes verified; TWO items left blocking, both now closed this round.**
The R2 pass confirmed fixes 1–3 and 5–7. It left two blocking items — the
completion of #4 and the clone-preflight gap — dispositioned below:

- **#4 completion — protected-destination refusal now identifies the destination.**
  `ErrProtectedDestination` wrapping `domain.ErrConflict` gave the right 409 (R1 #4),
  but `errorBody` dropped detail for conflict, so the caller got the bare conflict
  message while `openapi.yaml:2584` promises the refusal names the protected
  destination. `errorBody` now honours detail for `conflict` as well as `bad_request`,
  BUT only when an explicit `SafeDetail` carrier supplies it (plain conflicts stay
  uniform). New `service.ProtectedDestinationRefusal(envID)` builds the refusal as a
  `SafeDetail`-typed error (wrapping `ErrProtectedDestination`) carrying the caller's
  own destination id; `withDestination` uses it. The id is request-derived and the
  refusal is post-authorization, so naming it discloses nothing.
  Tests: `server/TestUnconfirmedProtectedDestinationIs409NotFault` now asserts the 409
  body's detail names the destination env id, AND asserts a PLAIN conflict carries no
  detail (widening did not leak every conflict body).
- **Clone disclosure rollback (CRITICAL) — closed by preflight, not settlement.**
  `readSourceMaterial` split into `planSourceMaterial` (gate + resolve what lands, no
  decrypt, no disclosure event) and `openSourceMaterial` (decrypt + record). `cloneInto`
  runs the born-invalid abort against the plan, opening only after it cannot fire — so
  an aborted clone rolls back nothing it opened. `readSourceMaterial` stays a thin
  plan-then-open wrapper, leaving Copy's ordering intact. Registry + service comments
  rewritten to the preflight order.
  Test: `conformance/value_clone_at_creation` gained a disclosure before/after count
  AND a source-ciphertext corruption before the aborted clone — the corruption is the
  real discriminator (the count nets zero either way because audit is transactional;
  proven red on the buggy open-before-abort order, green on the fix, both engines).

1. **BLOCKER — clone born invalid.** `cloneInto` aborted only for gate-BLOCKED
   required secrets (`skipped ∩ required`); a `mode: all` required SECRET absent
   AT SOURCE cloned through, leaving the new environment invalid. Now the abort
   is the literal superset — it decides on what will actually LAND
   (`material.secret`) and strands any `secret ∧ required.Covers(dest) ∧ ¬landed`,
   sorted union of names, covering both causes.
   Test: `conformance/value_clone_at_creation` (gate-blocked case kept; new
   full-authority **source-absent** case `NEVER_SET_TOKEN`).
2. **MAJOR — abort keys never reached the caller.** `writeHandlerError` called
   `writeError(w, code, "")`, so the clone-abort's key names were dropped and the
   caller saw the bare `bad_request` message. Added `service.detailErr`
   (`SafeDetail() string`, wraps `domain.ErrInvalid`) built by `invalidDetail(...)`;
   `writeHandlerError` extracts it via `errors.As` and passes it as the detail
   argument (`errorBody` already restricts detail to `bad_request`).
   Tests: `server/TestCloneAbortBodyCarriesTheStrandedKeys` (400 body names the
   key) + `conformance/value_clone_at_creation` asserts the abort exposes
   `SafeDetail()`.
3. **MAJOR — copy opened material before destination authz.** `Copy` ran
   `readSourceMaterial` (opening secrets, writing `value.revealed`) before any
   destination was authorized, so a destination refusal rolled the disclosure
   trail back — contradicting `OpValueCopySource`'s own comment. Reordered:
   `classifyCopyKeys` + `authorizeDestination` clear every destination (formula +
   protected ceremony) BEFORE `readSourceMaterial` opens anything; post-open
   failures are now genuine faults where rollback is correct. Registry comment and
   the `readSourceMaterial` comment rewritten to the preflight ordering.
   Tests: `conformance/value_copy_runs_the_locked_formula` (all three destination
   refusals still uniform, nothing lands) + isolation copy probes stay green.
4. **MAJOR — protected destination answered 500.** `ErrProtectedDestination` was a
   bare `errors.New` wrapping no sentinel → `classify()` → Internal → 500 + fault
   log for a documented refusal. Now wraps `domain.ErrConflict` → 409. Conflict
   detail never reaches the wire (by design).
   Test: `server/TestUnconfirmedProtectedDestinationIs409NotFault`.
5. **MAJOR — CLI reveal bypassed the print triad.** `values list --reveal` and
   `values diff --reveal` rendered secret plaintext straight to `Render(Stdout)`.
   They now carry the same triad flags `get` has (`--output-file`,
   `--dangerously-print`); `--reveal` runs `disclose.Preflight` BEFORE the request,
   renders to a buffer, and delivers via `disclose.Emit` (`emitRendered`).
   Tests: `cli/TestRevealingDiffIsRefusedBeforeAnyRequestWithoutASink` (pre-request
   refusal on non-TTY, no sink) + `help.txt` golden updated.
6. **MINOR — spurious `value.cleared` on a no-op.** Clearing an already-absent cell
   emitted `value.cleared` for a transition that never happened. `ValueRepo.Clear`
   now returns rows-affected (both engines; `DeleteValueEntry` already `:execrows`,
   no sqlc regen needed); the service emits only when a row existed. HTTP stays 2xx
   for the no-op.
   Test: `conformance/value_set_delivers_absent_delivers_nothing` asserts exactly
   one `value.cleared` after two clears.
7. **MINOR — duplicate items caused repeated writes/events/rows.** `declare`'s
   `environment_ids` and `copy`'s `keys` / `destination_environment_ids` accepted
   duplicates. The service now rejects them with `domain.ErrInvalid` naming the
   duplicate (via `invalidDetail`, so the caller sees which); `uniqueItems: true`
   added to the three arrays in `openapi.yaml`; apigen + TS client regenerated.
   Tests: `conformance/value_declare_into_environments` (duplicated env refused,
   naming it) and `conformance/value_copy_runs_the_locked_formula` (duplicated key
   and duplicated destination each refused, naming the duplicate); contract shape
   re-validated by `pnpm verify`.

**Standards cleanups (with the batch):** (a) `server/values.go` copy result builds
the apigen anon-struct once via `apigen.ID`/`KeyName`; (b) `cli` uses `apigen.Secret`;
(c) `read()` dropped its always-"cell" `surface` param; (d) `writeCell` dropped the
`envID` param (== `scope.Env`); (e) the empty/blank/dup env checks live once in
`declare`; (f) `writeCell` returns the stored timestamp so `Declare` reports it
rather than a second `time.Now()`; (g) the `copyOp*` const comment no longer names a
non-existent `CopyOperation` type; (h) `readCells` resolves a single key within the
already-listed catalogue (`keyByName`) instead of listing twice; (i) `readValue` I/O
failures are bare errors (→ `ExitInternal`, the trust/state-file precedent), not
`ExitUsage`; (j) `StoreValuesEnvironmentsForKey` renamed to
`StoreValuesEnvironmentsWithValue` so the Go const, the store method and the op
value agree — the SQL query name `ListValueEnvironmentsForKey` is the lone remaining
outlier (renaming it needs an sqlc regen for cosmetic gain; left as a note).

## Disposition items (human) — surfaced at merge gate

- **Standalone `values declare` (decoupled from key creation).** The issue phrases
  the three operations as "each independent", while the flat-model ADR describes key
  creation as "taking the set of environments". This slice reads them as SEPARATE:
  `values declare` is a value-write verb (`edit ∧ publish` per destination), not part
  of key creation. That is a deliberate interpretation — merge-gate confirms it, and
  if rejected, `declare` folds back into the key-create path.
- **Conflict detail: the key-delete refusal stays uniform; the protected-destination
  refusal now names the destination (R2 #4 completion).** `errorBody` honours detail
  for `bad_request` AND `conflict`, but ONLY when an explicit `SafeDetail` carrier
  supplies it — a plain conflict (the key-delete refusal in `keys.go`, and every other
  `ErrConflict` that wraps no `SafeDetail`) still carries no detail and stays
  byte-identical. The lone conflict that opts in is `ErrProtectedDestination`
  (`ProtectedDestinationRefusal`), whose detail is the caller's OWN destination
  environment id: it came from the caller's request and the refusal is
  post-authorization, so naming it discloses nothing. The clone abort (fix 2) still
  discloses key names because it is `bad_request`. This CLOSES R2's residual item on
  finding #4 — the openapi.yaml:2584 promise that the refusal identifies the protected
  destination is now honoured on the wire.
- **Copy's AND clone's disclosure trails are now truthful (R2 clone-preflight
  completion).** Fix 3 reordered COPY so a destination refusal precedes any open. The
  clone gap it left is now closed the same way, by splitting `readSourceMaterial` into
  `planSourceMaterial` (authorizes the source legs and resolves what would land,
  opening NO plaintext and writing NO disclosure event) and `openSourceMaterial`
  (decrypts and records the disclosures). `cloneInto` runs the born-invalid abort
  against the PLAN, then opens only once no abort can fire — so an aborted clone rolls
  back nothing it opened, and the OpValueCopySource promise (one durable event per
  secret OPENED) holds. `readSourceMaterial` remains a thin plan-then-open wrapper, so
  Copy's already-fixed ordering is untouched. The residual gap this bullet used to
  describe (both the destination-refusal and the source-absent-abort instances) is
  gone. A NOTE on the test: because the disclosure rows are written in the clone's own
  transaction, an aborted clone rolls them back and a before/after row count nets zero
  whether or not the fix is present — so the conformance scenario ALSO corrupts a
  source secret's ciphertext before the aborted clone: the fixed preflight aborts
  without decrypting, while the buggy open-before-abort order hits `ErrDecrypt` and
  fails with a fault instead of the abort. That corruption is the assertion that
  actually catches the regression; the row count is the literal belt.

1. **The classification split in the copy formula** (above). It is an
   interpretation of a LOCKED row, forced by the reachability argument, and it
   is the one thing in this slice that should be confirmed rather than assumed.
   If it is rejected, C2's clone-abort criterion has to be rewritten, because
   it is unreachable under the uniform reading.
2. **`value.set` / `value.clear` are `edit ∧ publish`.** This slice has no
   working state, so a write IS delivered material; the pair is the fail-closed
   reading of the same table that puts `publish(destination)` on every operation
   that makes an environment start delivering something. #51 must move this: the
   draft write becomes `edit` alone and `publish` moves to the publish step.
3. **CLI verb set grew again**: `values` with six subverbs, and `env create
   --clone-from`. `get|set|diff` and `set --clear` are ADR spellings; `list`,
   `declare` and `copy` are declared additive joins under the ADR's own
   grammar, pre-freeze, exactly as #48's `rename` and #49's `create` were.
   #27/freeze must confirm.
4. **Deleting an environment deletes its values silently** (the environment's
   own deletion is the audited act; no per-value event is emitted for the
   cascade). If an investigator needs the cascade enumerated, that is an audit
   payload change and belongs to a decision.
5. **No value-size or per-project value-count cap beyond `MaxValueBytes`
   (64 KiB, #49's bound, enforced by the validation engine).** The ops spec owns
   a per-project value-row cap if it wants one; keys are already capped at 1000
   per project and environments at 50, which bounds the product at 50,000 rows.
6. **`values export` does not exist yet.** The ADR's one bulk-disclosure verb
   (with its ceremony enumerating the full key set, and `--format dotenv|json`)
   is delivery-shaped and belongs with #51's snapshots / #18's render path.
   `values list --reveal` is the interim, and it is NOT the export verb: it has
   no ceremony and no format switch.

## Known gaps / deferred

- **No snapshot, no pinned inputs, no publish preview.** Delivery reads live
  state here; the flat model's "delivery reads only committed, valid snapshots"
  arrives with #51, and this slice's `List` is what it will pin.
- **No revision lineage, so no `reveal-history` anywhere.** Restore, historical
  diff and the historical half of the copy formula are #51/#30.
- **No group all-or-none evaluation at write time.** `CheckGroupPresence`'s
  static half exists (#49); the runtime closure is publish's (#51).
- **A key's value cells are not re-encrypted on reclassification.** Nothing
  needs it — both classifications are sealed identically — but if a future
  change makes them differ, the ceremony grows a re-encryption step.
- **Machine delivery (fetch) is untouched**: no workload path reads values yet.

## Verification record

**R2 blocking-items round re-verified** (2026-08-12): the #4 completion and the
clone-preflight fix (above). `gofmt -l .` empty, `go build ./...`, `go vet ./...`
clean; `go test ./... -count=1` (sqlite) exit 0, 21 `ok` packages, zero FAIL; the
postgres leg (`HIKYO_TEST_POSTGRES_DSN=…/hikyo_50 go test ./... -count=1`) exit 0,
21 `ok`, zero FAIL, and `value_clone_at_creation` verified EXECUTING on PG via
`TestConformancePostgres -v` (`--- PASS`). The clone-preflight regression guard was
proven to DISCRIMINATE: with a scratch open-before-abort restored, the corrupted-
ciphertext assertion turned the scenario RED on both engines; the fix turns it back
GREEN. No SQL, contract, or CLI wire-shape changed this round — no apigen/sqlc/TS
regen and no golden re-pin needed (the change is server-internal detail routing plus
a service function split).

**R2 review-fix batch re-verified** (2026-08-12): `gofmt -l .` empty,
`go build ./...`, `go vet ./...` clean; `go test ./... -count=1` (sqlite) exit 0,
21 `ok` packages, zero FAIL; the postgres leg
(`HIKYO_TEST_POSTGRES_DSN=…/hikyo_50 go test ./... -count=1`) exit 0, 21 `ok`, zero
FAIL, and the six value scenarios verified EXECUTING on PG via
`TestConformancePostgres -v` (six `--- PASS` lines, not an absent skip).
apigen + sqlc regenerated (sqlc idempotent — no SQL changed); TS client
regenerated (`pnpm verify` clean: typecheck + 4/4 contract fixtures, Node 24 via
fnm). `help.txt` golden re-pinned (list/diff gained the triad flags); the two
`-o json` documents unchanged (no wire-shape change). `operation_formulas.json`
NOT re-pinned — the store-op RENAME kept the op string value
(`values.EnvironmentsWithValue`), so the pin is untouched.

Original slice verification:

`go build` / `go vet` / `gofmt -l .` clean.

- **sqlite**: `go test ./... -count=1` — **994 passed, 0 failed** (33 packages).
- **postgres** (`HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_50`):
  `go test ./... -count=1` — **exit 0, 21 `ok` packages, zero FAIL lines** (the
  remainder have no test files). `internal/isolation` 100.8s,
  `internal/conformance` 7.0s. The six value scenarios EXECUTE on the postgres
  leg — verified by running `TestConformancePostgres -v` and reading the six
  `--- PASS` lines, not inferred from an absent skip.
- Both PG reset drop-lists grew `value_entries` (conformance AND isolation —
  they drift, and #49's handoff records it biting twice).
- sqlc regeneration idempotent; oapi-codegen regenerated; TS client
  regenerated, `pnpm verify` clean (typecheck + 4/4 contract fixtures, Node 24
  per `.nvmrc` via fnm).
- Formula pin and CLI goldens re-pinned as reviewed diffs (`operation_formulas.json`
  gained the eight value operations; `help.txt` gained the values family; two
  new `-o json` documents: `value-json.json`, `value-diff-json.json`).

**The live demo was executed at the merge gate — and caught a real defect.**
The real binary refused `hikyo values` with "unknown command": the dispatch
switch in `cli.Run` (verbs.go) had gained the verb, but `cli.Verbs` (exit.go)
— the list `main` gates on before calling `cli.Run` at all — had not. Every
test passed because the goldens and demos call `cli.Run` directly, below
main's gate. Fixed at the root: the switch is now a `verbHandlers` map and
`Verbs` is derived from its keys (`slices.Sorted(maps.Keys(...))`), so the
two surfaces cannot disagree again. That immediately made the
classification-totality and audit-completeness invariants demand what the
desync had let them skip: `cli:values` now carries `ClassTenant` in the wire
registry and an audited-exemption pin like its `cli:key` sibling.

The demo itself, against a booted sqlite dev instance (bootstrap admin →
establish-credential → local login → TOTP enrol/confirm/step-up → org +
admin-template self-grant → project + dev/staging/prod): `key create
LOG_LEVEL`, `values declare LOG_LEVEL --envs dev,staging,prod --stdin` (info),
`values set LOG_LEVEL --env dev --stdin` (debug), `values diff --left dev
--right prod` → `different | set debug | set info`; `env create --name dev2
--clone-from dev` delivered a new environment holding dev's value. One
operator note: TOTP enrolment consumes the current 30-second step, so
`confirm-totp` in the same window is refused uniformly (401) — the code from
the NEXT window confirms. That is #54's documented single-use rule, not a
defect, but it reads like one from a terminal.

**Assertions proven to execute.** A sentinel break was run and reverted:
re-pointing `value_set_cross_org` at the AUTHORIZED custodian fails the
uniform-response assertion (`probe outcome = <nil>`), so the probe is testing
the boundary rather than passing on a capability accident.

**A probe found a real defect while being written.** `value_copy_read_only_principal`
originally failed on the response-shape comparison: copying a key with no value
answered `not found: key "SHARED_KEY" is absent in the source environment`
against the missing twin's bare `not found`. The isolation fixture now seeds a
REAL value through the service (`seedValues` — raw SQL cannot produce a
ciphertext anything can open), so the probe reaches the authorization boundary
it is meant to test.

### Test map

| criterion (C2, value portion) | test |
|---|---|
| a `set` entry delivers, `absent` delivers nothing, no fallback source | `conformance: value_set_delivers_absent_delivers_nothing` |
| `masked` absent from schema and API surface | `conformance: TestMaskedIsAbsentFromSchemaAndAPI` (scans both migration sets and `api/openapi.yaml`) |
| copy / bulk-apply run the locked formula | `conformance: value_copy_runs_the_locked_formula` (source-reveal, destination-reveal and destination-publish each removed in turn; config-only copy under `read+publish`; independence of the copy) |
| clone runs the locked formula, aborts naming a stranded `mode: all` required secret | `conformance: value_clone_at_creation` |
| uncopied secrets enumerated by name | same scenario, `result.UncopiedSecrets` |
| declare-into-environments, atomic and per-destination | `conformance: value_declare_into_environments` |
| `values diff` under #11's oracle rules | `conformance: values_diff_between_environments` |
| ciphertext row-bound, no plaintext at rest, no id reuse | `conformance: value_ciphertext_is_row_bound`, `conformance: TestKnownPlaintextAbsentFromDump` (now over the REAL `value_entries` table, not a scratch stand-in) |
| unauthorized ≡ nonexistent on every value operation | `isolation: value_{read,set,clear,copy,clone}_*` (9 probes, all three axes) |
| every registered audit type has an emitter | `isolation: runValueLifecycle` |

## For the next agent (#51)

- `Values.List` is the shape a snapshot pins. It is already "one row per
  declared key, `set` or `absent`", which is the resolved snapshot minus the
  pinning.
- `value.set` / `value.clear`'s formula is the interim (disposition 2). When
  drafts land, split it.
- The key-delete refusal (above) is the placeholder for the
  per-affected-environment `publish` leg. When #51 can evaluate the fan-out,
  the refusal becomes an authorized cascade.
- `readSourceMaterial` already separates the current-material gate from the
  material it reads; `reveal-history` joins as a second gate on the same seam
  when historical material exists.
