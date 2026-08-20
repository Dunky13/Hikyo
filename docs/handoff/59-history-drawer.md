# Handoff — #59 History drawer + restore + pin lifecycle UI

Ticket: [#59](https://github.com/Hikyo-Org/Hikyo/issues/59) (parent #41). Blocked-by
#52 (rollback & pins), #53 (retention & GC), #56 (UI shell / flow registry), #57
(environment matrix) and #58 (reveal ceremonies) — all merged before this work.

Binds the frozen prototype `prototype/revision-history/6` (branch `wayfinder-docs`,
locked 2026-08-05: panes drawer from iteration 2 verdict **b**, pin clarity from
iteration 3, pin-as-workload-binding + sole-keeper language from iteration 4,
read-only retention line from iteration 6), `docs/adr/revision-model.md` read
through its flat-model amendment banner (restore is two-way `set | unset`; no
masks), and `docs/adr/mvp-boundary.md` rows **C5 [UI]** and **S3**.

## What shipped

**A new locked surface, `history`.** `web/src/app/navigation.ts` gains
`/orgs/:org/projects/:project/matrix/history`, `section: null`, chrome-wearing.
The element in `App.tsx` is `<Matrix historyOpen />` — the same component, told
by the ROUTE TABLE that its drawer is open. That is the shape the prototype
locked: the panes render *over* the matrix, not instead of it, and the matrix
stays addressable behind them. It also means no second component owns the
project's catalogue, values and signals, which the drawer needs anyway.

Environment and per-key filter are QUERY PARAMETERS (`?env=`, `?key=`, `?rev=`),
because per-key history is a filter over the same lineage and not a second
surface — the prototype's first decision. Every part of the drawer's state is
therefore deep-linkable, and the flow asserts the deep link.

- `web/src/routes/HistoryDrawer.tsx` — the drawer: head (current revision,
  protected marker, environment tabs, others'-drafts summary, read-only retention
  line, active key filter), the list + detail panes, the restore sheet, the pin
  sheet and the sole-keeper release confirmation. Below 800px the two panes
  become one — list, then detail, with a back affordance — because a split 440px
  drawer is neither pane.
- `web/src/routes/history-state.ts` + `history-state.test.ts` — the pure seam
  (39 cases): revision action gating, per-key filter projection, pin action
  label, expiry tiers, the sole-keeper predicate, restore preview chips, the two
  ceremony units, the pin-refusal classifier, the retention line, relative age.
- `web/src/api/history.ts` + `history.test.ts` — the API boundary: revisions,
  gated detail, pins, project retention; rollback, pin set, pin release; refusal
  text. Two contract invariants are re-stated as `superRefine`s because their
  violation would be a disclosure rather than a rendering bug (below).
- `web/src/routes/Matrix.tsx` — the `rev N · history` link in each environment
  column header and the drawer render. On mobile the matrix becomes `inert`
  while the drawer is open; focus lands on the drawer title, moves to revision
  detail, and returns to the selected row on back.
- `web/src/routes/MatrixRowEditor.tsx` — the per-key affordance,
  `History for <KEY>`, which is the history surface with `key` set.
- `web/src/routes/Ceremony.tsx` / `useProtectedPublishCeremony.ts` — two new
  told-the-human purposes (`restore`, `pin`) that SIGN `reveal`, and an optional
  `purpose` on a ceremony target. Same controller as publish and copy, so the
  "prompt or not" decision stays in one place.
- `web/src/styles/app.css` — the `history__*` block and `.btn--danger`.

### Secret safety on this surface

Nothing here can render secret material, and three separate things enforce that:

- the lineage rows carry write-presence only (`added` / `edited` / `removed`)
  and mark the key 🔒 — never a value, a length, a digest or a comparison;
- `zHistoryRollbackResult` refuses an impact row that carries `before`/`after`
  for a `secret` key, or an `after` on a clear, at the parse boundary;
- the restore impact rows render `secret — <status>, write-presence only` by
  construction rather than by omission.

## API addition (additive, both engines)

`Revision` gains **`payload_present`** (boolean, required) and
**`collected_policy`** (string, optional — present only when collected, and
carrying the store's own `formatRetentionPolicy` vocabulary verbatim).
They are intentionally on `listRevisions` rows only, not `RevisionDetail`:
`Show` refuses collected revisions before producing detail, so the detail bit
would be invariantly true and its policy invariantly absent. Machine clients can
also reach `getRevision`, so its response should not advertise a misleading
payload lifecycle contract that it can never represent.

The bit already existed on `store.Snapshot` (#52's `payload_present`, #53's
`collected_policy`); it simply never reached the wire. It has to, because
`getRevision` **409s on a collected revision** — it derives a change token over
the snapshot's manifest — so the drawer cannot learn "this payload was collected"
from the detail endpoint. `listRevisions` is the only read that still works, and
without the bit the surface would have to discover a collected revision by
failing on it.

- `internal/service/revisions.go` — `RevisionView.PayloadPresent` /
  `.CollectedPolicy`, filled in `History`. `collectedPolicy()` reports
  the stamped policy ONLY for a collected payload: the column carries a default
  while the payload is live, and emitting that would read as a fact about
  nothing.
- `internal/server/revisions.go` — `wireRevision` renders list rows only;
  `GetRevision` renders the detail fields directly without lifecycle members.
- Regenerated `api/apigen` (`go tool oapi-codegen --config api/oapi-codegen.yaml
  api/openapi.yaml`) and `clients/ts` (`pnpm run verify` under Node 24).
- Tests: `TestLineageWireCarriesTheCollectionBit` (transport, both directions)
  and an assertion inside `runRetentionGCC6` (isolation, **sqlite + postgres**)
  that the bit and the stamped policy survive a real GC sweep on the read that
  still works.

No migration, no store change, no registry/formula change — so no
`annotated_queries.json` / `audited_exemptions.json` / `operation_formulas.json`
re-pin was needed. Verification is in the table at the end of this document.

### One server-side fix this ticket required

`validateValue` (`internal/service/values.go`) raised its refusal as a bare
`domain.ErrInvalid`, so the wire carried a 400 with **no detail** — and C5
requires a schema-failing restore to "block loud, naming the keys". Its own
comment already says the text is schema-derived and carries nothing the caller
may not see, so it now uses `invalidDetail` like the presence vetoes beside it.
`matrixMutationError` quotes the server's caller-safe detail verbatim rather than
paraphrasing it. Without this pair the flow's schema-refusal assertion cannot be
written at all.

## Decisions, and divergences from the locked prototype BY NAME

1. **Revision-to-revision diff modal: OUT.** The prototype offers "diff vs
   previous" and "diff vs current". No API computes a rev↔rev diff — `diffValues`
   compares two ENVIRONMENTS — and neither C5 nor S3 names one. The restore
   **impact preview** is this surface's "what would change" view. Deferred, not
   dropped: it needs an endpoint first.
2. **Same-revision re-pin is a RENEW, not a refused no-op.** Iteration 4 refuses
   it ("a workload fetches exactly one revision"). The API/CLI taxonomy locked
   afterwards (#52, api-cli-surface) makes it a renew: it extends the expiry,
   revalidates against the current schema, and records the drift that
   revalidation finds. That is not nothing, so the sheet relabels to
   `Renew pin on rN` and says what renewing does. The label is what the human
   agrees to; the outcome toast reports the SERVER's `RevisionPinResult.action`.
3. **Restore previews AFTER it stages, not before.** Iteration 1 previews, then
   stages on confirmation. `rollbackRevision` does both in one call — it writes
   the drafts and returns the impact preview with the token that binds them — so
   the sheet explains the act before it is taken and reports the exact impact
   after. Nothing is published either way.
4. **No "n schema-blocked" chip.** The prototype's third summary chip counted
   rows the staging step rejected. The shipped model validates at PUBLISH (#52:
   publish is the only authority), so a successful preview has no blocked rows to
   count. The refusal is still loud and still names the key; it arrives on the
   publish leg, where the server decides it.
5. **Retention is READ-ONLY here** — iteration 6's own verdict. Effective window,
   inherits-org / custom badge, and a plain-text pointer at project settings ›
   Policy (#60 owns that surface). One read: `getProjectRetention` already
   answers with the effective policy AND `inherited`, so `getOrgRetention` is not
   fetched.
6. **Human actors are IDs; workloads are names.** Nothing in this API resolves a
   HUMAN principal id to a display name — there is no member-listing operation,
   and inventing one is a permission decision this ticket does not own — so
   `published_by` renders as a shortened id with the whole one in `title`.
   Workloads DO resolve, through the project's service accounts, which is why
   pin rows and the consumers line name them.
7. **The preview token lives in memory, in `Matrix`.** `PendingChange` carries no
   `source`, so the browser cannot tell a restore-authored draft from an ordinary
   one after the fact. The token travels from the restore that minted it to the
   publish that spends it; a reload asks for the restore again rather than
   guessing. Publish refuses a missing or stale token by name and the sheet
   quotes it.
8. **The ceremony purposes `restore` and `pin` SIGN `reveal`.** Both acts read
   historical secret material and the service gates them with `PurposeReveal`
   over the enumerated secret-key unit (`internal/service/{rollback,pins}.go`),
   so that is what the assertion has to commit to — while the modal still tells
   the human which of the two decisions they are taking. Exactly the
  told-vs-signed split #58 established for clipboard copy.
- `web/src/routes/useModalDialog.ts` — one dialog primitive shared by ceremony,
  row editor, machine-access, restore, pin and release sheets: native modal,
  initial focus, focus trap, inert background, Escape and focus restoration.
- `web/src/api/matrix.ts` — a page-lifetime restore-preview store keyed by the
  exact version-id set. Both the in-drawer `Publish this restore` action and the
  ordinary matrix publish sheet attach the stored token; partial overlaps are
  refused client-side before a publish request is sent. The browser flow counts
  `/publish` requests around that refusal (zero), then around publish-alone
  (exactly one).
- The pin sheet includes a read-only comparison (no disclosure event). Config values render as
  `stays at … — latest: …`; secrets render lineage only. Pin rows state the
  behind-latest gap and expiry consequence in visible prose, not colour alone.
9. **`override_schema` is offered only AFTER the server refuses.** An override
   permanently on screen is an override people tick to make an error go away.
   `pinSchemaOverrideOffered` classifies the refusal off `pins.go`'s own bounded
   prefixes (expiry, quota, request shape) — anything else came from
   `validatePinnedSnapshot`, which is the one refusal the recorded override
   exists for.
10. **The expiry bound is not pre-blocked client-side.** The input takes any
    date and the server's `pin expiry exceeds the maximum 365 days` is surfaced
    by name. A client-side cap would be a second source of truth for a value the
    service owns.
11. **`payload_present` is list-only.** It is intentionally absent from revision
    detail because collected detail is unreachable; `listRevisions` is the read
    that survives collection and therefore the only honest lifecycle carrier.
12. **Secret impact `status` is authorized disclosure.** The server first builds
    the historical/current secret unit and applies both authorization formulas
    (`internal/service/rollback.go:138-167`), then requires the reveal ceremony
    (`rollback.go:168-170`). It computes set-vs-set equality only after those
    gates (`rollback.go:198-209`). Rendering status without `before`/`after` is
    therefore server-gated disclosure, not an ungated client inference.
13. **Schema override discovery is prose-bound for now.** The checkbox appears
    only after a positive match against the server's schema-refusal wording.
    That is intentionally fail-closed, but remains pending a structured refusal
    code so copy changes cannot hide the offer. `pinSchemaOverrideOffered`
    positively matches all three `validateResolved` schema-refusal shapes: value
    rule, presence rule and key-group rule. The value-rule browser path is green.
14. **The matrix KEY NAME opens the drawer filtered to that key** (Marc's
    disposition "a", 2026-08-19). The first cut kept #57's key-name → row-editor
    binding and called it a prototype-vs-prototype conflict; that was wrong:
    env-matrix iteration 31 wires NOTHING to the key name (`.kn` is a plain span),
    the row-editor-on-name was #57's own choice, and revision-history it-1/it-6
    is the only lock that speaks ("a key name click opens the same drawer
    filtered to that key"). So the name is now a link (`History of <KEY>`), any
    cell opens the row editor (unchanged, #57), and the row editor keeps its
    `History for <KEY>` link. `matrix.spec.ts` opens the editor from a cell;
    `history.spec.ts` proves both entries (matrix name, changed-key row) and the
    deep link. #57's handoff line is corrected in place.
15. **The pin-sheet comparison is a READ, not a disclosure.** It calls
    `exportValues` with `reveal:false`: config plaintext rides `read` (the same
    authority the matrix reads config under), secret lines are lineage
    write-presence, and no secret is ever opened — so the server writes NO
    `disclosure.value_revealed` event for it (`Export` audits only revealed
    secret entries, `internal/service/revisions.go`). The first cut of this
    ticket labelled the section "audited"; that was wrong and is gone. The
    browser flow pins the contract from both ends: the export request body
    carries `reveal:false` + the compared revision, and the server trail's
    disclosure count does not move across the click.
16. **The schema-override checkbox is the shared `.chk` control** (44px on a
    coarse pointer). It escaped the pinned sweep because it renders only after a
    refusal, so the pin-lifecycle flow asserts its touch target explicitly at
    the moment it exists (`expectTouchTargets`, mobile project) — the gap is
    closed in the pipeline, not noted.

### Deliberate ceilings (marked `ponytail:` in the code)

- `restoreCeremonyUnit` cannot see WRITTEN-TIME (sticky) classification, so a key
  reclassified since the target revision was published can put the enumerated
  unit one key out of step with the server's. The consequence is bounded and
  loud — a protected environment refuses it as a unit mismatch and the surface
  says so — never a disclosure. Carry the sticky bit on `SnapshotKey` if it ever
  shows up in practice.
  This is the one client-invisible ceremony-unit gap: the ponytail ceiling.
- `pastNormalRetention` duplicates the GC's own predicate
  (`ListEligibleSnapshotPayloads`) because no endpoint answers "would this be
  collected". It only decides how LOUD a release confirmation is; the server
  still refuses a collected payload by name, so a drifted client warns wrongly
  rather than deleting wrongly.

## e2e coverage map

`web/e2e/flows/history.spec.ts`, registry flow `history` → surface `history`
(`web/e2e/registry.ts`). Serial, desktop + mobile projects, dark + light pinned
passes. The pinned assertion set runs FIRST in the file, deliberately: the two
ceremony-bearing tests reissue the browser session, so asserting the surface
before anything mutates it keeps the S3 evidence off that dependency.

| Criterion | Test |
|---|---|
| C5 [UI] restore flow from the history drawer | `restores an environment to an earlier revision and publishes the staged drafts` captures rollback and publish at the wire, then proves `preview_token` and the exact version-id set through the in-drawer action |
| C5 ordinary publish path | `restores one key from the changed-key row` proves the matrix publish sheet carries the same captured token and exact previewed set |
| C5 partial overlap | `refuses partial restore overlap, then publishes the restore set alone` stages another key in the same environment, proves the named client refusal sends zero `/publish` requests, then re-stages and proves publish-alone sends exactly one request carrying the exact restore set |
| C5 schema-failing restore | `refuses a schema-failing restore loud, naming the key` proves the exact `value for "WORKERS" is invalid (` alert prefix, then identifies the surviving draft by the restore-returned version ID and asserts its rollback-preview base revision, `revealed: true`, and the older revision's invalid value; no publish success and unchanged revision list |
| C5 secret restore impact | `renders secret restore impact status-only and never exposes its value` proves a secret-bearing restore has status-only impact, no before/after arrow or fixture value, and spends the rollback token when published |
| S3 drawer + environment tabs | `opens from the matrix environment header and reads one environment at a time` proves header entry, current revision/list order, per-environment counts, and a retention line with no descendants matching the shared canonical interactive selector |
| S3 per-key filter | `filters the timeline to one key, by click and by URL` proves the URL carries immutable key ID while visible copy uses key name |
| S3 lineage secret safety | `shows one revision’s lineage without ever showing a secret value` proves write-presence-only lineage and absence of every seeded secret string in list and detail |
| S3 pin gap + expiry | `shows the behind-latest gap sentence and warning-tier expiry as text` derives the exact publish gap and expiry tier from live state and proves both visible strings |
| S3 historical pin + comparison | `requires a fresh-session ceremony for a historical move and audits comparison` requires the ceremony in a new cookie jar, verifies `history_authorized: true`, runs the read-only comparison and proves the export request carried `reveal` not true for the compared revision, the named changed config key plus unchanged-config cardinality, secret write-presence lineage copy, no fixture secret on any visited state (ceremony modals included), and a server-trail disclosure delta of exactly zero |
| S3 renew, override + release | `runs renew, schema override, and retention-gated one-click release` proves the 365-day refusal, renew, successful-retention one-click release, value-rule override discovery, schema-drift pin, and cleanup |
| S3 pinned assertion set | `meets the pinned assertion set on Revision history (dark|light)` on both viewport projects |
| S3 mobile focus | `keeps the mobile matrix inert and restores drawer focus` proves matrix inert, title/detail focus, and selected-row focus restoration |
| S3 registry closure | Teardown requires both `dark` and `light` executions for every claimed flow/surface; registry unit test proves one-theme-only fails |

**Fixture (`web/e2e/fixtures/seed.ts`).** Its own project, `ledger` — one
instance serves the whole suite and the matrix flow asserts exact key counts and
exact cell text in `payments`. Three value publishes in `development` (a secret
edit and a config edit between them), one in `staging`, a declaration tightened
afterwards, two workload service accounts, and one pin on the current revision
with an expiry inside the 30-day warning tier. The break-glass grant loop gains
`pin` and `reveal-history`.

**Revision numbers used by actions are READ, never assumed.** The fixture carries
only the seeded baseline count and seeded pin revision so pass one can prove it
did not repair away global-setup state; every actionable revision is derived.
Two properties forced this and both are easy to get wrong:

- Every SCHEMA act mints its own revision in every environment of the project —
  creating a key and tightening a declaration each advance the environment
  though they change no value — so three publishes are emphatically not
  `r1..r3`. The first version of this flow hard-coded them and was really a test
  of when a revision happens to be minted.
- **The flow MUTATES its project** (it restores and publishes) and Playwright
  runs it once per viewport project against ONE instance, so pass two starts from
  whatever pass one left. Any number captured at seed time is wrong by then.

So the flow derives every action target in `beforeAll`, from the same
`listRevisions` projection, and repairs the two pieces of state pass one moves
only when drift is actually present:
the invalid draft the schema-refusal test necessarily leaves staged (superseded
with a valid value and published — otherwise pass two's restores drag it into
their publish and are refused for pass one's reason), and the pins (released,
then one canonical pin re-created on the current revision only when pins differ).
On a fresh pass the test asserts the seeded revision count, workload, pin
revision and expiry exactly. Its bearer session is its own password login: the shared storage state
is re-minted several times per run and re-minting enrols a passkey, which kills
every session the principal holds — the seeding one included.

### Not reachable in the browser flow, and where it is covered instead

- **Collected-revision gating.** A payload is collected by the GC sweep, which
  runs at startup and hourly; a fixture cannot age a revision past the retention
  window inside a run. Covered by `revisionActionGate` in the vitest seam (all
  four states, including the policy-naming refusal) and by the isolation test
  above, which asserts the bit round-trips through a REAL sweep on both engines.
- **Sole-keeper release confirmation.** Same reason: it needs a revision past
  both retention dimensions. Covered by `soleKeeperPinIds` in the seam (seven
  cases, including the two-live-pins, expired-pin and already-collected
  exemptions). The one-click release the flow exercises is the non-sole path,
  which is what the ticket names for e2e.
- **Move consequence.** It requires moving the sole keeper of a revision already
  outside normal retention, the same unreachable retention-window state. Vitest
  covers the predicate and consequence copy.
- **Failed retention query.** The browser harness cannot force only that query
  to fail without request interception that would test a synthetic network
  response. D1's successful-query one-click path is exercised; failure stays at
  the query/component seam.
- **Per-key ID/name conflict.** Producing one requires deleting or replacing a
  seeded key, outside this fixture's non-destructive API path. Covered in vitest.
- **Reveal-history refusal naming keys.** Existing seeding has one interactive
  human principal. Creating a second editable human without `reveal-history`
  exceeds the bounded fixture change; permission/refusal wording remains seam
  coverage.

## Verification record (2026-08-19, orchestrator's own runs on the final tree)

| Check | Result |
|---|---|
| `gofmt -l .`, `go vet ./...`, `go build ./...` | clean |
| `go test ./...` (sqlite) | 2151 passed, 45 packages |
| `go tool oapi-codegen …` + `clients/ts` `pnpm run verify` (Node 24) | regen idempotent (md5 stable), TS client typecheck + 4/4 contract tests |
| `pnpm --dir web typecheck` | clean |
| `pnpm --dir web test` (Vitest) | 11 files, 152 tests passed (registry closure incl. the theme-aware negative fixture) |
| `pnpm --dir web build` | clean |
| `cd web && pnpm exec playwright test flows/history.spec.ts` (both viewport projects, one invocation) | 27 passed, 1 skipped (the mobile-only focus contract skips on desktop by design) |
| `cd web && pnpm e2e` — ONE unfiltered invocation, both viewport projects, dark + light, on the committed tree | 157 passed, 1 skipped (3.4 min); global teardown's theme-aware run-log closure ran and passed |

Review record: two-axis Standards + Spec (Claude sub-agents) and a capped
three-round native Codex (`gpt-5.6-sol`, high) adversarial loop, split by concern
(Go/API, seam, drawer, e2e). R1 found 11 Go/seam, 5 drawer, 5 e2e, plus
standards/spec items; all were fixed or dispositioned with evidence (secret
impact `status` is server-gated — decision 12; sticky written-time
classification is the one client-invisible ceremony-unit gap; the pin
comparison is a read, not a disclosure — decision 15). R2 verified the fixes and
left six partials, all fixed. R3 returned CLEAN on Go/API; its three remaining
items (opener snapshot at mount, ceremony-state secret negatives, this record)
were applied by the orchestrator before commit — the affected checks above are
from AFTER those edits.

Ports for this session: `HIKYO_E2E_PORT=45840 HIKYO_E2E_PORT_B=45841
HIKYO_E2E_PORT_TLS=45842`.

## Three harness findings, all fixed

1. **The registry's execution check never actually skipped under `--grep`**
   (campsite fix, `e2e/global-teardown.ts`). The predicate read
   `String(config.grep) !== '/.*/'`, and Playwright leaves the resolved config's
   `grep` at `/.*/` — the CLI filter is applied separately. So every filtered run
   ended, after its tests passed, with a wall of "claims more than it runs" lines
   about flows nobody asked to run: precisely the "check people work around
   instead of with" the file's own comment warns against. It now reads the CLI
   from `process.argv` and still consults the config field, which a `grep` set in
   `playwright.config.ts` does reach.
2. **`login answered 401` from `refreshSharedSession` was a STALE INSTANCE, not
   an auth bug.** A run killed without teardown leaves a server on the port with
   a different datastore behind it. `startInstanceAt` catches that for a fresh
   boot, but `mintStorageState` talks to `BASE_URL` directly — so it authenticated
   the fixture administrator against a stranger's database and got a perfectly
   correct credential refusal. Cost several hours of chasing an auth path that was
   working. If it reappears: `lsof -nP -iTCP:<HIKYO_E2E_PORT> -sTCP:LISTEN`
   first, before reading any Go.
3. **Theme-aware closure exposed login's missing light pinned-set execution.**
   `login.spec.ts` had a separate light-palette check, but only the dark test
   called `expectPinnedAssertionSet`, so final teardown correctly refused the
   claim. The pinned set now runs as distinct dark and light tests; the next
   unfiltered run recorded both and passed closure.

## Deferred, by name

- **Revision-to-revision diff** (decision 1). Needs an endpoint.
- **Retention EDITING** — project settings › Policy and org settings › Policy,
  #60's surface. This drawer reports the policy and never writes it.
- **Sole-keeper release confirmation is not exercised in a browser** (above); the
  predicate and the sheet exist and the seam covers the predicate.
- **A schema-failing publish flags no matrix CELL.** `matrixPublishValidation`
  indexes a problem against `(key, environment)`, and the value-rule refusal
  names a key but no environment (a publish can span several). The alert names
  the key and points at the row editor, which is the ticket's stated minimum.
  Naming the environment would need the refusal to carry it.
