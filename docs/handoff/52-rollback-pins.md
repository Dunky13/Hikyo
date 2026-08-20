# Handoff: #52 rollback & pins — restore as publish, durable pins (E2E)

Issue: https://github.com/Hikyo-Org/Hikyo/issues/52 (parent #41, blocked by
#51 — merged). Specs, all on `wayfinder-docs`: `docs/adr/revision-model.md`
(§ Rollback, § Diffs and secret safety, § Retention — read through the
flat-model amendment banner: the `masked` restore rows, "never weakens a
mask", and the flatten-provenance paragraph are VOID; the restore comparison
is two-way `set | unset`), `docs/adr/ops-spec.md` (§ Pins & grants, limits
row 15), `docs/adr/mvp-boundary.md` row C5, `docs/adr/permission-model.md`
(grant primitive; the pin/restore history gates), `docs/adr/api-cli-surface.md`
(locked verb taxonomy). Predecessor context: `docs/handoff/51-revisions-publish.md`.

Scope: rollback/restore and pins, E2E only. The history-drawer UI is its own
ticket; GC and the retention-policy engine are #53's.

Implementation was authored by Codex (gpt-5.6-sol, high) under an
orchestrated brief; reviewed on Standards + Spec axes; two fix rounds.

## Restore — staged drafts through the normal publish pipeline

`revision rollback` (env-level, or `--key` for one key) stages ordinary
caller-owned pending changes with `source=restore` and materializes nothing
itself. Publish remains the only authority: current-schema validation
(schema-failing restore blocks loud naming the keys — C5), per-environment
publish authorization immediately before commit, serializable per project.
`revision.published.trigger` is `restore` when any selected draft was
restore-authored; `revision.restore_staged` plus per-key `value.staged`
events are emitted at staging.

- Two-way comparison per the flat-model amendment: rev N `set(v)` vs current
  differing → stage `set(v)`; rev N unset vs current set → stage a clear;
  matching outcomes untouched (no churn). No masks, no shared layers.
- Least-blast: only the target environment's own entries are ever written.
- **The disclosure gates bind at staging time**, before secret plaintext is
  decrypted into the caller's drafts. Historical secret material requires
  `read + reveal-history`; current secret material used for comparison requires
  `read + reveal`. The two sides are evaluated independently. Human restores
  consume one purpose-bound ceremony over the combined enumerated secret-key
  unit, and write one `disclosure.value_revealed` event per secret side read.
  Restore of the CURRENT revision needs no history gate.
- **Classification is sticky to the immutable value occurrence** (review fix
  F1, blocking). Payload-free `secret_value_occurrences` lineage survives
  snapshot collection, while restore-authored pending rows carry the sticky
  secret bit forward. Reclassification and later GC therefore cannot launder
  material past the disclosure gate or into a config preview. Pinned by the
  `restore_gate_uses_written_time_classification` and
  `secret_classification_survives_payload_collection` scenarios.
- A collected payload (`snapshots.payload_present = 0`) fails loud naming the
  revision, before staging anything.
- Restore returns the complete selected + key-group-closed impact preview. Its
  opaque token binds the exact versions, base revision, schema revision, and
  principal grant generation; publishing restore-authored drafts rejects a
  missing or stale token. Secret rows are always status-only. Protected human
  publishes require a publish ceremony; machine/local callers must name the
  exact reviewed protected-environment set.
- Per-key restore refuses a historical row whose name was later reused by a
  different key identity, instead of clearing the replacement.

## Pins — durable, quota-bounded, expiry-bounded retention exceptions

Migration `00022_rollback_pins.sql` (both dialects): `revision_pins` with
composite ancestry FKs, `UNIQUE (org_id, project_id, environment_id,
workload_principal_id)` — ≤1 pin per (workload, env) structurally — plus
`snapshots.payload_present`, `pending_changes.source`, sticky pending
sensitivity, and payload-free `secret_value_occurrences` lineage.

- CLI is the locked taxonomy: `pin create | list | release`. Repeating
  `pin create` on the same revision renews; on a different revision
  reassigns. There is deliberately no separate renew verb
  (`api-cli-surface.md`).
- Quota 100/project, refused naming the quota. Expiry mandatory: default
  180 d on omission; an explicit expiry not in the future or beyond the
  365 d max is refused loud naming the bound, audited as
  `pin.expiry_refused` with a bounded cause.
- Creating, reassigning, or renewing a NON-current revision authorizes the
  history gate (`reveal-history` seam, `pin.set-history`), consumes a
  purpose-bound ceremony for its secret-key set, and audits each disclosed
  secret with the pinned revision. Historical status is recomputed at the
  time of every mutation, so a formerly-current pin cannot bypass the gate.
- **Renewal revalidates against the current schema.** An invalid existing pin
  remains deliverable but renewal records `schema_override=true`, surfacing
  the new drift instead of copying stale creation metadata.
  Reassignment is a new target decision and validates normally.
- Pinning a revision that fails CURRENT-schema validation requires
  `--override-schema`; the override is recorded **only when actually
  consumed** (review fix F2) so the operator drift surface lists real
  exceptions only.
- Pin create + payload-retained marking is one transaction under the project
  lock — GC (#53) can never collect a payload a concurrent pin is acquiring.
  The durable contract #53 must honor: a live pin's snapshot payload is not
  collectible; collection flips `payload_present` and pinned delivery /
  restore then fail loud naming the revision.
- **Pinned delivery**: `Delivery.Fetch` routes through a live pin for the
  calling workload and re-checks the pin's recorded authority principal
  (pin + publish grants, plus a freshly recomputed history gate) on EVERY
  fetch; a
  revoked authority refuses loud, never silently downgrades to latest.
  Expiry never changes delivery: an expired pin keeps delivering while the
  payload survives, reported as `pin_expired` status; post-collection fetch
  fails loud until re-pin or release. Pinned delivery is the documented
  exception to current-schema validation (delivered verbatim).
- Every pin mutation (create/reassign/renew/release, plus env-delete
  cascade) advances the workload's per-environment pin generation on the
  federation cursor, so delivery cursors cannot hide routing changes.
- Principal deletion removes its pin-generation rows before the principal,
  so the lifecycle cannot be blocked by the generation-table foreign key.

Audit types: `pin.created`, `pin.reassigned`, `pin.renewed`, `pin.released`,
`pin.expiry_refused`, `revision.restore_staged` — all metadata only, never a
value.

## C5 test map

| criterion | test |
|---|---|
| restore of a superseded secret requires `reveal-history` | `conformance: restore_of_superseded_secret_takes_reveal_history` |
| written-time classification cannot be laundered by reclassify | `conformance: restore_gate_uses_written_time_classification` |
| secret classification survives historical payload collection | `conformance: secret_classification_survives_payload_collection` |
| current and historical secret sides require only their own reveal formula | `conformance: restore_secret_formulas_are_side_specific` |
| schema-failing restore blocks loud | `conformance: schema_failing_restore_blocks_loud` |
| pin lifecycle: create/re-pin/renew/release, expiry + quota refusals by name, expired + collected delivery | `conformance: pin_lifecycle_quota_and_expiry_refusals_by_name` |

The pin scenario additionally covers: creation-time authorization surviving
a later publish, schema override + grandfathered renewal, authority-grant
loss on pinned fetch, the 100/101 quota boundary, and collected-payload
refusals on both restore and pinned delivery.

Commands:

    go test ./internal/conformance/ -count=1 -run TestConformanceSQLite
    go test ./internal/isolation/ -count=1
    # database must be OWNED by the hikyo role (the harness drops tables)
    HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_52_rollback \
      go test ./internal/conformance/ ./internal/isolation/ ./internal/store/... -count=1

Verified at handoff: full `go test ./...` green (sqlite), conformance +
isolation + store green against PostgreSQL, `go tool sqlc generate`
diff-clean, `go vet` and gofmt clean, and the generated TypeScript client
(`clients/ts`, `pnpm run verify` under the pinned Node) regenerated from
the updated `api/openapi.yaml` — CI's `validation / client` job diffs it,
so an OpenAPI change without the regen fails the pipeline.

## Review rounds

Round 1 (two-axis, Standards + Spec) surfaced 11 findings, all fixed:

- **F1 (blocking, spec)** — restore history gate consulted only the CURRENT
  classification; written-time classification now participates (stricter of
  the two sides). See above.
- **F2 (spec)** — `schema_override` was recorded whenever the flag was
  passed, even if validation succeeded; now recorded only when consumed.
- F3–F10 (standards) — stale comment in `authz/classify.go`; query renamed
  `UpsertRevisionPin`→`InsertRevisionPin` (it is a plain insert; replace is
  delete-then-insert in the service); `historyAuthorized` disambiguated
  (`historyGated` on the pin side); renewal decided once; triplicated audit
  schema literal shared; absent-key check extracted to one helper;
  `domain.PrincipalID` through the pin service API; conformance assertions
  use the service action constants.
- F11 (docs) — 30/7/1 d pin-expiry warnings named as deferred: UI badge to
  the history-drawer ticket, doctor warning to the pruning-health surface.

Declined as judgement calls (dispositioned, not forgotten):
`hierarchyFailureEvent` keeps its single-caller shape for registry symmetry;
the pin-generation cursor advance and env-delete pin cascade are spec-silent
but required by the no-silent-change rule.

Round 2 addressed all 12 PR findings: restore and historical-pin ceremonies
plus per-key disclosure audit; recomputed pin history/schema gates; principal
generation cleanup; delivery retry-output reset; recorded-authority formula
evaluation without caller impersonation; per-key identity refusal; exact CLI
arity; protected publish confirmation; and a full bound impact preview. The
Standards follow-up found one duplicated authorization predicate; it was
extracted into a shared formula evaluator before final validation.

The Round 2 adversarial verification found five remaining gaps, all fixed:
sticky classification now has payload-free durable lineage; recorded-authority
denials attribute the fetching workload as actor and the recorded principal as
authority; restore applies current/history reveal formulas independently; the
wire and CLI expose the complete protected impact preview and accept an exact
multi-environment confirmation set; and the delivery regression forces a real
`tx.Write` retry through the production reset anchor. Round 3 is the capped
final CLEAN/blocker disposition gate. It returned one explicit blocker:
restore-to-absent was requiring current reveal despite reading no current
plaintext. The condition now gates current reveal only for set-vs-set
comparison, with a dedicated no-reveal secret-clear conformance regression.

## Known gaps / deferred

- **GC and retention policy are #53's.** This slice supplies the contract:
  `revision_pins` as the observable reference, `payload_present` as the
  collection bit, loud refusals on collected payloads.
- **Pin expiry warnings (30/7/1 d)** — doctor + UI surfaces, see F11 above.
- **No UI.** The history drawer (restore flow, pin badges, drift surface)
  is its own ticket.
