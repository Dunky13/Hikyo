# Handoff: #216 validating registry constructor

Issue: https://github.com/Hikyo-Org/Hikyo/issues/216. Related invariants live in
`docs/adr/tenant-isolation.md` (registry completeness, invariant 6) and
`docs/adr/audit-model.md` (audit disposition, CI invariant 2).

## Outcome

An invalid authorization registry can no longer be installed. The operation
policy table is validated by a constructor that runs at package init; a
malformed row aborts initialization (panic in `mustNewRegistry`) rather than
surfacing later as a runtime authorization anomaly. Production lookups read the
immutable `*Registry`, never the raw table.

## What exists

`internal/authz/registry.go`:

- `operationTable` — the reviewable policy table, unchanged in content. It was
  renamed from `operations` and is **never read directly** by production; only
  `newRegistry` and the constructor tests touch it.
- `type Registry struct{ ops map[Operation]opSpec }` — immutable. The
  constructor **deep-clones** every mutable field of each row (`cloneSpec`:
  `formula`/`events` slices and the `storeOps` map), so an installed row shares
  no backing with `operationTable` or a caller fixture — a later mutation of the
  source cannot reach in. Read-side access also exposes no mutable backing:
  `authorizationSpec(op)` returns only authorization fields and defensively
  copies the formula, while `permitsStoreOp` and `permitsEvent` answer membership
  inside `Registry`. Unknown operations, store ops, and events return false.
- `newRegistry(table) (*Registry, error)` / `mustNewRegistry` — validate then
  freeze. `var registry = mustNewRegistry(operationTable)` installs the one
  registry at init.
- `validateSpec` / `validateAuditDisposition` — the single place every
  in-package invariant lives (acceptance #4). Adding an operation must satisfy
  it. `opSpec` gained an internal `reviewExempt` marker (set on
  `definitions.plan.get` and `scim-discovery.read`) so the reviewed
  no-event/no-audited-none disposition is explicit in the row, not implicit in
  the absence of the other two. It is not exposed by `RegistryFacts`/
  `AuditMappings`, so those exports stay byte-equivalent.
- `storeOpCatalogue` — the closed in-package set of the 250 `StoreOp` constants,
  generated from the const block and diff-verified equal to it at authoring
  (const identifiers vs catalogue keys, sorted `diff` → identical). A row naming
  a StoreOp absent here is rejected at construction. Adding a StoreOp const means
  adding it to the catalogue. Deleting a const compile-breaks the catalogue entry
  that references it, so the two cannot silently diverge.

Lookups rewired from `operations[op]` to `registry.authorizationSpec(op)`,
`permitsStoreOp`, `permitsEvent`, or internal `registry.ops`: `authorize.go`
(×2), `denial.go`, `session.go`, `verify.go` (×2), and the six `RegistryFacts`
iterators. Fail-closed semantics at both `verify.go` sites are preserved.

## Invariants enforced in the constructor (in-package)

| Invariant | Rule |
|---|---|
| valid class | `class ∈ {tenant, instance}` only; unauthenticated / system / stub rejected (those are wire/verb classes, never operation rows) |
| class/level | tenant op ⇒ `level ∈ {org, project, env}`; instance op ⇒ `level = none` |
| deny-by-default | non-empty formula |
| capability | every atom's `Cap` passes `domain.IsCapability`; atom level is one of the four depths; atom no deeper than `domain.DeepestLevel(cap)`; tenant atom no deeper than the op's level |
| known store op | every `storeOps` key is in `storeOpCatalogue`; no `false` value (presence must mean licensed) |
| one audit disposition | **exactly one** of `events`, `auditedNone`, `reviewExempt`; exemptions accepted only for the two reviewed operation names; `auditedNone` only under the permit rule (tenant class, all-`read` formula, all store ops read-only); each event non-empty, registered via `audit.Spec`, no duplicates |

## What deliberately stayed in `internal/isolation` (cross-contract)

- **Store-op existence.** The catalogue is the in-package "known store op" half.
  That a StoreOp corresponds to a real store *method* needs `internal/store`
  reflection; `boundary_test.go:22` restricts `internal/authz` to `store/authn`
  only, so that half stays in `TestInvariant06...Completeness`.
- **Audit completeness "audited or pinned".** The two `reviewExempt` rows carry
  no event and no audited-none by design; the completeness invariant still pins
  them by name in `testdata/audited_exemptions.json` (isolation). The
  constructor enforces exactly-one-disposition; isolation keeps the name pin.

## Key uniqueness

Enforced one step earlier than any constructor could: `operationTable` is a map
literal, so the compiler rejects a duplicate operation key. The constructor
instead rejects the empty-key case. No runtime duplicate-key test exists because
the shape makes duplicates uncompilable — converting the 178 KB table to a slice
to make it runtime-checkable would destroy reviewability for zero safety gain.

## Tests

`internal/authz/registry_test.go` (`package authz`, needs unexported `opSpec`):
focused constructor negatives across every invariant above (class, class/level,
capability, atom depth, store-op catalogue, false store-op entry, the three
audit dispositions incl. none/conflicting, event well-formedness/registration/
duplicates, empty key), plus `TestConstructorAcceptsBaseSpec` (keeps the
negatives from passing vacuously), `TestConstructorDeepClonesSpec` (immutability:
mutating every nested source field after construction leaves the row unchanged),
and `TestConstructorAcceptsRealTable` (green anchor).

## Verification run

- `go test ./internal/authz/` — 52 passed after parent review added negative
  fixtures for unreviewed exemptions, instance operations with tenant formula
  atoms, and lookup mutation; it also added StoreOp catalogue totality coverage.
- `HIKYO_TEST_POSTGRES_DSN=... go test -count=1 ./internal/authz/... ./api/...
  ./internal/isolation/...` — 2,197 passed across four packages. This retained
  `TestInvariant06a` (formula pins byte-identical), audit completeness (the two
  reviewed exemptions remain name-pinned), and both database engines.
- `HIKYO_TEST_POSTGRES_DSN=... go test -count=1 ./...` — 4,002 passed across 56
  packages against SQLite and isolated PostgreSQL 18.
- `go vet ./...`, `gofmt -l internal/authz`, and `git diff --check` — clean.
- Blocking native Codex review: Standards CLEAN in round 3; Spec CLEAN in round
  2. Findings fixed before the final suite: instance formula scope, StoreOp
  catalogue totality, and read-side registry immutability.

## Notes for the reviewer

- TDD deviation: negatives were batch-written rather than one red-green slice at
  a time — both the first round and the second-round negatives added for these
  acceptance fixes were written against an already-working validator, never seen
  red individually. The positive `baseSpec` anchor plus the real-table anchor
  close the vacuous-pass risk that discipline guards against: if `baseSpec` were
  itself invalid the anchor fails, so each negative's rejection is attributable
  to its single mutation.
- Init-panic means a mid-edit developer sees every authz-importing package fail
  at once. That is the ticket's stated intent ("impossible to install"); the
  constructor negatives give the focused failure first.
