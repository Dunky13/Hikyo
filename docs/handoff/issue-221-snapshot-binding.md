# Issue #221 — validated offline snapshot binding

## Outcome

Offline snapshot scope, storage location, credential binding, delivery identity,
projection, targets, and issuance window now travel as one immutable
`crypto.SnapshotBinding`. Live fetch completes the locally constructed binding
once; offline load validates the same scope before key or snapshot filesystem
work and returns the stored delivery-complete binding.

## Contract choices

- `HKS1` framing and `SnapshotAAD` JSON field names/order are unchanged.
- `StorageDir` belongs to the validated binding but is not serialized or
  authenticated; moving local state does not change snapshot cryptographic
  identity.
- Targets, projection, and RFC3339 timestamps canonicalize before live save.
- Scope-only bindings are valid offline locators. Save requires a
  delivery-complete binding; mixed/partial delivery fields cannot be built.
- Existing snapshots need no migration. A literal pre-change HKS1 fixture loads
  with the new representation.

## Generated outputs

None.

## Validation

- `go test -count=1 ./internal/cli/... ./internal/crypto/... ./internal/compose/...` — 479 passed.
- `go vet ./internal/cli/... ./internal/crypto/... ./internal/compose/...` — passed.
- `go test -count=1 ./...` — 3,092 passed across 57 packages.
- Two-axis review (standards/security and issue #221 spec), round 2 — CLEAN / CLEAN.
