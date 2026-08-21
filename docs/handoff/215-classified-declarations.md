# #215 — Classified declaration compilation

Issue: https://github.com/Hikyo-Org/Hikyo/issues/215.

**State: implemented.** Declaration validity, normalization, classification
compatibility, validator compilation, canonical storage bytes, and validation
disclosure now originate from one classified artifact.

## Contract

- `schema.CompileClassified` is the only production constructor. It rejects an
  unknown classification, normalizes once, enforces secret/config compatibility,
  and compiles validators from that normalized declaration.
- `schema.Compiled` retains the classification. `Validate` accepts only a value,
  so a caller cannot compile as config and validate as secret or the reverse.
- `Compiled.Canonical` serializes the artifact's normalized declaration.
  `Compiled.Declaration` returns a deep clone, preserving artifact immutability.
- Classification-compatibility-skipping fixtures use
  `CompileWithoutCompatibilityCheckForTest`, available only in `export_test.go`.

## Boundary migration

- Definition parsing returns a `CompiledBundle`: raw normalized wire DTOs remain
  in `Bundle`, while a private sidecar carries compiled declarations through
  apply. Normal and scanner-skew apply paths reuse those artifacts and never
  compile a declaration twice in one apply.
- Direct key create/update, definition create/update, stored value validation,
  and both reclassification directions use classified artifacts.
- Import type suggestions compile their fixed primitive declarations as secret,
  which is compatible with both suggested primitives.

Canonical bundle/declaration JSON bytes and wire shapes are unchanged. Generated
outputs: none.

## Validation

- `go vet ./...`: green.
- `go test -count=1 ./internal/schema/... ./internal/definitions/... ./internal/service/...`: green.
- `go test -count=1 ./...`: green across all Go packages.
- Two-axis review rounds 1 and 2 found four issues; all were fixed. Round 3
  returned spec `SOUND`; its sole standards finding was this handoff's helper
  wording, corrected before commit.
