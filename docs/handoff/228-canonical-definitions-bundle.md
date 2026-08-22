# Handoff: #228 canonical definitions bundle

Issue: https://github.com/Hikyo-Org/Hikyo/issues/228 (parent #204; programme
#203; audit ID `BE11-A`). Implemented from `origin/main` at `6dff17c5`.

## Contract

- `definitions.Bundle` is the mutable wire/import DTO. Production encoders take
  only `CanonicalBundle`, whose state is private and whose zero value fails
  loudly.
- `Parse` and `Canonicalize` are the only canonical constructors. Both enforce
  format version, entry and encoded-byte limits, additive-ID rules,
  classification/declaration validity, presence rules, and deterministic
  ordering before a value becomes encodable. Strict parsing continues to reject
  unknown and duplicate members and trailing content.
- `Encode` and `Digest` accept only `CanonicalBundle`. Every successful encoded
  result therefore parses to the same canonical model and remains byte-stable.
- `WireBundle` returns a detached DTO for review, diffing, and scanning;
  mutating it cannot change the canonical snapshot.
- Import plans now carry the canonical type. Service export, plan persistence,
  apply pin checks, CLI scaffold/read paths, and all test/conformance callers
  canonicalize or parse before encoding.
- External bundle JSON and digest spelling are unchanged. Generated outputs:
  none.

## Review

Two-axis review against repository standards and issue #228 found one initial
fail-loud gap: zero-value observation could look like an empty additive bundle.
Zero-value observers now panic, the detached accessor is explicitly named, and
the obsolete `Normalize` alias is removed. Round 2: `CLEAN` / `CLEAN`.

## Validation

```text
go test -count=1 ./internal/definitions/... ./internal/importer/... \
  ./internal/service/... ./internal/cli/... ./internal/conformance/...  649 passed
go test -run '^$' -fuzz '^FuzzCanonicalBundleRoundTrip$' \
  -fuzztime=10s ./internal/definitions                              passed
go test -count=1 ./...                                               3186 passed / 57 packages
go vet ./...                                                         passed
git diff --check                                                     clean
```
