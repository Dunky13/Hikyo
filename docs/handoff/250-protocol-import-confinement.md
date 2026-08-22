# Issue #250 — Protocol-library import confinement

Issue: https://github.com/Hikyo-Org/Hikyo/issues/250.

**State: implemented.** OIDC, OAuth2, WebAuthn, SAML/XML-DSIG, and SOPS
dependencies are checked directly through one declarative boundary-test
registry and one `go list` import-graph walker.

## Stack position

- Stack root: PR #285 (`f8d18e5f6ea44e8ada3beb6609dd989b5bc74004`).
- Immediate parent: PR #286 (`afba6b088dc0982295c9f5586a79e0f7c8c76736`).
- This branch contributes only issue #250 and its handoff; generated outputs:
  none.

## Contract

- Import paths match an exact dependency module path or one of its subpackages;
  similarly named modules do not match.
- OIDC is confined to `internal/oidcrp` and the explicit workload-identity
  verifier exception in `internal/oidcfed`. OAuth2 is confined more narrowly to
  `internal/oidcrp`.
- WebAuthn is confined to `internal/webauthnrp`; SAML/XML-DSIG to
  `internal/samlsp` plus the `internal/samltest` signed-IdP fixture harness; and
  SOPS to `internal/importer`.
- Production, internal-test, and external-test imports are checked together.
  Generated production files receive no exception because their imports are
  part of the package graph returned by `go list`.
- Store, crypto, scanning, authorization, and forbidden-edge boundary rules
  remain separate invariants. Generated outputs: none.

## Validation

- `go test -count=1 ./internal/boundary/...`: 24 passed.
- `go vet ./...`: passed.
- `go test -count=1 ./...`: 3077 passed in 57 packages.
- Two-axis review round 1 found two standards issues and one spec-fixture gap;
  all were fixed. Round 2 returned Standards `CLEAN` and Spec `SOUND`.
