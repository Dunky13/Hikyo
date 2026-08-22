# Handoff: #220 private scoped-token derivation

Issue: https://github.com/Hikyo-Org/Hikyo/issues/220 (parent #204; programme
#203; audit ID `BE05-A`).

## Contract

- `Keyring.deriveScopedTokenKey` is the only scoped token-key derivation. It
  applies HKDF-SHA256 to the live root token key with the canonical
  length-prefixed `(label, org, project, environment)` info encoding.
- Change tokens, delivery cursors, import occurrences, and publish previews
  retain their immutable purpose labels and public token bytes.
- `ScopedTokenKey` is retired. No exported API returns a raw scoped token key;
  each purpose API derives per call, defers `Zero`, tags its caller-owned
  encoding, and retains no cache.
- Root-token-key locking and rotation behavior are unchanged.

## Regression evidence

`TestScopedTokenFamiliesPreserveGoldenVectorsAndScopeSeparation` uses a fixed
root, scope, and payload to pin one byte-exact token for every purpose. Each
purpose also proves cross-purpose domain separation, cross-organization scope
separation, and injectivity across the `("a", "bc")` / `("ab", "c")` field
boundary. The former raw-key injectivity test is removed with the exported raw
key seam.

Generated outputs: none.

## Validation

```text
go test -count=1 ./internal/crypto/...         123 passed
go test -race -count=1 ./internal/crypto/...   123 passed
go test -count=1 ./...                         3066 passed in 57 packages
git diff --cached --check origin/main          passed
```

Two-axis Codex review against issue #220 and the crypto ADRs reported zero
standards findings and zero specification findings.
