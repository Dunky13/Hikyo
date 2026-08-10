# Hikyo rebrand handoff

Branch: `t3code/rebrand-wenv-to-hikyo`

## Delivered

- Product copy, CLI output, Go module/imports, API metadata, docs, and policies
  use `Hikyo` / `hikyo`.
- Runtime configuration uses `HIKYO_*`; local state uses `hikyo` paths and
  `.hikyo.json` project pins.
- Public contract extensions use `x-hikyo-*`; release schemas use
  `hikyo.dev/*`.
- Release artifacts, OCI identities, installer, Helm chart, and generated
  TypeScript packages use `hikyo`.
- Tracked executable and chart paths are `cmd/hikyo` and `chart/hikyo`.

## Intentionally unchanged

- Existing checkout and worktree directory names stay in place.
- Local Git remote configuration stays in place; it is not tracked source.
- The locked `ew_` bearer-token grammar and `wenv/change-token/v1` HKDF label
  remain unchanged for verifier, secret-scanner, and derived-key compatibility.

## External cutover

Rename the GitHub repository and Pages deployment to `hikyo` before publishing
the first rebranded release. Tracked links and release coordinates already
target `Dunky13/hikyo`, `dunky13.github.io/hikyo`, and
`ghcr.io/dunky13/hikyo`.

## Compatibility

This is a pre-1.0 identity cutover. Operators must rename `WENV_*` environment
variables to `HIKYO_*` and move client state to the new `hikyo` state directory
before starting the rebranded binary. Repository-local `.wenv.json` project pins
must be renamed to `.hikyo.json` at the same time.
