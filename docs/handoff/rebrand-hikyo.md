# Hikyo rebrand handoff

Branch: historical rebrand branch (merged)

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
- The `wenv/change-token/v1` HKDF label remains unchanged for derived-key
  compatibility; it is immutable cryptographic protocol data, not branding.

## External cutover

The GitHub repository was transferred to `Hikyo-Org/hikyo` on 2026-08-14;
existing checkouts must update their `origin` URL. GitHub Pages serves the
verified canonical `https://hikyo.app/` domain. Tracked links and release
coordinates target the organization repository and `ghcr.io/hikyo-org/hikyo`.

## Compatibility

This is a pre-1.0 identity cutover. Operators must rename `WENV_*` environment
variables to `HIKYO_*` and move client state to the new `hikyo` state directory
before starting the rebranded binary. Repository-local `.wenv.json` project pins
must be renamed to `.hikyo.json` at the same time. Bearer artifacts now use the
`hik_` prefix; every existing `ew_` session, token, recovery code, session-bound
CSRF token, OIDC state, and OIDC browser-binding cookie is rejected and must be
reissued after the cutover. Invalid legacy artifacts remain confidential and are
still removed by audit redaction.
