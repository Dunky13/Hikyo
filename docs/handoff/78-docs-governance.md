# Issue #78 handoff — docs site and governance artifacts

## Outcome

Issue #78 implements MVP acceptance criteria O4–O6:

- Starlight generates a GitHub Pages site at `https://dunky13.github.io/wenv/`.
- Root policy files remain canonical; `docs/site/scripts/prepare-content.mjs`
  derives site pages at build time.
- Release CI fails when locked security, governance, licensing, or support text is
  missing from source or built HTML.
- Release CI checks the live `security.txt`, security/support pages, and the MX
  route for `security@developwent.io`.

## Policy artifacts

- `SECURITY.md`: PVR primary, `security@developwent.io` fallback, 7-day
  acknowledgement, 14/30/next-release fix targets, and 90-day embargo rules.
- `GOVERNANCE.md`: honest BDFL authority, 12-month continuity threshold, locked
  amendment procedure, and full no-`/ee` pledge.
- `SUPPORT.md`: exactly one supported version, same-day previous-minor EOL, no
  backports, and prereleases unsupported.
- `TRADEMARK.md`, `CONTRIBUTING.md`, and the README pledge publish the remaining
  locked OSS mechanics.
- `LICENSE` is byte-exact MPL-2.0; the CI-pinned SHA-256 is
  `3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04`.

## Repository state outside Git

The GitHub repository settings were applied while implementing this ticket:

- Private Vulnerability Reporting: enabled.
- GitHub Pages: enabled with `build_type=workflow`, HTTPS enforced, URL
  `https://dunky13.github.io/wenv/`.

The first live deployment starts only after this branch reaches `main`; the
release live gate intentionally remains red until that deployment exists.

## Validation

- Go: build, vet, and 399 tests passed across 30 packages.
- TypeScript client: generated client, typecheck, and Node tests passed.
- Docs: dependency peers clean; Astro check 0 errors/warnings/hints; 9 pages
  built; O4–O6 source and served-site gates passed.
- CI: ShellCheck and actionlint passed; all release fixture scripts passed.
- Browser: Chromium at 1440×900 and 390×844; no console errors or horizontal
  overflow; mobile hero actions are exactly 44px high.

## Deployment verification after merge

1. Confirm the `docs` workflow succeeds at the merge commit.
2. Run `./scripts/ci/check-docs-live.sh https://dunky13.github.io/wenv security@developwent.io`.
3. Confirm `https://dunky13.github.io/wenv/.well-known/security.txt` serves the
   two locked contacts.
