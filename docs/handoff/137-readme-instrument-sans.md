# Handoff: PR #137 README and Instrument Sans

## Scope

PR [#137](https://github.com/Hikyo-Org/Hikyo/pull/137) refreshes the repository
README and adopts Instrument Sans as Hikyo's house sans-serif across the web
app, landing page, and documentation.

## Decisions

- Instrument Sans owns interface and body typography.
- IBM Plex Mono remains reserved for code, keys, and values.
- The app uses the variable Fontsource package; the docs load static 400, 500,
  and 700 weights. All packages remain pinned at `5.3.0`.
- Fonts remain self-hosted with `font-display: swap`; no CSP or external-egress
  change is required.
- The README uses the existing Hikyo mark and a semantic environment matrix
  rather than adding an unmaintained screenshot.

## Changed surfaces

- `README.md`: branded first screen, product proof, quick start, CLI examples,
  production boundary, OSS commitment, and goal-based documentation map.
- `.impeccable.md`: Instrument Sans is the canonical interface/body typeface.
- `web/`: variable font dependency, import, design token, and computed-font
  assertion description.
- `docs/site/`: static font dependency and both landing/docs stylesheet stacks.

## Verification

- Web TypeScript check passed.
- Vitest: 86 tests passed.
- Playwright: 124 desktop/mobile tests passed across dark and light themes,
  including computed typeface assertions.
- Astro: 0 errors, warnings, or hints; 31 pages built.
- OSS policy, live-doc, and fallback-channel gates passed.
- Local desktop/mobile previews showed Instrument Sans loaded on landing and
  docs pages with no horizontal overflow.

For a fresh checkout, install `clients/ts` before validating `web`; the web
package consumes generated client source whose `zod` dependency is owned by
that standalone package.
