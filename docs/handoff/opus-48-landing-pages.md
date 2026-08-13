# Handoff: Opus 4.8 landing page on GitHub Pages

## Outcome

The GitHub Pages root at `/hikyo/` now implements the visual direction and page
structure of `prototype/landing-opus-4.8/2/` from the `wayfinder-docs` branch.
The Starlight documentation overview moved from `/hikyo/` to `/hikyo/docs/`.

## Production corrections

The frozen prototype predated the flat-value and MPL-2.0 decisions. The public
implementation keeps its graphite/linen theme, teal accent, environment matrix,
asymmetric feature rows, self-hosting band, and compact footer while replacing:

- inherited/default value states with explicit `set` and `absent` states;
- MIT wording with Mozilla Public License 2.0 wording;
- placeholder install, pricing, sign-in, star-count, and community links with
  real GitHub and generated documentation routes;
- unimplemented `run`/`render` demonstrations with current write validation and
  the catalogue/classification/presence-only machine-fetch boundary.

## Files

- `docs/site/src/pages/index.astro` — standalone landing route.
- `docs/site/src/styles/landing.css` — responsive dual-theme landing styles.
- `docs/site/src/content/docs/docs.mdx` — relocated documentation overview.
- `docs/site/astro.config.mjs` — overview sidebar route.
- `scripts/ci/check-oss-policy.sh` — generated landing assertions.

## Verification

- `fnm exec --using 24 ./scripts/ci/verify-docs.sh` passes.
- Astro check reports zero errors, warnings, or hints.
- Generated `/hikyo/`, `/hikyo/docs/`, and `/hikyo/security/` routes return 200.
- Generated links retain the GitHub Pages `/hikyo/` base path.
- T3 preview navigation loaded the landing page title at 1280×800. Snapshot and
  DOM automation timed out, so this handoff does not claim screenshot-based
  desktop or mobile verification.
