# Handoff: Fumadocs documentation

## Outcome

The GitHub Pages site keeps the custom landing page at `/hikyo/` and replaces
Starlight with Fumadocs for documentation, policy, and release-trust routes.
Astro remains the static-site host; Fumadocs UI runs as a React island and the
search index is generated at build time.

## Routes

- `/hikyo/docs/` — documentation overview.
- `/hikyo/docs/getting-started/` — source build, evaluation server, and first-admin bootstrap.
- `/hikyo/docs/core-concepts/` — value, disclosure, validation, authorization, and audit rules.
- `/hikyo/docs/self-hosting/` — production datastore, root-key, network, and backup boundaries.
- Existing root policy routes and `/hikyo/release/signing/` remain stable.

## Implementation notes

- `docs/site/src/lib/source.ts` adapts Astro content collections to the Fumadocs page tree.
- `docs/site/src/lib/site.ts` owns base-path URLs and the shared theme persistence contract.
- `docs/site/src/pages/[...slug].astro` statically renders every documentation route.
- `docs/site/src/pages/api/search.json.ts` exports the browser search index at an explicit JSON URL that works in dev and on GitHub Pages.
- `docs/site/scripts/prepare-content.mjs` remains the canonical policy-copy boundary.
- The landing page and Fumadocs shell share the `hikyo-theme` local-storage key.
- Fumadocs is pinned to `16.14.2`; `takumi-js` is pinned to `2.5.11` so dependency installation passes the repository minimum-release-age policy without exceptions.

## Verification

- `./scripts/ci/verify-docs.sh`
- Browser: 1280x800 and 390x844.
- Browser flows: docs navigation, static search, light-theme persistence.
- Browser console: zero errors and zero warnings after the final search-route fix.
- Mobile document width: 390px viewport and 390px scroll width.
