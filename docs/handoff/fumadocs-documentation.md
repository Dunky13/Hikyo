# Handoff: Fumadocs documentation

## Outcome

The GitHub Pages site serves the custom landing page at `https://hikyo.app/`
and Fumadocs at `/docs/`, with policy and release-trust routes at the same
domain root. Astro remains the static-site host; Fumadocs UI runs as a React
island and the search index is generated at build time.

## Routes

`docs/site/src/content/docs/docs/meta.json` is the route manifest. It groups
23 pages into Get started, Installation, Concepts, Guides, Identity providers,
Operations, and Reference sections.

- Get started: overview, quick start, and first project.
- Installation: installation choices and source build.
- Concepts: core concepts, architecture, hierarchy, values, and access.
- Guides: contexts, values, machine identities, and account security.
- Identity providers: SAML and SCIM.
- Operations: self-hosting, configuration, backup/restore, upgrades, and troubleshooting.
- Reference: CLI command families and the HTTP API contract.

Existing root policy routes and `/release/signing/` remain stable.

## Implementation notes

- `docs/site/src/lib/source.ts` adapts Astro content collections to the Fumadocs page tree.
- `docs/site/src/lib/site.ts` owns site URLs and the shared theme persistence contract.
- `docs/site/src/pages/[...slug].astro` statically renders every documentation route.
- `docs/site/src/pages/api/search.json.ts` exports the browser search index at an explicit JSON URL that works in dev and on GitHub Pages.
- `docs/site/scripts/prepare-content.mjs` remains the canonical policy-copy boundary.
- `scripts/ci/check-oss-policy.sh` derives required docs routes from `meta.json`; policy-route and load-bearing copy assertions remain explicit.
- The landing page and Fumadocs shell share the `hikyo-theme` local-storage key.
- Fumadocs is pinned to `16.14.2`; `takumi-js` is pinned to `2.5.11` so dependency installation passes the repository minimum-release-age policy without exceptions.

## Verification

- `./scripts/ci/verify-docs.sh`
- Browser: 1280x800 and 390x844.
- Browser flows: docs navigation, static search, light-theme persistence.
- Browser console: zero errors and zero warnings after the final search-route fix.
- Mobile document width: 390px viewport and 390px scroll width.
- Expanded manual: 23 internal docs routes resolve and all guide titles appear in search.
- Fumadocs integrity: deleting a page named by `meta.json` fails the OSS policy gate.
- Custom-domain regression: generated HTML rejects stale `/hikyo/` asset and navigation URLs.
- Post-deploy gate: landing and docs CSS/JavaScript must resolve from `hikyo.app` with expected content types.
