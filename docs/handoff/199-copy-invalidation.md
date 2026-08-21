# #199 — Copy destination cache invalidation

Status: implemented in PR #235.

## Contract

A successful value or matrix-config copy republishes every destination
environment. The client therefore treats the server's destination write set as
the cache invalidation boundary:

- invalidate destination values and reveal-window state;
- invalidate destination revision lists, revision details, and pins;
- invalidate destination matrix signals and pending drafts;
- retain source reveal-window invalidation on settlement, including refusal;
- never invalidate a shorter org-, project-, or family-wide prefix.

Both copy hooks use the unique union of destinations named by the request and
echoed by the successful response. This keeps the client correct if the server
returns a destination that was not represented in the caller's local state.

## Module boundary

`web/src/api/keys.ts` owns the environment and matrix reference types, all
affected query-key builders, and `invalidateAfterCopy`. It imports only the
React Query client type, so `values.ts`, `history.ts`, and `matrix.ts` can share
the invalidation contract without an application-module cycle. Existing key
exports remain available from their previous modules.

## Evidence

- `web/src/api/values.test.ts` primes a real `QueryClient` with two
  destinations, a source environment, and an unrelated project. It proves all
  destination keys become invalid and the source and unrelated project remain
  untouched by destination invalidation.
- `web/e2e/flows/matrix.spec.ts` keeps the production destination mounted with
  its pre-copy value, copies development into it, and proves the mounted cell
  renders the copied value without navigation or reload.

## Validation

Run from the repository root with the pinned Node version:

```sh
fnm exec --using 24 -- corepack pnpm --dir web run typecheck
fnm exec --using 24 -- corepack pnpm --dir web run test
fnm exec --using 24 -- corepack pnpm --dir web run build
NODE_OPTIONS=--dns-result-order=ipv4first \
  fnm exec --using 24 -- corepack pnpm --dir web exec playwright test --project=desktop
NODE_OPTIONS=--dns-result-order=ipv4first \
  fnm exec --using 24 -- corepack pnpm --dir web exec playwright test --project=mobile
```
