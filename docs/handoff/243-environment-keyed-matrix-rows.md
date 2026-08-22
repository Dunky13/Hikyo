# Issue #243: environment-keyed matrix rows

## Contract

`useMatrixProject` returns one ordered `environmentRows` collection. Each row
embeds its `environmentId`, environment metadata, and the values, signals,
settings, and pending-draft query states for that same ID. Server environment
order remains the explicit display order; independently updating query families
are joined by ID and duplicate or missing identities fail loudly.

The route and row editor consume keyed rows. They no longer correlate a
separate environment list with positional query arrays. The existing project
owner still issues three project queries plus four query families per
environment; no per-row hook or mutation owner was added.

## What changed

- Added the keyed row DTO and ID-based query-family assembler at the matrix API
  boundary.
- Migrated matrix rendering, pending/revision/protection derivation, history
  props, and row-editor props to explicit environment IDs.
- Added reorder, removal, partial-loading, duplicate-ID, and missing-ID unit
  coverage.
- Added a real browser reorder flow that verifies row interaction identity and
  the unchanged 11-resource read shape for two environments.

## Generated outputs

None.

## Validation

- `./scripts/ci/build-spa.sh --verify`: typecheck, 254 Vitest tests, and Vite
  production build passed.
- Isolated desktop matrix flow: 7 passed.
- Isolated mobile matrix flow: 7 passed.
- `git diff --check`: passed.
- Standards and issue-spec review axes: CLEAN in round 3 after cache-contract
  and observer-count findings were fixed.
