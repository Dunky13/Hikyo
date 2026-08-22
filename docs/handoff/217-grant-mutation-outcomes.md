# #217 — Closed grant mutation outcomes

Status: implemented on the PR #274 stack before the #79 API freeze.

## Contract

Every grant mutation now returns one required `outcome` value alongside
`grant_id` and `capability`:

- `created`: a new grant row and origin were written;
- `origin_added`: an origin joined an existing grant row;
- `unchanged`: the same origin already held the existing row.

The former `created` and `origin_added` booleans are removed. This makes the
invalid `created: true, origin_added: false` combination unrepresentable in
the OpenAPI contract and generated TypeScript client. Go uses a sealed value
whose representation is private; only the three constructors produce valid
values, while the zero value and unknown JSON strings fail loudly. Every
service, server, operator, and CLI branch handles the three outcomes
exhaustively.

## Compatibility and migration

This is an intentional pre-1.0 response-shape break. Issue #79 remains open,
so the API is not frozen and no compatibility decoding window is required.
Servers, the Go model, the generated TypeScript/Zod client, CLI, and SPA land
together. External `0.x` consumers must regenerate from `api/openapi.yaml` and
replace Boolean-combination checks with an exhaustive `outcome` branch.

No database migration or persisted-data rewrite is needed. Grant rows, grant
origins, audit event types, template counters, session invalidation, and the
break-glass `grant_created` audit fact keep their existing semantics.

## Rendering

The network CLI prints `created`, `origin added`, or `unchanged`; its decoder
refuses an unknown server value. The local break-glass command does the same.
SPA member, instance-admin, and machine-access success notices name each
returned outcome. Partial-failure notices retain those outcomes too, so an
idempotent repeat is never described as a newly created grant.

## Validation

- service outcome and audit regressions on SQLite and PostgreSQL;
- OpenAPI schema and server conversion tests;
- generated TypeScript closed-enum contract test;
- CLI and SPA rendering tests;
- generated-artifact check, Go suite, TypeScript typechecks/tests, lint, and
  production web build.
