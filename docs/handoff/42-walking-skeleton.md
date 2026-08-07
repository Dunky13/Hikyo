# Handoff: #42 walking skeleton

Issue: https://github.com/Dunky13/wenv/issues/42 (parent #41). Spec:
`docs/adr/system-architecture.md` on `wayfinder-docs` (incl. the 2026-08-07
amendment banner: Go 1.26 toolchain, OpenAPI 3.1 — the latter is out of this
ticket's scope).

## What exists

One Go module (`github.com/Dunky13/wenv`, toolchain go1.26.2), one multicall
binary:

- `wenv server [--dev] [--listen] [--auto-migrate=BOOL]` — chi router with
  `/healthz` (process alive) and `/readyz` (datastore reachable; migrations
  are current by construction at serve time). `--dev` boots zero-config
  sqlite (`wenv-dev.db` in cwd); production start without `WENV_DB` refuses.
- `wenv migrate` — explicit migration application, DDL only.
- Client verbs (`login run render sync adopt doctor definitions import`) —
  stubs, exit 2.

Layout and the rules it carries:

- `internal/config` — strict fail-fast parsing. `WENV_DB` is `sqlite:PATH`
  or `postgres://…`; unknown `WENV_*` keys warn; remote postgres without
  `sslmode=verify-full|verify-ca` refuses (threat-model TLS boundary).
- `internal/store` — per-aggregate repository interfaces (`Org` is the
  demonstration aggregate) over sqlc-generated code (`sqlitegen`, `pggen`,
  committed; regen via `go tool sqlc generate`). Canonical cross-engine
  semantics live here: UTC timestamps truncated to µs (RFC 3339 text on
  sqlite / timestamptz on pg), bool-as-int on sqlite, JSON-as-text validated
  both directions. SQLite pragma policy (`foreign_keys`, WAL,
  `synchronous=FULL`, `busy_timeout=5000`) is in the DSN and re-verified at
  `store.Open` — mismatch refuses boot. Single write connection
  (`MaxOpenConns(1)`, `_txlock=immediate`) + separate read pool.
- `internal/store/tx` — the transaction boundary: pg SERIALIZABLE retrying
  SQLSTATE 40001/40P01, sqlite BEGIN IMMEDIATE retrying SQLITE_BUSY/LOCKED;
  3 attempts, jittered 10/50/250 ms backoff, 15 s overall deadline
  (ops-spec values). Retried unit is the whole closure; effects after commit.
- `internal/store/migrate` — goose (library mode) on the embedded per-dialect
  dirs; pg session advisory lock, sqlite flock (`<db>.lock`) held for the
  whole run; roll-forward only; any failure refuses to serve.
- `internal/service` — the only production importer of store;
  `internal/server` (HTTP) reaches data through it.
- `internal/boundary` — import-boundary test: exact allowlist for store
  importers + forbidden edges (server→store, store→service, cmd→store).
- `internal/conformance` — one scenario corpus (roundtrip semantics, list
  order, rollback, unique violation, invalid JSON, not-found, 8-writer
  concurrency) run on sqlite always and on postgres via
  `WENV_TEST_POSTGRES_DSN`. Unset DSN skips locally but **fails when
  `CI=true`** — the postgres leg cannot go vacuously green.

CI (`.github/workflows/ci.yml`): build, vet, sqlc-regen diff gate, full test
run with a postgres:18 service container. Actions pinned by commit SHA.

## Verified empirically

- `wenv server --dev` on a clean dir: creates the db, migrates, `/healthz`
  and `/readyz` both 200.
- `wenv server` without `WENV_DB`: refuses, exit 1, names the fix.
- Fresh db + `--auto-migrate=false`: boot refuses (pending migrations).
- Conformance green on sqlite and on postgres 18 (local container).
- `CI=true` without pg DSN: conformance fails loudly, as designed.

## Deliberate scope cuts (per ticket — not debt)

No OpenAPI/oapi-codegen, no SPA/embed, no auth, no crypto/keyring, no SSE,
no outbox, no TLS listener, no goreleaser/Helm/compose. Each has its own
ticket per the ADR's Binds section. The `Org` aggregate is scaffolding to
make migrations/sqlc/tx/conformance non-vacuous; replace or extend when the
real domain lands.

## Pickup notes

- sqlc: `go tool sqlc generate` (tool dependency in go.mod, no system
  binary). CI fails on stale generated code.
- Postgres locally: any 17/18 with a scratch database; the harness drops
  only `orgs` and `goose_db_version`.
- `/readyz`'s "migrations current" claim rests on fail-closed boot; if a
  live pending-check is ever wanted, put it in `service.System.Ready`.
