# Handoff — #53 Retention & GC

Implements issue #53 (parent #41): payload retention policy, GC sweep,
collected-revision refusals, and the retention audit trail, per ops-spec § 2
and § 10 and the revision-model ADR's Retention section.

## What landed

- **Migration 00023** (both dialects): org retention columns
  (`retention_mode` keep-if-either|unlimited, `retention_age_seconds`
  default 90 d, `retention_revision_count` default 10), nullable project
  override columns (both-or-neither CHECK), and `snapshots.collected_at` +
  `collected_policy` bookkeeping beside #52's `payload_present`. One CHECK
  binds all three as the payload-presence fact; the stamped policy is what the
  named refusal reports forever. GC uses #52's `revision_pins` substrate and
  the `retention_runtime` singleton (row is
  upserted at first prune, never migration-seeded — a seeded row breaks the
  restore drill's empty-target check).
- **Service** `internal/service/retention.go`: org/project policy CRUD with
  both-dimension cap validation (project ≤ org, unlimited org-only, org
  tighten refused while a project override exceeds it — all named
  refusals), and `Sweep()` — chunked (100/batch), each chunk its own
  transaction, mark-then-delete with a live-pin re-check at mark time.
- **Scheduler** `internal/app/scheduler.go`: startup catch-up + hourly
  runs, 10-min per-job deadline, `last_prune_success` persisted with a
  > 24 h staleness warning. Payload GC is the first and only job; audit
  classes / render generations / plans-tokens GC are future jobs here.
- **Pruner health surfaces** (ops-spec § 10 "exposed"): `GET
  /api/v1/instance/retention-health` (`instance-config@instance`, audited
  read), a `hikyo doctor` row (ok / warn stale > 24 h / warn never), a
  stdlib Prometheus text `/metrics` endpoint (unauthenticated like
  `/healthz`; `hikyo_last_prune_success_timestamp_seconds`,
  `hikyo_prune_stale`; no identity labels), and a persistent Shell banner
  in the web UI when stale (hourly poll; 403/404 hides it silently).
- **Fail-loud collected fetch**: `domain.CollectedRevisionError` (revision +
  stamped policy) from revision show/export, pinned delivery, pin set, and
  rollback. `Snapshot` is the sole Go state representation; `Entries` keeps a
  post-read re-check covering the Postgres READ COMMITTED race.
- **Authz**: new `SiteScheduler` system-proof site (store surface pinned by
  isolation invariant 11); four `retention.*` operations wired to
  `/orgs/{org}/retention` and `/orgs/{org}/projects/{project}/retention`.
- **Audit**: `settings.org_retention_changed`,
  `settings.project_retention_changed` (security class, tenant trail);
  `retention.payload_gc` per collected snapshot, inserted in the same
  transaction as the mark + delete under a per-row scoped scheduler
  authority (tenant trail); `retention.prune_run` per sweep with counts,
  success or failure (instance trail).
- **CLI**: `hikyo org retention get|set`, `hikyo project retention get|set`.
- **Wire contract**: every operation that can surface
  `CollectedRevisionError` declares `409 Conflict` (revision show, values
  export, delivery fetch, pin set, rollback).
- **sqlite time comparisons** on `revision_pins.expires_at` go through
  `julianday()` on both sides — the store writes RFC3339Nano, which trims
  trailing zeros, so lexical TEXT comparison is wrong at sub-second
  boundaries (`TestRetentionPinSubsecondBoundary*`).
- **C6 E2E**, both engines: `retention_gc_e2e_test.go` (service seam +
  direct DB scan proof) and `retention_cli_e2e_test.go` (normative seam:
  real `app.Boot` server + real CLI, retention set via CLI, seeded corpus,
  server restart so the startup catch-up run is the real sweep, 409 named
  refusal on the wire, doctor health, all audit events).

## Deliberate scope lines

- Pin lifecycle and substrate (`revision_pins`, create/renew/release API,
  quota 100, expiry warnings, reveal-history gating) are **#52**. GC protects
  only rows with `expires_at > now`; expired pins remain for delivery routing.
- **Pin/GC race verdict: closed by construction.** PostgreSQL `tx.Write` uses
  `SERIALIZABLE`, and its retry loop retries SQLSTATE `40001` and `40P01`.
  A pin transaction that read the old presence bit cannot commit across GC's
  snapshot update; one transaction retries and observes the winning state.
- Backup retention (§ 2) and storage high-water bounds (§ 8) are separate
  tickets.

## Verification trail

Full `go test ./...` green on sqlite + postgres
(`HIKYO_TEST_POSTGRES_DSN`), `go vet`, sqlc drift-free, ui-tagged server
tests, TS client verify (Node 24). Two-axis review (standards + spec):
CLEAN after one fix round (dead query removed, yield comment corrected,
param rename, guard extraction, policy data clump). PR #135 review threads
(sqlite expiry compare, 409 contract, pruner-health surfaces, normative
E2E seam, GC audit events) all fixed; web Vitest + Playwright + typecheck
green.
