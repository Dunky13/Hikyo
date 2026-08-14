# Handoff: #45 audit core

Issue: https://github.com/Hikyo-Org/hikyo/issues/45 (parent #41). Spec:
`docs/adr/audit-model.md` on `wayfinder-docs` (incl. the scim/scanning/
multi-instance amendment banners — all out of this ticket's scope), plus
mvp-boundary rows A4 and A6.

## What exists

- `internal/audit` — the event vocabulary, a leaf package (imports domain
  only):
  - Envelope (`Event`) with the ADR's fields; **deliberately no scope-chain
    field** — the chain is passed beside the event by the trusted layer that
    binds it (proof chain in the store, authorize()'s own resolution in the
    denial writer), so no tenant-typed value travels a store-method
    parameter and analyzer 1 stays intact.
  - Closed `category.action` registry (`Registry`): per-type payload schema
    (closed field set, kinds incl. `KindFreeText`), schema version,
    retention class (`access`/`security`), licensed outcomes, permitted
    trails. `Validate` refuses unregistered types, unlicensed outcomes,
    schema violations and unsanitized free text; a refusal fails the
    emitting operation (fail-closed).
  - Free-text hygiene: `SanitizeFreeText` (UTF-8 sanitize, control-char
    strip, 512-byte bound — ops spec owns the concrete value — and the
    active `hik_<version>_<type>_<body>` token-grammar redaction filter, which
    also redacts invalid legacy `ew_` artifacts, fixture-tested incl.
    embedded-in-noise). The write boundary re-checks
    and refuses rather than silently re-cleaning.
  - `Row`/`BuildRow`: the single envelope→column mapping, shared by both
    writers so they cannot drift. Fixed-width microsecond UTC text
    timestamps on sqlite (lexicographic order == time order, so range
    predicates work); timestamptz on postgres. Since #84, the postgres
    BEFORE INSERT trigger acquires the export writer gate and then stamps
    `recorded_at` with `clock_timestamp()`, rather than trusting an application
    instance clock.
  - `Context`/`WithContext`/`FromContext`: per-request wire metadata
    (source IP, user agent, origin), sanitized at capture. Absent context =
    `origin: system`, structural absence. **The HTTP/CLI layers (#47/#48)
    inherit the obligation to attach it.**
- Migrations `00004` (both engines): `audit_tenant_events` (org-owned,
  `org_id` chain conjunct, nullable `project_id`/`env_id` refinements with
  a scope-class CHECK) and `audit_instance_events`. `seq` INTEGER PRIMARY
  KEY AUTOINCREMENT / BIGSERIAL; `id` (UUIDv7 `evt_`) unique. **No foreign
  keys** — the composite-FK rule's single declared exception (amendment
  part 5): an audit event must outlive its subject.
- Queries (`audit.sql`, both engines): 2 INSERTs + paged SELECTs (org/
  project/env refinement + instance) — INSERT and SELECT only, nothing
  else. Interactive query order remains `seq`; exports use the database-
  assigned `commit_seq` cursor on postgres and equivalent `seq` order on
  sqlite. Both retain `recorded_at` range conjuncts and the public `seq`
  lower bound.
- `internal/store/repos_audit.go` — proof-gated `AuditRepo`/`AuditReader`
  (insert tenant/instance, page tenant/instance). Tenant chains bound
  exclusively from the verified proof; the page depth follows the proof's
  chain (org proof reads the whole org, deeper proofs their refinement).
  Actor class resolved server-side from `principals.kind` when the emitter
  leaves it empty.
- **The denial writer** (audit-model amendment part 4): `authorize()`'s
  fail paths capture the denial (`internal/authz/denial.go`) — resolvable
  → tenant trail with the truthful resolved chain; unresolvable → instance
  trail with the addressed ids as bounded/sanitized caller-asserted claims;
  formula recorded **by name, never missing-grant enumeration**. The
  transaction package rolls the attempt back, then flushes captured denials
  through `authn.WriteDenial` — the enumerated resolution surface's SINGLE
  write path — in a dedicated retried transaction, **before `tx.Write`/
  `tx.Read` returns** (denial durable before the error response). A flush
  failure returns a loud error that deliberately does NOT wrap
  `ErrNotFound`/`ErrUnauthorized` — keeping the sentinel in the chain would
  let the response layer render the uniform denial without its record.
  Retryable attempt errors skip the flush (the retry re-captures).
- `internal/service/audit.go` — the trail read surface:
  - `Query`/`InstanceQuery`: one write transaction — authorize, materialize
    the bounded page, insert the `audit.query` event (normalized filters +
    row count), commit — durable before the response by construction.
  - `Export`/`InstanceExport` (JSONL): `audit.export_started` (outcome
    `intent`) durable before the first byte; every page in its own
    `tx.Read` under a **freshly authorized proof**; only committed page
    data emitted; terminal `audit.export_completed` (success / failure with
    cause / disconnected) correlated by the started event's id.
- Operations: `audit-read` capability; 6 tenant rows (`audit.query-*` /
  `audit.export-*` at org/project/env — the registry pins one depth per
  row, so depths are rows, not a registry mechanism change) + 2 instance
  rows, formula `audit-read` at the addressed depth. Demonstration
  mutations now emit scaffolding `settings.*` events in-transaction;
  `environment.read` is the one `audited: none` operation.
- Postgres durability boot refusal: `store.Open` verifies `fsync=on` and
  `synchronous_commit=on` (`SHOW`, injectable querier seam for the fsync
  leg) and refuses otherwise; `SET synchronous_commit` is lint-banned in
  `internal/store` (statement form, so prose naming it doesn't trip).
- A6 redaction: `crypto.Keyring`/`ProjectSealer`/`InstanceSealer` (and the
  unexported `keyHandle`/`dekEntry`) embed a redactor implementing the full
  surface — `String`/`GoString` (what fmt consults for `%v`/`%s`/`%#v`),
  `LogValue`, `MarshalText`, `MarshalJSON` — all returning
  `[REDACTED:hikyo-key-material]`. Coverage test plants a secret and
  exercises every surface. Two new analyzers (`internal/lint`):
  `CheckRedactionSurfaces`/`CheckSensitiveFormatting` (no fmt/json/log/slog
  call takes a sensitive-typed argument outside `internal/crypto`; no
  log/slog call takes audit-content types anywhere — the ops-log mirror
  ban) and `CheckAuditAppendOnly` (INSERT/SELECT only on audit tables,
  empty licensed-deleter allowlist, `SET synchronous_commit` ban), each
  with negative fixtures.
- Analyzer 2 extension: WHERE conjuncts may use `<,<=,>,>=` on **non-chain**
  columns (cursor + time range); chain columns still require `=`, enforced
  with a new refusal case.

## Invariant → test map (audit-model ADR § CI invariants)

| # | Invariant | Test |
|---|---|---|
| 1 | Registry closure (runtime fail-closed + linkage + live emitters) | `audit.TestValidate*`, `isolation.TestInvariantAuditRegistryClosure`, `isolation.TestAuditCore*/every_registered_type_is_actually_emitted` |
| 2 | Completeness vs the total probe classification, default-deny `audited: none` | `isolation.TestInvariantAuditCompleteness` (+ pinned `testdata/audited_exemptions.json`) |
| 3 | Append-only, empty pinned deleter allowlist | `lint.TestAuditAppendOnly*`, `isolation.TestInvariantAuditAppendOnly` |
| 4 | No plaintext: schema-field ban + `hik_` filter round-trip + dump-grep over both trails | `audit.TestRegistryForbiddenPayloadContent`, `audit.TestRedactTokens`, `audit.TestSanitizeFreeText`, `isolation.TestAuditCore*/no_token_material_in_trails` |
| 5 | Cardinality (structural half: no counter/aggregate columns, pinned column set) | `isolation.TestInvariantAuditNoAggregates` — fetch-path halves arrive with #49+ |
| 6 | Denial durability + siting + single writer | `isolation.TestAuditCore*/denial_*` (both engines), `denial_durability_under_induced_commit_failure`, boundary test (authn importers), and `lint.TestDenialWriterIsSoleWriter` — an analyzer refusing any mutating generated query call outside `WriteDenial` inside the resolution surface |
| 7 | Durability settings | `store.TestVerifyPGDurability` (seam), `isolation.TestPostgresDurabilityBootRefusal` (real `ALTER DATABASE`), sqlite pragmas #42's |
| 8 | Redaction surfaces + lint bans | `crypto.TestRedactionSurfacesAgainstPlantedSecret`, `lint.TestRedaction*`, `lint.TestSensitiveFormatting*`, `isolation.TestInvariantAuditRedaction` |
| 9 | Retention units (envelope+per-key atomic) | vacuous — no fetch envelopes exist; arrives with the fetch path |
| 10 | Class totality | `audit.TestRegistryWellFormed` |
| 11 | Export pair + paging + revocation stop + gap-free postgres commit order | `isolation.TestAuditCore*/export_*` (both engines), plus `isolation.TestPostgresAuditExportCommitOrder` (lower `seq` commits after first page and is emitted on the next) |
| 12 | Outcome restriction, no payload shadow | `audit.TestRegistryWellFormed`, `TestRegistryNoOutcomeShadow`, `TestValidateRefusals` |
| 13 | FK exception named, not counted | `isolation.TestInvariantAuditFKException` |

A4 E2E criteria: denial durability under induced commit failure (audit
table renamed mid-test → denied probe answers a loud refusal, never the
uniform denial), export page-boundary revocation stop (grant deleted via a
first-write hook), INTENT/OUTCOME pairing incl. disconnect — all on sqlite
and postgres. A6 CI criteria: formatting-surface coverage vs a planted
secret, free-text filter fixtures.

## Deviations from the ADR letter, stated

- **Export completed-on-revocation is NOT written.** The ADR wants a
  terminal `export_completed(failure)` on mid-export revocation, but the
  revoked principal can no longer mint the proof the insert requires, and
  the ADR's own amendment part 4 pins the denial writer as the single
  proof-free write path — fabricating a fifth system site or a second
  authn writer would violate the stronger invariant. Implementation: the
  stream stops at the page boundary, the revoked page's `grant.denied`
  event records the cause, and the started-without-completed record is the
  ADR's own "visible reconciliation case" (`service.ErrExportUnpaired`).
  Success, page-failure and sink-disconnect paths all get their terminal
  event. If review wants the letter, it needs an ADR amendment naming the
  authority that writes it.
- **Page/pagination order is `seq`, not `(recorded_at, seq)`.** The keyset
  cursor for the ADR's display order needs a row-value or OR-composed
  predicate — both shapes analyzer 2 rejects as unprovable. `seq` is
  allocation-ordered (identical to commit order on sqlite; honestly not a
  commit-order total on postgres, per the ADR's own statement). Display
  ordering by `(recorded_at, seq)` stays the audit view's job (#29).
- **`audited: none` exemption fixture** (`audited_exemptions.json`,
  name-pinned, reason-carrying) covers WIRE ENTRIES ONLY:
  `healthz`/`readyz`/`cli:version`/`cli:server`/`cli:migrate` — the ADR's
  default-deny rule refuses `audited: none` to unauthenticated/system
  classes but declares no event types for health probes, a local version
  print, or process entry points whose auditable acts (boot keyring reads,
  migration DDL) run below the operation surface. The operations map is
  EMPTY: `org.get`/`org.list` now emit `settings.org_read` (access class)
  rather than riding an exemption, per cross-model R1. `ClassStub` verbs are
  excluded by their existing contract.
- **The registry does NOT yet contain the ADR's full v1 catalogue**, and
  this slice does not claim otherwise: the ADR's completeness rule
  ("the registry MUST contain every event an upstream locked ADR requires")
  is satisfied per-slice, because the events of unbuilt surfaces (auth,
  fetch, crypto rotation, adapters) cannot be emitted by code that does not
  exist. What IS enforced here is the machine-checkable half — the
  completeness invariant against the total probe-classification registry,
  which refuses silence for every operation that exists today. Registered
  types are additionally proven to have live emitters (E2E
  `every_registered_type_is_actually_emitted`); the catalogue grows with
  each surface's ticket, and the ADR's row list is the standing obligation
  on those tickets, not a claim of present compliance.
- **Filters**: time range + seq cursor + limit only. Category/type/scope/
  actor filters are the API surface's delegated mechanism (#25) — each is a
  further provable conjunct on the same queries.
- **Retention pruning job is not built** (scheduler + ops-spec defaults
  ticket); the append-only allowlist ships EMPTY — strictly tighter than
  the ADR — and loosens only when pruning/org-deletion land their
  content-pinned queries. Retention classes are registry data already.
- **`actor.credential_id` is always empty** — no authentication exists
  until #16; the envelope column is ready.
- **Instance-trail query events**: `audit.query`/`export_*` events for
  instance-trail reads land in the instance trail (self-contained), tenant
  reads in the tenant trail.
- **Offline-reconciled records**: envelope carries `occurred_asserted`,
  `origin: offline-reconciled`; no reconciliation path exists yet (#18's
  compose ticket).

## Accepted residuals, stated

- **Postgres export-order residual resolved by #84.** Migration `00011`
  adds database-owned `commit_seq` metadata. A deferred per-row trigger
  takes the global audit-appender transaction advisory lock and assigns
  `commit_seq` immediately before commit; the lock remains held through commit. Export
  pages advance this commit-order cursor while the emitted/public `seq`
  remains unchanged. A lower `seq` that commits after an earlier page is
  therefore later in export order and cannot fall behind the cursor.
  Existing rows are backfilled in their already-settled `seq` order.

  An export without a caller-supplied `To` captures `clock_timestamp()`
  before writing `audit.export_started` and holds that fixed upper bound for
    every page. A transaction registered and timestamped before the cutoff
    remains eligible when it commits later. Audit INSERTs acquire a shared
    in-flight advisory lock before the database stamps `recorded_at`;
  before accepting a final short page, the exporter queues the exclusive side,
  waits for every pre-cutoff writer, then rereads. Writes inserted after the
  cutoff cannot turn the export into an endless chase or make it export its own
  audit records.

  This is the serialization point anticipated by the ADR's future
  single-writer appender. It uses built-in transaction advisory locks and
  requires no non-default postgres server setting, so no new boot prerequisite
  exists. The 30 s application-clock settle ceiling and its clock-skew
  residual were replaced by the zero-lag server-clock snapshot. sqlite is
  unchanged: its single write connection already makes allocation order
  commit order and durably serializes `export_started` before paging. #25 must
  treat `AfterSeq` as a selection floor, not derive a resume cursor from the
  last emitted row; resumability would require an opaque commit-order cursor.

- **Denial-path timing.** A resolvable denial evaluates grants and writes to
  the tenant trail; an unresolvable one skips the grant lookup and writes to
  the instance trail. The work differs, so repeated latency measurement can
  in principle distinguish "exists but forbidden" from "does not exist"
  despite the byte-identical response (cross-model R1 finding 5). This is
  the tenant-isolation ADR's already-stated residual — application-layer
  uniformity is the claim, engine-internal microtiming is not — and the
  grant evaluation is inherent: a resolvable denial cannot be decided
  without it. The mitigation is #8's per-principal rate limiting, which
  bounds how many samples a prober can take. Recorded here rather than
  papered over.
- **Emitter-supplied actor id.** Until authentication lands (#16), the
  service passes the acting principal id; the store resolves its CLASS from
  `principals.kind` and the event type is bound to the minting operation, so
  a proof cannot forge event meaning. Under a principal-backed proof an
  emitter may not assert ANY actor class — `system`/`break-glass`/
  `unauthenticated` are accepted only under a system proof or on the denial
  writer's own no-principal path (cross-model R2), so a principal's act
  cannot be recorded as a system or anonymous one. Binding the id itself to
  an authenticated session is #16's.

## Pickup notes

- Adding an event type: register in `audit.Registry` (schema, version,
  retention class, outcomes, trails). Unregistered emits fail at runtime
  (fail-closed) and unregistered *operation* mappings fail
  `TestInvariantAuditRegistryClosure`.
- Adding an operation: the completeness invariant now refuses silence —
  map `events`, declare `auditedNone` (only tenant + bare-read +
  non-mutating qualifies), or pin an exemption with its reason.
- Emitting a domain event: build via `service.domainEvent` (or inline),
  insert through `r.Audit().InsertTenant/InsertInstance` inside the same
  transaction; the proof must carry the audit-insert store op (registry).
- Re-pin on change: `operation_formulas.json` (new ops),
  `annotated_queries.json` (authn gained `GetPrincipalKind`),
  `audited_exemptions.json`, and the pinned column sets in
  `TestInvariantAuditNoAggregates`.
- Postgres locally: point `HIKYO_TEST_POSTGRES_DSN` at a scratch database
  (needs CREATE DATABASE); the durability E2E derives `<name>_durability`
  and ALTERs/RESETs its `synchronous_commit`.
- The `readOnlyStoreOps` pin in `authz/registry.go` is the
  mutates-nothing half of the `audited: none` permit rule — review
  additions like formula pins.
