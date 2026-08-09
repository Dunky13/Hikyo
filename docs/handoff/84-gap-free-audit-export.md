# Handoff: #84 gap-free postgres audit export ordering

Issue: https://github.com/Dunky13/wenv/issues/84 (parent #41; required by #25
before an export route ships).

## Decision

Postgres audit rows retain public `seq` allocation order and gain internal
`commit_seq` export order. Migration `00010_audit_export_order.sql` installs a
deferred constraint trigger on each trail. During commit, the trigger takes the
global audit-appender transaction advisory lock, assigns the next `commit_seq`, and holds
the lock until commit finishes. Rollbacks may leave sequence-number gaps; they
cannot reorder visible commits.

This is the audit ADR's single-writer serialization point without a background
worker, non-default postgres setting, or application clock. One global lock
also avoids opposite-order deadlocks when one transaction carries events for
both trails. sqlite keeps using
`seq`: its single write connection already serializes allocation and commit.

## Candidate evaluation

1. **Server `recorded_at` + oldest active transaction:** server time is adopted
   for the fixed export cutoff, but `pg_stat_activity.xact_start` is too broad
   (transactions that never touch audit delay every export) and visibility is
   role/configuration-sensitive. It still needs a reliable way to identify the
   audit-writing subset.
2. **`track_commit_timestamp`:** directly exposes commit time, but requires a
   non-default restart-time server setting, boot refusal, and timestamp-retention
   operations. Timestamps can collide, so `seq` remains a tie-breaker. This is
   heavier operational coupling than #84 needs.
3. **Commit-order appender + in-flight barrier (chosen):** uses built-in advisory
   locks only. Writers share an in-flight gate from INSERT through commit; the
   deferred appender serializes `commit_seq` assignment; the exporter takes the
   exclusive gate before its final reread. Cost: one shared lock per audit-
   writing transaction and a brief serialized commit-finalization step. Benefit:
   exact ordering, no server prerequisite, and the serialization point a future
   hash chain already needs.

## Runtime shape

- `AuditEvent.Seq` remains the JSONL/public value.
- `AuditEvent.CommitSeq` is the internal export cursor and is never serialized.
- Postgres `commit_seq` is NULL only inside its inserting transaction because
  postgres cannot defer a NOT NULL/CHECK constraint. The deferred constraint
  trigger is the commit-time non-null invariant: it rejects caller-supplied
  positions, assigns the database position, and aborts if finalization misses
  the row. Read conversion also fails loud on any committed NULL.
- Interactive query pages stay allocation-ordered by `seq`.
- Export pages retain the caller's `AfterSeq` lower bound, then page by
  `commit_seq` on postgres. `AfterSeq` is a selection floor, not a resumable
  export cursor: #25 must not derive a continuation token from the last
  emitted public `seq`. A future resumable route needs an opaque cursor that
  carries the internal commit-order position.
- The Postgres BEFORE INSERT trigger first acquires the shared writer gate,
  then stamps `recorded_at` with `clock_timestamp()`. Eligibility therefore
  cannot predate the writer's registration at the export barrier.
- An unbounded export captures that same server clock before its INTENT event
  and holds it as a fixed `To`, so pre-cutoff in-flight rows remain eligible
  while post-cutoff writes cannot create an endless chase.
- Audit INSERTs hold a shared in-flight lock. Before a short page can terminate
  the export, the exporter waits on the exclusive side and rereads, so a row
  cannot commit between the final page and `export_completed` unnoticed.
- sqlite needs no equivalent final barrier: the fixed cutoff is captured before
  the durable `export_started` write, and its sole write connection settles
  every writer stamped at or before that cutoff before paging begins. Writers
  admitted afterward are stamped after the cutoff and are outside the export.
- The former 30 s settle ceiling is removed; the fixed snapshot has zero lag
  and no application-clock skew.

Postgres transaction advisory locks are built in and need no server setting,
so #84 adds no boot-verification requirement beyond the existing `fsync=on`
and `synchronous_commit=on` checks.

Migration `00010` must remain transactional. The supported `wenv migrate` and
auto-migrate paths use goose's transactional default, so no writer can commit
between the backfill and trigger installation. Running the statements manually
or marking this migration `NO TRANSACTION` is unsupported: either can strand a
row with NULL `commit_seq`.

## Regression proof

`isolation.TestPostgresAuditExportCommitOrder` opens a transaction that
allocates the lower `seq`, commits a higher `seq`, exports the first one-row
page, then commits the lower `seq`. The second page must emit that later commit.
The pre-#84 `seq > cursor` implementation exports one row; the commit-order
implementation exports both in visible commit order.

## Validation

- Focused real-postgres regression:
  `go test ./internal/isolation -run '^TestPostgresAuditExportCommitOrder$' -count=1`
- Audit suite on sqlite + postgres:
  `go test ./internal/isolation -run '^(TestAuditCoreSQLite|TestAuditCorePostgres|TestPostgresAuditExportCommitOrder)$' -count=1`
- Full suite: `go test ./...`
