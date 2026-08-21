# Handoff: #76 backup / restore drill + headline guarantee (K2, K3)

Issue: https://github.com/Hikyo-Org/Hikyo/issues/76 (parent #41). ADRs on the
`wayfinder-docs` branch: `docs/adr/encryption-model.md` § Backups and exports,
`docs/adr/threat-model.md` § Compromise assumptions / trust boundary 5,
`docs/adr/ops-spec.md` §§ 9, 11, `docs/adr/mvp-boundary.md` rows K2, K3, O1.

## What shipped

- **The age container** — `internal/crypto/backup`, the module's SOLE importer
  of `filippo.io/age` (boundary-tested). Leaf package, imports nothing under
  `internal/`. It owns the contract age does not supply: zero-recipient
  refusal, scrypt-stanza exclusivity at export AND at open (age enforces it
  only on its own `ScryptIdentity` path, so an X25519 identity would otherwise
  open a container whose passphrase half is a second, weaker door), and
  `ExtractTo`, which returns only after the container has authenticated
  through to its final chunk. `GenerateIdentity` mints an escrow identity.
- **Archive contents** — `internal/store/backup.go`. tar (stdlib) inside the
  age container, manifest first. sqlite payload is a `VACUUM INTO` snapshot —
  the engine's own consistent online snapshot, page-exact, goose table
  included. Postgres payload is one `COPY … TO STDOUT` stream per table inside
  `SERIALIZABLE READ ONLY DEFERRABLE`, in an order topologically sorted over
  live `pg_constraint` foreign keys (derived, never curated, so a new
  migration cannot silently fall out of the backup); sequence positions ride
  in the manifest, because COPY moves rows and not the counters behind them.
- **Restore** — `store.RestoreSQLite` / `store.RestorePostgres`, wrapped by
  `internal/store/tx/restore.go` so the credential-epoch bump commits in the
  SAME act as the data it invalidates. Postgres restores with user triggers
  disabled for the load only (the audit tables' `recorded_at` stamp and
  database-owned `commit_seq` are correct for a live append and wrong for a
  replay of history); foreign keys are internal triggers and stay enforced, so
  the manifest's parents-first order is still load-bearing.
- **Restore reconciliation** — migration `00016_restore_reconciliation.sql`
  (both engines): `auth_instance_state.restore_epoch`,
  `auth_instance_state.reactivated_at`, `principals.reconciled_epoch`. The
  gate is a conjunct of `ListGrantsForPrincipal` itself, so authorize() cannot
  forget it and the pinned query count is unchanged. `InsertPrincipal` /
  `InsertMachinePrincipal` stamp new principals as born-reconciled.
- **Operator surface** — `hikyo backup export|keygen`, `hikyo restore
  run|status|reconcile`, host-only verb groups beside `hikyo admin`
  (`cli:backup` / `cli:restore`, ClassSystem, no HTTP route).
- **Automatic pre-migration export** — `internal/app/premigration.go`, wired
  into both entry points that can apply a migration (`hikyo migrate` and
  boot's auto-migrate). Fires only when a migration is actually pending.

## Decisions worth not re-deriving

- **Reconciliation is a host-authority CLI verb, not an HTTP endpoint.** This
  is closer to forced than chosen: a restore leaves every session dead and
  every grant inert, so at the moment reconciliation must happen there is no
  principal in existence who could authenticate, let alone authorize. Same
  bootstrap paradox `hikyo admin grant` already lives in. It writes through
  the resolution surface (`internal/store/authn/restore.go`, two names added
  to `lint.ResolutionSurfaceWriters`), which keeps `SiteRecoveryReconcile`'s
  pinned store-operation set empty, exactly as break-glass does.
- **`restore_epoch` is separate from `credential_epoch`.** Any epoch bump
  advances the second; only a restore advances the first. Folding them would
  lose the fact the grant gate needs. Zero means never restored, which every
  principal's default already satisfies — a fresh instance is not born locked
  out.
- **An archive restores into the same engine, into an EMPTY datastore.**
  Merging a backup into a live instance is how two identity sets become one.
  Cross-engine migration is a different feature with different failure modes.
- **Restore refuses an archive newer than the binary, or below schema 16**
  (`app.MinRestoreSchemaVersion`), by name. Below 15 the archive predates the
  restore state a restore has to write; the operator's fix is "restore it with
  the binary that took it", and the error says so instead of failing deep
  inside the load transaction on a missing column.
- **Export never touches the root key**, and must not start to: the artifact
  is readable only by someone holding BOTH the backup identity and the root
  key, which is the custody separation the threat model requires.
- **Query files stay ASCII.** sqlc's sqlite parser computes statement spans in
  bytes and mis-slices every query after a non-ASCII byte in a comment (a `§`
  silently produced `WHERE id =` with the literal eaten). Cost an hour; do not
  reintroduce em-dashes into `internal/store/queries/**`.
- **The isolation harness's postgres reset is now `DROP SCHEMA public CASCADE`,
  not an enumerated table list.** Found while running this ticket's suite: one
  aborted run left a table the list did not name, and every subsequent run
  cascaded into "cannot drop X because other objects depend on it" / "relation
  Y does not exist" across unrelated tests, from a cause several runs in the
  past. The list was also a maintenance burden every migration had to be
  remembered in. A schema drop cannot have that failure mode, and it took the
  package from ~175 s to ~105 s.

## Evidence map

| Row | Evidence | Where |
|---|---|---|
| K2 | full backup→destroy→restore drill, both engines | `internal/isolation/backup_drill_e2e_test.go` `TestBackupRestoreDrill{SQLite,Postgres}` |
| K2 | truncated backup refused before any state committed | drill subtest `truncated_backup_refused_before_any_state_is_committed` (chunk-boundary and mid-chunk cuts) + `internal/crypto/backup` unit tests |
| K2 | custody separation as two distinct identities | drill subtests `custody_separation_is_two_distinct_identities`, `unbootable_with_the_age_identity_alone` |
| K2 | re-establishment through the credential-establishment authority, and authorization still gated until reconciliation | drill subtest `re_establishment_through_the_credential_authority_works` |
| K2 | no bulk-accept path in the API surface | `TestNoBulkAcceptInTheAPISurface` (signature reflection, CLI refusal, route sweep) |
| K3 | planted-plaintext scan of dump + backup | drill's `assertNoPlaintext` over the raw snapshot and the age artifact |
| K3 | recoverable credential artifacts replayed and refused | drill's `assertDumpMaterialIsUnreplayable` |
| O1 (export) | pre-migration export with recipients / loud skip without | `internal/app/premigration_test.go` |
| CI | the K3 job | `.github/workflows/ci.yml` job `headline-guarantee` (required) |

## Review hardening (cross-model R1, gpt-5.6-sol high)

The adversarial pass found five things; all fixed in this PR:

- **Restore trusts nothing about the archive's epoch bookkeeping.** An archive
  is forgeable by anyone holding the PUBLIC recipient, so the restore's new
  epoch is now `1 + MAX` over the instance row and every epoch-stamped table
  (`MaxKnownCredentialEpoch`), and every `principals.reconciled_epoch` is
  zeroed (`MarkAllPrincipalsUnreconciled`). A forged archive that understates
  the instance epoch while stamping planted credentials ahead, or stamps its
  principals pre-reconciled, lands fully dead.
  `TestRestoreDistrustsArchiveEpochStamps{SQLite,Postgres}` forges all three
  stamps through a real archive. Full cryptographic provenance (signed
  backups) was considered and deliberately not added: backup custody is the
  operator's boundary in the threat model, and with epoch distrust a forged
  archive yields an instance where nothing authenticates or authorizes.
- **A `HasPending` failure no longer skips the export silently** — it warns
  and fails toward taking the backup (`internal/app/app.go`).
- **Same-second exports cannot overwrite each other**: unique staging file
  (`os.CreateTemp`), no-replace publication (`os.Link`) with suffix retry.
- **Empty-target TOCTOU closed**: sqlite publishes the restored file with
  `os.Link` (fails if a database appeared since the check) under a
  per-attempt, exclusively created staging name in the destination directory;
  postgres re-verifies emptiness-modulo-migration-seeds under `LOCK TABLE ...
  ACCESS EXCLUSIVE` inside the restore transaction, before the truncate.
- **Drill honesty**: survival counts captured before the export (on postgres
  `db` and `restored` are the same database, so post-restore reads compared
  the restore with itself); the restore's own `restore.completed` event is
  accounted and asserted; replay candidates include the recovery-code batch
  presented through the native recovery flow; the dump-presence check is per
  verifier class instead of first-hit.

## Review hardening, round 2 (Claude spec + standards axes, Codex R2)

- **Passkey leg added to the drill** (spec axis: the K2 row names passkeys and
  it was neither exercised nor disclosed). The fixture enrols a real
  authenticator (`webauthntest.Device`) pre-backup; post-restore the drill
  presents a REAL assertion and requires refusal (ops spec § 11's pre-backup
  attacker enrolment), and the re-establishment subtest enrols a fresh device
  through the re-established password, proves it logs in, and proves the
  pre-backup device stays dead beside it.
- **Superseded session tokens joined the plaintext scan** — every token the
  fixture rotated past, not only the survivor.
- **Epoch overflow guard** (Codex R2): a forged stamp at MaxInt64 would wrap
  the +1 to MinInt64 — plantable. `authn.nextEpoch` refuses any stamp outside
  [0, 2^32] by name; `TestRestoreRefusesImplausibleEpochStamps` proves the
  refusal happens before any state is published.
- **`MaxKnownCredentialEpoch`'s table list is pinned to the schema**
  (standards axis): `TestMaxKnownCredentialEpochCoversEveryEpochColumn`
  introspects every `credential_epoch` column on a migrated database and
  requires each table in BOTH engines' query text, so a future epoch-stamped
  table cannot silently fall out of the sweep.
- **`MinRestoreSchemaVersion` is pinned to the migration file**
  (`TestMinRestoreSchemaVersionMatchesTheMigration`): this repo renumbers
  migrations on rebase, and a desync fails toward admitting bad archives.
- **Pre-migration preflight fails loud**: `store.ErrNoSchema` distinguishes
  "no goose table" (fresh instance, nothing to export) from every other
  `SchemaVersion` failure, which now aborts the migration instead of silently
  skipping the one artifact it could be recovered from.
- Smaller standards fixes: `RestoreSQLite` takes the caller's context;
  `runAdmin` folded into `runOperator`; the `Status` alias inlined; the
  export unwind deduplicated into one deferred cleanup; sibling-consistent
  error wrapping in `authn/restore.go`.

## Post-review rebase (#100/#101/#103 landed mid-review)

Rebased onto main after Codex R3 CLEAN; the rebase-driven changes are
mechanical plus one addition:

- Migration renumbered `00015` → `00016_restore_reconciliation.sql` (main's
  00015 is now values); `MinRestoreSchemaVersion` bumped to 16 — the pin test
  caught this exactly as designed.
- The drill plants a real secret value (see the superseded scope-out below).
- The isolation harness conflict resolved in favour of this PR's
  `DROP SCHEMA public CASCADE` reset, absorbing the drop-list entries #101
  and #103 had added to the old list.

## Known ceilings

- **OIDC links** are covered by the epoch mechanism and its existing test
  (`internal/isolation/oidc_e2e_test.go`, the `external_identities`
  credential-epoch probe), not replayed inside this drill: an OIDC replay
  needs a live IdP fixture, and the property under test is the same predicate.
- **The v15→v16 bootstrap gap.** The first pre-migration export ever taken is
  at schema 15 and is restorable by no binary: the old one has no restore verb
  and the new one refuses below `MinRestoreSchemaVersion`. Recovery is manual
  (age CLI, then the sqlite file directly). One-time edge of shipping restore
  itself; the alternative — bumping the epoch after the roll-forward instead
  of inside the load — reopens the crash window the whole design closes, so
  the refusal is the right side of the trade.
- **A postgres restore that fails inside the load transaction** leaves a
  migrated-but-empty schema, and the retry is then refused as non-empty until
  the operator drops it. Deliberate: the alternative is a restore that decides
  for itself which existing state is safe to overwrite.

## Deliberately out of scope, and why

- **Federated `iat`-skew predicate.** No federation credential kind exists yet
  (`machine_credentials.kind` admits `hikyo-token` only), so the rule has no
  subject to exercise. The anchor it needs — `reactivated_at` — IS written by
  this restore and asserted non-zero by the drill, so the predicate lands with
  federation rather than needing a schema change then.
- **Adapter outbound credential re-entry.** No adapter exists (#65).
- ~~**Secret values.**~~ **Superseded by the #101 rebase:** flat encrypted
  values landed on main mid-review, so the drill now plants one secret value
  through the real `values.Set` surface (custodian actor, `edit ∧ publish`)
  and the K3 scan asserts it appears nowhere in the dump or archive — the
  headline row's first half is exercised for real. The original scope-out,
  kept for history: there was no `values` table, so K3's plant set is what
  is actually encrypted or verifier-hashed today: password, TOTP seed,
  recovery codes, session token, machine bearer token, establishment
  authority.
- **Backup retention pruning** (180 d / count > 3 for pre-migration exports,
  ops spec § 2 and § 11). Retention is the pruner's ticket; this one shipped
  the export.
- **`last_successful_backup_export` doctor check / RPO metric** (ops spec
  § 11) — same reason.
