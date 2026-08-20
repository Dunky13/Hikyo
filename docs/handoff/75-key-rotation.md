# Handoff: #75 key rotation operations (five ops, crash-safe root rotation)

Issue: https://github.com/Hikyo-Org/Hikyo/issues/75 (parent #41; blocked-by #43
and #51, both merged). Spec: `docs/adr/encryption-model.md` § Rotation and
§ CI-enforced invariants (7, 8, 9, 15). Milestone v1.0.

Branch: `worktree-implement-75`. Model label `model:fable-5`; **implemented by
Claude Opus 4.8** (the running model), a deviation from the label flagged to the
human. Review routing per the label: Codex `gpt-5.6-sol` high.

## Status: 4 of 5 operations complete, reencrypt + writer-fence + E2E remain

`rotate-token-key` shipped with #51. This ticket adds the other four. The
inventory (ADR § Rotation names five; the scanning key's `rotate-scanning-key`
is #39, explicitly out of scope):

| Operation | State |
|---|---|
| multi-version DEK resolution (prerequisite) | **done**, committed |
| `rotate-dek --project/--instance` | **done**, committed |
| `rotate-master-key` | **done**, committed |
| `rotate-root-key --prepare/--verify/--finalize` | **done**, committed |
| writer fence (invariant 7 writer clause) | **infra built + value-stage wired**; remaining paths below |
| `reencrypt --project` (folds in **#187**) | **COMPLETE + pg-validated** — 5 tables + retire, `TestReencryptProjectMovesValueToActiveVersion`, BOTH engines |
| `reencrypt --instance` | **COMPLETE + pg-validated** — all 6 credential tables + retire, `TestReencryptInstanceMovesCredentials`, BOTH engines (row_version CAS + blob-CAS) |
| reencrypt HTTP/CLI transport + scheduler pacing | **not built** — the service methods `ReencryptProject`/`ReencryptInstance` are the seam; wire a CLI `reencrypt --project\|--instance` + routes (project=tenant-class under `/orgs/{org}/projects/{project}/reencrypt`, instance=instance-class under `/instance/reencrypt`), and a `ScheduledJob` sweeping scopes with a `retiring` version |
| kill -9 mid-root-rotation E2E | crypto-level crash-safety **done**; live-op E2E pending |

### CI invariants (ADR § CI-enforced)

Green now: 8 (crash-safe root rotation — `TestRootKeyRotationCrashSafe`), 9
(master rotation completeness + dual-wrap refusal — `TestMasterKeyRotation*`),
and the "no snapshot moves" half of 15 (already green from #51's
`rotate-token-key`). Invariant 7 (rotation completeness / writer race) and the
reencrypt half of everything are **pending with reencrypt**.

## What exists (committed on this branch)

Four commits, each green (build, vet, gofmt, `go test` on sqlite; isolation
invariants; api/cli goldens; TS client regenerated + typechecked):

1. **`feat(crypto): multi-version tier-3 key resolution`** — a scope's DEK is a
   `versionSet` (active + retiring), not a single handle. Writes seal under the
   active version; reads resolve the version named in the record header
   (`ProjectSealer.openVersioned`, `InstanceSealer.OpenField`), so a sealer
   opens ciphertext a reencrypt has not yet moved. Store `GetTier3Versions`;
   authz `keys.Tier3Versions`; `crypto.RecordKeyVersion` exposes a record's
   header version for reencrypt.
2. **`feat(crypto): rotate-dek`** — append a DEK version, demote the old active
   to `retiring`. `Prepare{Project,Instance}DEKRotation` mirror the token
   pattern; store `RotateDEK` under the hierarchy + scope fences, demote-CAS +
   stale-master guard. HTTP `POST /api/v1/instance/rotate-dek`; CLI
   `rotate-dek --instance|--project`; audit `crypto.dek_rotated`.
3. **`feat(crypto): rotate-master-key`** — master is now a version-indexed set
   (`masterSet`, atomic), so tier-3 unwrap resolves its master by the row's
   version (this retired #43's "scaffolding honesty" refusal in `unwrapTier3`
   and closed the commit→adopt window). `PrepareMasterKeyRotation` re-wraps
   every openable tier-3 under a new master; **DEK caches are NOT evicted** (key
   bytes unchanged). Store `RotateMasterKey` refuses when active master count
   != 1 (dual-wrapped), CAS-retires the old master, updates every tier-3
   wrapping. New queries `AllOpenableTier3`, `UpdateTier3Wrapping`,
   `RetireMasterAtVersion`.
4. **`feat(crypto): rotate-root-key`** — crash-safe dual-wrapped protocol.
   `PrepareRootKeyRotation` seals the in-memory master under the new root at
   epoch+1 (no current root needed); `VerifyRootKeyRotation` confirms the
   primary source now unwraps the new wrapper; boot warns on the dual-wrapped
   state (`RootRotationPending`). New root read from `HIKYO_NEW_ROOT_KEY_FILE`
   — **no key material on the API**. Store `RootKeyRotatePrepare` /
   `RootKeyRotateFinalize`; query `RetireMasterWrapperAtEpoch`. Three audit
   events. **Also fixed a latent sqlc-sqlite mis-slice**: an em-dash in a query
   comment truncated the generated `AcquireScopeGeneration` statement at
   runtime (not codegen) — see the `sqlc-sqlite-non-ascii-truncation` note.

### Key design facts for a continuer

- **All keyring KeyStore reads run under `SiteBoot` SystemProof** (via
  `internal/store/keyring`), including on-demand DEK loads. The four rotation
  **writes** run under the operator proof through the service's own `tx.Write`
  (like `RotateTokenKey`), NOT the boot path.
- **`rotate-master-key` and `rotate-root-key` are mutually exclusive**, enforced
  by the "exactly one active master wrapper" check inside the hierarchy fence.
- **`RootKeySource`** (`internal/service`) re-reads root material on demand
  (master/root rotation); the app impl (`rootKeySource` in `internal/app/app.go`)
  reads the same file/env sources boot used. The isolation harness uses
  `probeRootSource` / `mutableRootSource` (`harness_test.go`).
- Crash-safety is testable **in-process**: a crash mid-rotation leaves the same
  persisted state as a clean stop, and `LoadKeyring` IS the reboot. No
  real-binary process harness is needed (none exists in `internal/isolation`).

## Remainder — precise design (worked out, not yet built)

### Writer fence — INFRASTRUCTURE BUILT, wiring in progress

`feat(crypto): writer fence infrastructure + value-stage wiring` shipped the
complete fence mechanism: store query `AssertActiveTier3Version` (sqlite plain /
postgres `FOR SHARE`), `KeyReader.AssertActiveDEKVersion`, `store.ErrStaleDEK`,
authz op `keys.AssertActiveDEKVersion`, and the `fenceProject` / `fenceInstance`
service helpers (map `ErrStaleDEK` → conflict). Wired into the **value-stage**
path so far. **Remaining: add `StoreKeysAssertActiveDEKVersion` to each other
ciphertext-writing operation's store set, and call the helper before its store
write.** The paths and their operations:

- `OpValuePublish` (value_entries + snapshot_entries), `OpValueSet` (declare),
  `OpRevisionRestore` (rollback re-seal) — `fenceProject`.
- the adapter ops (`OpAdapterConfigure`/`CredentialSet`/`Adopt`/`Move`) —
  `fenceProject`.
- password / totp / recovery / oidc-provider / saml-sp-key / remote-credential
  ops — `fenceInstance`.

Add a **completeness gate** (a test in the `hikyo:table` lint idiom) asserting
every encrypted column's write path calls a fence helper, so a future write
can't silently skip it. The original design below stands.



Every ciphertext write must not commit under a version being retired. The hole
(confirmed): a sealer built at active=N, then rotate-dek + full reencrypt +
retire all complete, then the writer's tx opens — a plain state read finds no
conflict and the writer seals under retired N. Close it with a **locking read**:

- New query `LockTier3VersionShared`: sqlite `SELECT state FROM tier3_keys WHERE
  purpose=? AND org_id=? AND project_id=? AND version=?`; postgres the same with
  `FOR SHARE`. One query is both the lock and the check.
- New store method `AssertActiveDEKVersion(pf, purpose, org, proj, version)` →
  require `state='active'`, else `ErrStaleDEK` (new, beside `ErrRotationSuperseded`).
- The version is already in the ciphertext — call `crypto.RecordKeyVersion(blob)`
  in the store write method rather than threading a new param (store already
  imports crypto). Scope (purpose/org/proj) is on the row being written.
- Wire into all **11** ciphertext-writing store paths (see table below). In-flight
  writers hold `FOR SHARE` on row N, so rotate-dek's demote and reencrypt's
  retire of N block until they commit; a writer starting after demote sees
  `retiring` → `ErrStaleDEK`. Map `ErrStaleDEK` → `domain.ErrConflict` (409); the
  client retries the request (getting a fresh sealer). Rejection satisfies the
  invariant — no in-service re-seal loop is required.
- sqlite needs no `FOR SHARE` (single write connection serializes globally); the
  plain `SELECT` + state check is enough there.

**It lands whole or not at all** — a fence covering 5 of 11 tables that claims
invariant 7 is worse than no fence commit.

### reencrypt --project X / --instance  (folds in #187)

**#187 sharpens this with the ops-spec §9 bounds** — the reencrypt walk is
**background, chunked 100 rows, 100 ms inter-chunk pause, resumable, per-row
compare-and-swap, with a row-count preflight + progress.** Acceptance also flips
a bound-registry entry from `enforcement-pending` to `enforced` — but that
registry (`#77`'s `feat(ops): bound registry`, commit `ad99ec4d`) is on the
parallel branch `t3code/implement-ticket-work-2`, **not on main or this branch**,
so the flip is a cross-branch coordination item, not part of this feature's code.
Build the walk here; flip the registry when #77 lands (or in the merge that
unifies them).

**Per-row CAS (anti-resurrection) strategy — verified against the schema:**
- Project tables (value_entries, snapshot_entries, pending_changes, adapters,
  adapter_route_moves) have **no row-version column**; CAS on the **old
  ciphertext blob** (`UPDATE … SET ciphertext=? WHERE id=? AND ciphertext=?`).
  A concurrent fresh write changed the blob → CAS matches 0 rows → skip (that
  row is already on the active version). value_entries is normally
  delete-then-insert-with-fresh-id (the id is AAD-bound), but reencrypt keeps
  the **same id and AAD** (only the DEK version moves), so an in-place ciphertext
  UPDATE is correct and exempt from that convention; the append-only lint guards
  only the two audit tables, so it does not block this.
- Instance tables (password/totp/recovery/oidc/saml) have `dek_version` +
  `row_version`; CAS on **row_version** (the existing guard #187 refers to),
  and stamp the new `dek_version = InstanceSealer.Version()`.
- remotes has neither; blob-CAS like the project tables.

**Adapters + adapter_route_moves specifics (the last two project tables):** these
use the **raw-SQL adapter repo** (`repos_adapters.go`, `sqliteAdapters{db}`), NOT
sqlc — so add hand-written list/CAS queries in that pattern, not `.sql` files.
AAD for BOTH is `ProjectFieldAAD{OwnerTable:"adapters", OwnerRowID:<adapter_id>,
FieldTag:"credential"}` (no env/key/snapshot). Note `adapter_route_moves` is
**keyed by its own move id but its AAD OwnerRowID is the adapter_id** — so
`projectFieldRow` needs a distinct `owner` field (add it; value/snapshot/pending
leave it as id). Both ciphertext columns are **nullable** (adapter without a set
credential; move without a pending credential) — the walker already skips empty
ciphertext. Then wire two authz store ops each into `OpReencryptProject`.

**The retire (once all 5 project tables walk):** after a full pass moves zero
rows, every retiring version is unreferenced (the walk moved everything to active
and the writer fence blocks new retiring-version writes). Retire them inside the
scope fence (`AcquireScopeGeneration` FOR UPDATE) with a new
`RetireRetiringTier3ForScope` query (`state='retiring'→'retired'` for the scope),
then `evictProjectDEK` + zero. Loop-until-a-pass-moves-zero for crash-resume.

**The proven pattern (value_entries, `internal/service/reencrypt.go`) — replicate
per table:** (1) a `ListXForReencrypt` keyset-paged query + a `ReencryptX` CAS
update query (both engines, with the scope-class chain conjuncts the predicate
analyzer requires); (2) `ReencryptRow`-shaped store methods + two authz store
ops added to `OpReencryptProject`'s set; (3) a `reencryptXChunk` walk function
mirroring `reencryptValueChunk` — reconstruct the AAD with that table's existing
builder, `RecordKeyVersion` to skip active rows, `OpenX`→`SealX`, CAS-update.
Per-table specifics: snapshot_entries (`snapshotAAD`, has snapshot_id; immutable
so CAS always matches), pending_changes (`pendingAAD`, ciphertext NULL for
`unset` → skip those rows), adapters + adapter_route_moves (owner_table
`adapters`, `SealField`/`OpenField`). Instance tables use `InstanceSealer`,
stamp the new `dek_version`, and CAS on `row_version`.

A resumable, per-row-transactional walker that moves every ciphertext onto the
scope's active DEK version, then retires the superseded versions.

**The complete encrypted-column surface (11 columns), from the inventory:**

Project-scoped (project DEK) — `reencrypt --project` walks these 5:

| table.column | kind | version col? | AAD (owner_table / field_tag / extras) |
|---|---|---|---|
| `value_entries.ciphertext` | value | none (header-parse) | env_id,key_id,row=id,field=`value` |
| `pending_changes.ciphertext` | project_field | none | `pending_changes` / `pending_value` / +env_id,+key_id |
| `snapshot_entries.ciphertext` | project_field | none | `snapshot_entries` / `snapshot_value` / +env_id,+key_id,+snapshot_id |
| `adapters.credential_ciphertext` | project_field | none | `adapters` / `credential` (no trailing triple) |
| `adapter_route_moves.pending_credential_ciphertext` | project_field | none | `adapters` / `credential` (owner_row_id = adapter_id) |

Instance-scoped (instance DEK) — `reencrypt --instance` walks these 6:

| table.column | version col | AAD (owner_table / owner_row / field_tag) |
|---|---|---|
| `password_credentials.verifier` | `dek_version` (+`row_version` CAS) | `password_credentials` / account_id / `verifier` |
| `totp_credentials.seed` | `dek_version` | `totp_credentials` / row id / `seed` |
| `recovery_codes.batch` | `dek_version` | `recovery_codes` / account_id / `batch` |
| `oidc_providers.client_secret` | `dek_version` | `oidc_providers` / provider_id / `client_secret` |
| `saml_sp_keys.encrypted_private_key` | `dek_version` | `saml_sp_keys` / key id / `private_key` |
| `remotes.credential_sealed` | none (header-parse) | `remotes` / remote_id / `credential` |

**AAD reconstruction — REUSE the existing builders, do not re-derive** (a wrong
field is a permanent decrypt failure). The walker must rebuild each row's AAD
with the exact same function that sealed it:
- value_entries → `valueAAD(store.ValueEntry{...})` (values.go): org, project,
  env, key, row=id, field `value`.
- snapshot_entries → `snapshotAAD(org, project, env, key, snapshotID, rowID)`
  (publish.go): owner_table `snapshot_entries`, field `snapshot_value`.
- pending_changes → `pendingAAD(org, project, env, key, rowID)` (publish.go):
  owner_table `pending_changes`, field `pending_value` (no snapshot_id).
- adapters / adapter_route_moves → the adapter AAD builder (owner_table
  `adapters`, owner_row `adapter_id`, field `credential`, no trailing triple).
- instance tables → `InstanceFieldAAD{owner_table, owner_row, field_tag}` per the
  inventory row.
The list query for each table must therefore SELECT every column those builders
read. Re-seal is `pt := sealer.OpenX(aad, oldCt); newCt := sealer.SealX(aad, pt)`
— Open resolves the header's (retiring) version, Seal uses the active one.

**`reencrypt --instance` — fully de-risked spec (build as `OpReencryptInstance`,
ClassInstance, empty scope, `CapReencrypt@None`; the 6 credential tables are
class=instance, no tenant chain).** Use the `InstanceSealer` (OpenField/SealField,
`InstanceFieldAAD{OwnerTable, OwnerRowID, FieldTag}`). Confirmed per-table:

| table | pk | ciphertext col | AAD owner_row | field_tag | CAS |
|---|---|---|---|---|---|
| password_credentials | account_id | verifier | account_id | verifier | row_version + stamp dek_version |
| totp_credentials | id | seed | id | seed | row_version + dek_version |
| recovery_codes | account_id | batch | account_id | batch | row_version + dek_version |
| oidc_providers | id | client_secret | id | client_secret | row_version + dek_version |
| saml_sp_keys | id | encrypted_private_key | id | private_key | row_version + dek_version |
| remotes | id | credential_sealed | id | credential | **blob-CAS** (no dek_version/row_version) |

Write an instance walk mirroring `walkTable` but with the `InstanceSealer`, a CAS
of `WHERE …=? AND row_version=?` that sets `row_version=row_version+1` and stamps
`dek_version = InstanceSealer.Version()` (5 tables), and blob-CAS for remotes.
Because the 5 tables carry `dek_version`, the list can `WHERE dek_version <> ?`
(active) to skip current rows in SQL rather than header-parsing. Then the retire
reuses `RetireRetiringTier3(PurposeInstance, "", "")` and
`InstanceSealer`-side eviction (add an `EvictInstanceDEK` / reload of the atomic
instance set). password/totp/recovery/oidc use sqlc query files; saml + remotes
— check whether they are sqlc or raw and follow suit.

**Walker design (per the advisor):**

- A per-table registry entry: `{table, ciphertext column, optional version
  column, scope columns, AAD reconstruction fn}`. Each entry needs a **list**
  query (id + ciphertext + AAD component columns, scoped) and an **update**
  query (set ciphertext, and `dek_version` where present, by id + optimistic
  `row_version` where present). That is ~22 query pairs × 2 engines — the bulk
  of the mechanical work. Keep them sqlc (the repo forbids raw SQL in the store
  layer); do NOT introduce a dynamic-table-name walker.
- Per row: `crypto.RecordKeyVersion(blob)`; if == active, skip (this is what
  makes it resumable — re-run skips current rows). Else open under the old
  version via the scope sealer (which holds the retiring versions), re-seal
  under active, UPDATE in its **own transaction**. No global lock.
- Loop passes until a full pass moves zero rows — that "dry" pass IS the
  zero-reference proof. Then, inside the scope fence (`AcquireScopeGeneration`
  FOR UPDATE, which the writer fence's FOR SHARE blocks against), retire every
  `retiring` version whose ciphertext is gone (`RetireRetiringTier3AtVersion`,
  a new CAS query `state='retiring'→'retired'`).
- **DEK-cache eviction lands here**: the `cacheDEK` comment already notes
  rotation's fence is the one place eviction+zeroing is legal. `evictProjectDEK`
  exists; add the instance equivalent and zero the retired version's buffer.
- Expose two ways (satisfies #187's "background job", the issue's "scheduler
  job" wording, and the ADR's "resumable from the CLI"): a `ScheduledJob`
  (`internal/app/scheduler.go`, `ScheduledJob{Name, Run, LastSuccess}`) that
  sweeps for any scope with a `retiring` version and processes it **in 100-row
  chunks with a 100 ms inter-chunk pause** (#187), resuming across runs — the
  crash-resume, for free — **plus** an HTTP/CLI `reencrypt --project/--instance`
  that preflights the row count, triggers/awaits the walk, and reports progress
  (`rows_moved` / remaining). Share the chunk-walk core between the two.
- **Completeness gate**: add an analyzer/test in the `hikyo:table` lint idiom
  asserting every encrypted column is declared in the reencrypt registry, so a
  future encrypted column cannot silently escape reencrypt.
- Audit `crypto.reencrypt_completed` (already designed: scope, org, project,
  rows_moved) — register it WITH its emitter, per the "stage beside the emitter"
  discipline (registering an event with no emitter reddens
  `every_registered_type_is_actually_emitted`).
- authz: op `crypto.reencrypt` (formula `reencrypt@instance`), store ops
  `keys.RetireRetiringTier3` + the per-table read/write ops. HTTP `POST
  /api/v1/instance/reencrypt` {scope, org?, project?}; CLI `reencrypt
  --instance|--project`. `usr_root` already holds the `reencrypt` grant.

### Live-op E2E (acceptance K1)

An isolation E2E running the full recovery order on live data —
`rotate-root-key` (prepare→install→verify→finalize) → `rotate-master-key` →
`rotate-dek` (project + instance) → `reencrypt` (project + instance) →
`rotate-token-key` — asserting values stay readable throughout and, after
reencrypt, zero ciphertext references a retired version. The kill -9 clause is
covered by `TestRootKeyRotationCrashSafe` in-process (a crash leaves the same
persisted dual-wrapped state; `LoadKeyring` is the reboot). Run on both engines
(`HIKYO_TEST_POSTGRES_DSN`).

## Review record

Three-axis review of the 4 delivered ops (Standards + Spec Claude sub-agents +
cross-model Codex `gpt-5.6-sol` high, per the standing routing). **Codex and the
Claude Spec reviewer independently converged on the same three concurrency bugs**
— all fixed in `fix(crypto): rotation review round 1`:

- **CRITICAL** — master rotation's zero-reference check ran outside the fence; a
  tier-3 key created in the pre-fence window stranded under the retired master
  (instance-DEK variant bricked boot). Fixed: `CountOpenableTier3NotAtMaster`
  in-fence + predecessor-version pin.
- **HIGH** — root `--prepare` didn't pin the master version in-fence; a master
  rotation in the gap produced two active wrappers of different versions →
  brick. Fixed: version pin in `RootKeyRotatePrepare`.
- **MEDIUM** — `--finalize` didn't re-verify the primary root → skipping verify
  bricked boot. Fixed: finalize re-runs verify before retiring.

Plus: master adopt-window (new master made resolvable at prepare, activated on
commit, abort-zeroed on failure), constant-time verify compare, error→conflict
mappings, and the `rotate-root-key --yes` gate. Codex #4 (held sealer → retiring
DEK) is the deferred writer-fence unit (the ADR's "rotate-dek is incomplete on
its own").

**R2 (Codex, high):** closed R1 1/3/4; blocked on two — verify compared against
retained *retired* masters (not the active one), and two concurrent master
*preparations* mint different keys for one version so a version-keyed adopt could
activate/zero the wrong key. Both fixed: verify now requires the active version +
key; hierarchy rotations are serialized.

**R3 (Codex, high):** verify fix confirmed; the serialization lock was on each
`Rotation` instance rather than the shared object. Fixed by moving it to the
`Keyring` (the one object every service holds) — process-wide by construction.
Per the standing 3-round cap this lock-placement refinement (same R2 blocker, not
new scope) was fixed in-slice and verified by a scoped closure Codex pass rather
than routed to a ticket; the deviation is recorded here for the merge gate.

**Test gap the Spec reviewer flagged, to close with reencrypt:** the invariant-8/9
crypto tests use a single-threaded `memStore`, so the *fenced-interleaving*
clauses (a tier-3 created concurrently with master rotation; a master rotation
racing root prepare) are not exercised — only the serial happy paths. A
**store-level concurrent test on both engines** is required to exercise the new
in-fence refusals directly, and lands naturally with the writer-fence work.

## Deliberate deviations (for human disposition)

1. **Model label mismatch.** `model:fable-5`; implemented by Opus 4.8. The
   commit co-author reflects reality; the review routing (Codex high) is
   unaffected. Flagged rather than silently followed.
2. **Root-key rotation transport.** New root read from a server-side source
   (`HIKYO_NEW_ROOT_KEY_FILE`), never the API body — a request-supplied path
   would be a file-probe oracle. This is a command-surface decision the ADR
   delegates to #25; recorded here for that ticket.
3. **Crash-safety tested in-process**, not by killing a real binary — a crash
   and a clean stop leave identical persisted state, and `LoadKeyring` is the
   reboot. No real-binary process harness exists in `internal/isolation`.

## Verification record

`go build ./...` (incl. `-tags k8se2e`), `go vet`, `gofmt -l` clean.
`go test ./...` zero failures on sqlite (the `ui`-tagged webui embed needs a
built `dist`, a pre-existing local-only gap; CI builds the UI first). **Postgres
IS validated locally** (a dbugit dev pg 18 container at 127.0.0.1:5432): the
reencrypt cycle (both engines), the audit E2E's full rotation cycle
(rotate-token/dek/master/root + reencrypt) on pg, and the conformance / store /
isolation legs — all green. sqlc regeneration idempotent; oapi-codegen
regenerated; TS client regenerated + `tsc --noEmit` clean.

## Session continuation — reencrypt + fence completeness (this branch, latest)

Everything below is committed on `worktree-implement-75` and validated on BOTH
engines (sqlite + local pg 18: full crypto/service/store/isolation/conformance
legs green — last pg run 2287 passed).

**reencrypt COMPLETE for both scopes + transport.**
- `--project` (ClassTenant, needs the project chain): 5 tables —
  value_entries, snapshot_entries, pending_changes, adapters, adapter
  route-moves. `--instance` (ClassInstance, empty scope): 6 credential tables —
  password_credentials, totp_credentials, recovery_codes, oidc_providers,
  saml_sp_keys, remotes. `internal/store/repos_reencrypt.go` consolidates the 6
  instance tables; project tables via their own repos + raw-SQL adapters.
- Chunked (100 rows / 100ms pause, overridable), resumable (skips rows already
  at active), per-row CAS (blob-CAS for project value/remotes; row_version CAS +
  dek_version stamp for the versioned instance tables). AAD reconstructed per
  table from the existing builders. Retire is all-or-nothing per scope:
  `RetireRetiringTier3ForScope` runs inside the scope fence only once every
  table is dry, then EvictProjectDEK / ReloadInstanceDEK.
- Transport: `POST /api/v1/orgs/{org}/projects/{project}/reencrypt` and
  `POST /api/v1/instance/reencrypt`; `hikyo reencrypt --org O --project P` /
  `--instance`. Audited `crypto.reencrypt_completed`.

**Writer fence (invariant 7) — now COMPLETE across every sealing path.**
Previously only value-stage. Now every service function that seals ciphertext
for storage fences in its write tx before the store write:
- Project (fenceProject): value declare/set, copy dest (secret+config), import,
  publish (snapshot entries + cells), revision restore, all 4 adapter credential
  paths. Ops gained `StoreKeysAssertActiveDEKVersion`.
- Instance (fenceInstance / fenceInstanceVersion): remotes, OIDC, SAML SP-key.
- Authn-resolution surface (proof-free): password establish/upgrade, TOTP enrol,
  recovery generate/consume seal under the instance DEK with no tenant proof.
  New `authn.Resolver.AssertActiveInstanceDEKVersion` (same FOR SHARE assert,
  instance purpose) via `TxAuthorizer`. This closes the bare-INSERT window
  (WritePasswordCredential / WriteRecoveryCodes / CreateTOTP had no row_version
  CAS) where a slow argon2 derivation spanning a rotate-dek could strand an
  unreadable credential. KDF-upgrade-on-login skips (not fails) on a rotation
  race, preserving valid logins.

**InstanceSealer snapshot fix (correctness).** `Version()` used to re-read the
live active version, making the instance fence a no-op (compared live-to-live).
It now snapshots its write-handle at construction, mirroring ProjectSealer, so
Version() and the fence agree on the sealed version even across a concurrent
adoption. The old key buffer is GC-reclaimed (never zeroed on adoption), so a
captured handle stays usable — exactly the stale write the fence rejects.

**New CI gate.** `internal/lint/fence.go` (`CheckFenceCompleteness`) fails the
build if any `internal/service` function seals ciphertext without calling a
fence. Explicit `fence:delegated` (seal-helper returns version to a fencing
caller) and `fence:exempt` (never-written timing dummy) markers; reencrypt.go
(the mover) exempt wholesale. Negative fixture proves it fires.

**Live recovery-order E2E.** `TestFullRecoveryOrderOnLiveData` (both engines):
seeds a real value, runs rotate-root (prepare/verify/finalize) → rotate-master →
rotate-dek → reencrypt in sequence, asserts the value opens at every step, ends
on the active DEK version, and survives a fresh boot under the new root.

**kill-9 mid-root-rotation: VERIFIED covered** by the pre-existing
`TestRootKeyRotationCrashSafe` — seal under rootA → prepare (dual-wrapped) →
discard keyring and reboot from the datastore alone → RootRotationPending
surfaces and the value opens under BOTH old and new root → verify → finalize →
reboot clears pending and the old root is refused. LoadKeyring IS the reboot.

## Open items for the merge gate (human disposition)

1. **Codex R1 review in flight** on the reencrypt + fence diff
   (`.xreview/reencrypt-fence-r1.md`). Standing/blocking per WORKSTYLE; round
   cap 3. Findings loop back before merge.
2. **ScheduledJob for background reencrypt (#187 pacing) — DEFERRED, needs a
   decision.** The operator-triggered reencrypt (CLI/HTTP) is complete and
   resumable. A scheduler that auto-sweeps scopes with a retiring version would
   need SiteScheduler's system proof to gain write access to all 11 ciphertext
   tables, materially widening the invariant-11 system-proof enumeration.
   Options for Marc: (A) read-only sweep-and-warn under system proof — smallest
   surface, reencrypt stays an operator act like the other rotations
   [recommended]; (B) full auto-reencrypt under system proof; (C) operator-only,
   document resume, no scheduler. Not built pending Marc's pick.
3. **Human merge gate.** CI green + review CLEAN + (no preview env for a crypto
   backend change) → STOP and ask before merge. Not pre-authorized.

## Review round 1 — reencrypt + fence diff (Codex high + local Standards/Spec)

Diff reviewed: `db1d5cf1..HEAD` (reencrypt walk + fence-completeness + transport;
the rotation core through db1d5cf1 already passed its own closed R1→R3). Round
cap 3.

**BLOCKING (fixed, commit 122ceff8).** Codex HIGH + Spec-1 agreed: the retire
ran an unconditional `UPDATE tier3_keys SET state=retired WHERE state=retiring`
with no zero-reference check — ADR line 172 ("verified by query inside the
fence, never assumed"). Codex's data-loss scenario: reencrypt captures active=v2,
a concurrent rotate-dek makes v3 active + v2 retiring, reencrypt finishes on v2,
the retire destroys v2 → moved rows undecryptable. Fixed with three in-fence
layers (per-chunk re-assert, retire re-assert under FOR SHARE, dryness scan over
every table) + the reencrypt-coverage lint. Two TDD refusal tests, both engines.

**Spec-2 (fixed).** Promised reencrypt-coverage gate now exists
(`internal/lint/reencrypt_coverage.go`): every schema BLOB/BYTEA column is pinned
covered-or-exempt; an unclassified new column fails the build.

**Standards-1 (fixed).** `walkTable` used the shared `s.pause` helper.

**Dispositions (human, at the merge gate) — not code-fixed:**

1. **Codex MEDIUM — fence lint cannot prove same-transaction.** The
   `CheckFenceCompleteness` analyzer proves a seal and a fence co-occur in a
   function, not that the fence runs in the same transaction as the store write
   (seal→fence-commit in tx A, write in tx B would pass). Proving tx co-location
   needs dataflow the type-only pass does not attempt. All 15 current sealing
   sites were verified in-tx by hand (each fences immediately before its write,
   in that write's own tx); the limit is now stated in `fence.go`. Accept as a
   documented build-time-surfacing limit (the runtime fence is the enforcement).
2. **Spec-3 — "per-row transactional" is chunk-transactional.** ADR line 149
   says "per-row transactional"; the walk seals a whole chunk (default 100 rows)
   per `tx.Write`. Resumability (per-row CAS + skip-if-current) is preserved, so
   the guarantee the phrase protects holds; only the literal granularity differs.
   Deliberate deviation for connection-efficiency (#187's chunking mandate);
   human disposition.
3. **Standards-3 — DEK version type split (uint32 in crypto, int64 at the
   sqlc/store boundary).** The two fence entrypoints differ
   (`fenceInstanceVersion(uint32)` vs `AssertActiveInstanceDEKVersion(int64)`);
   callers convert at the boundary. Rooted in sqlc's int64 columns — unavoidable
   at the boundary; not churned mid-review.
4. **Standards-4 — two stale-DEK error conventions.** The proof-carrying fence
   returns `store.ErrStaleDEK` (mapped to `ErrConflict` centrally); the
   proof-free authn twin returns `domain.ErrConflict` inline (it cannot import
   store — cycle). Same surfaced behavior; the divergence is a package-layering
   constraint, documented here.

## Review round 2 — CLOSED (Codex high)

R2 verified the R1 fixes. Verdict verbatim: **"fixes sound."** All three findings
RESOLVED:
1. HIGH retire-without-dryness — RESOLVED: the active-version FOR SHARE, dryness
   scan, scope-generation acquisition and retirement all execute in the same
   tx.Write; all 5 project + 6 instance tables scanned; the v2/v3 race now
   refuses retirement or blocks rotation; no remaining window.
2. Coverage gate — RESOLVED: covered set matches the walk's 11 tables; the
   verifier/flow exemptions are hashed/opaque/short-lived, not DEK envelopes.
3. Lint same-tx limit — RESOLVED as documented; no split fence/write tx in the diff.

Review loop CLOSED at R2 (cap 3; R3 not needed). The reencrypt + fence diff is
review-CLEAN. Combined with the rotation core's own closed R1→R3, the whole #75
feature has passed its blocking cross-model review.

## Merge-gate state

- CI: NOT yet run (branch not pushed; push needs the parallel-session rebase +
  migration-renumber coordination per the branch-state memory).
- Review: CLEAN (this feature's two loops both closed).
- Preview: N/A (crypto backend; no UI/preview surface).
- Local verification: full suite green on BOTH engines (sqlite + local pg 18).
- STILL NEEDS MARC: (1) the #187 scheduler decision (A/B/C above); (2) go-ahead
  to push (triggering CI) and the merge itself. Not pre-authorized.
