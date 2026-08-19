# Handoff: #63 Compose delivery — `hikyo run --`, rendered `env_file`, offline snapshot, `compose doctor`

Issue: https://github.com/Hikyo-Org/hikyo/issues/63 (parent #41; mvp-boundary row
**M2**). Binds [compose-integration.md](../adr/compose-integration.md) (the
locked Compose ADR), [system-architecture.md § Client local state](../adr/system-architecture.md),
[ops-spec.md § 6](../adr/ops-spec.md) (7 d snapshot age, current+3 generations,
runtime/state directory conventions, flush-before-fetch, ARG_MAX preflight),
[audit-model.md](../adr/audit-model.md) (offline-reconciled origin), and the
api-cli-surface ADR (verb taxonomy: `run --` top-level, `compose render|sync|doctor`).

Blockers #51 (revisions/publish) and #62 (OIDC federation + conditional cursor)
are merged.

## Scope

**In:**

- **Server — values on the delivery surface.** `DeliveredKey` gains `value`
  (config always; secret iff the caller's projection holds `reveal` for the
  current snapshot / `reveal-history` for a pinned non-current one — the
  `values export` rule mirrored). One `disclosure.value_revealed` event per
  delivered secret, `surface: "delivery"`. `config_only` query parameter = a
  distinct authorized projection, bound into the cursor and recorded in the
  fetch event. Server-asserted snapshot `issued_at` / `expires_at` on the
  response (7 d; the client AAD binds them). Offline-record reconciliation
  endpoint (authenticated, idempotent, `origin: offline-reconciled`,
  since-revoked credentials accepted).
- **Client library** (`internal/compose` + client-side crypto in
  `internal/crypto`): raw-dotenv encoder with refusal-by-name for the
  unrepresentable class; loader-control baseline; project config file
  (committed, non-secret, targets by key id, per-target acknowledgements);
  local keys (one 256-bit local key, HKDF-separated stamp key + snapshot key),
  stamp `v1-<32 hex>` grammar; generation directories + completion marker +
  single atomic-rename stamp file + per-project writer lock + GC (current+3);
  XChaCha20-Poly1305 snapshot container with the normative AAD tuple, issuance
  high-water mark, expiry refusal, opt-in per stack; offline per-key audit
  records fsynced before plaintext release; cursor state with the three-part
  eligibility test; doctor checks as pure functions.
- **CLI verbs**: `hikyo run -- <cmd>` (machine-only, exec semantics with
  126/127, merge-collision hard error with named escape hatch, loader-control
  refusal, ARG_MAX preflight), `hikyo compose render`, `hikyo compose sync`
  (one-shot), `hikyo compose doctor` (floor 2.30 via `docker compose version`,
  stamp grammar, `:?`, `format: raw`, token-file mode, state-dir mode,
  config/stamp/generation/server agreement). Spellings + help golden.
- **E2E + CI fixtures**: round-trip over the representable domain, refusal by
  name, stamp-driven recreate, crash consistency at a deterministic seam,
  snapshot expiry + tmpfs-only, doctor floor refusal. Demo compose stack
  (`install/compose/`): a container echoes a hikyo-delivered value.

**Out (stated, not dropped):**

- `hikyo compose adopt` / scaffold-first rewrite — depends on the definitions
  flow (#70); the project config file is hand-authored and documented here.
- Per-project machine-`reveal` opt-in (grant API) — #67's handoff says "ships
  with #17/#18"; no open ticket owns it. E2E seeds reveal grants at the store
  layer (`seedMachineReveal`). **Marc's call to reclaim.**
- `run --use-human-session` exception (needs the bound reauth ceremony) —
  machine credentials only in this build; the human-session fallback is a
  refusal.
- systemd unit generator (the ADR ships none); reference unit + timer are
  documentation.

## Streams

A (server) ∥ B (client lib) → C (CLI wiring) → D (e2e, demo, docs). A and B
were built in sibling worktrees and merged before C.

(Filled in as the streams land.)

## Stream A — server (Codex gpt-5.6-sol), commits ef65b45 + de34902

Implemented the server half of Compose delivery (#63).

- `DeliveredKey.value` now carries config plaintext under `read` and secret
  plaintext under `reveal` / historical `reveal-history`; unrevealed secrets
  remain presence-only. Full secret delivery emits one
  `disclosure.value_revealed` event per secret with `surface: delivery`.
- `config_only` is a server-side projection, is recorded on
  `identity.delivery_fetched`, and is bound into the delivery cursor while the
  change token remains over the full manifest.
- `DeliveryResponse` now requires `issued_at` and `snapshot_expires_at`; expiry
  is server-asserted at issuance plus seven days.
- Added `delivery.reconcile-offline` and
  `identity.offline_records_reconciled`. The endpoint reconciles up to 1000
  client records idempotently, emits `disclosure.value_revealed` with
  `surface: offline-serve` and `origin: offline-reconciled`, preserves the
  client-asserted occurrence time, and accepts a since-revoked serving
  credential only from a live credential of the same service account.
- Added migration `00026_offline_delivery_records` on SQLite and PostgreSQL,
  regenerated OpenAPI/sqlc bindings, and re-pinned
  `operation_formulas.json`, `annotated_queries.json`, and the API no-proxy
  contract surface.

Validation passed: `go build ./...`, `go vet ./...`, empty `gofmt -l .`, the
required delivery/service/server/audit/authz/boundary tests, SQLite isolation
and conformance suites, API contract tests, and CLI regression tests.

Follow-up (de34902): `DeliveredKey.key_id` (required, immutable key id) and `DeliveryResponse.credential_id` (required, the authenticated caller's credential id, both dispositions).

## Stream B — client library (Claude Opus 4.8), commits 8f8207a..4ea2799

# Stream B summary — Compose client library (#63)

Client-library half of #63. No `internal/cli`, `api/`, `internal/service`,
`internal/server`, or `web/` touched. Branch `t3code/implement-issue-63-B`.

## Exported API surface

### `internal/crypto/client.go`
- `type LocalKeys struct{…}` (unexported fields)
- `func LoadOrCreateLocalKey(dir string) (*LocalKeys, error)` — one random 256-bit
  `local.key` (O_EXCL, 0600), state dir 0700, owner+mode enforced, refused (not
  repaired) on violation.
- `func (k *LocalKeys) Stamp(content []byte) string` — `v1-<32 hex>`, keyed
  HMAC-SHA256 over `"hikyo-stamp-v1\x00"+content`, 128-bit.
- `func ParseStamp(s string) error` — anchored `^v1-[0-9a-f]{32}$`.
- `func (k *LocalKeys) SealSnapshot(aad SnapshotAAD, plaintext []byte) ([]byte, error)`
- `func (k *LocalKeys) OpenSnapshot(aad SnapshotAAD, record []byte) ([]byte, error)`
- `type SnapshotAAD struct{ InstanceOrigin, OrgID, ProjectID, EnvironmentID,
  CredentialID string; Revision int64; Pinned bool; Projection []string;
  ConfigOnly bool; TargetNames []string; IssuedAt, ExpiresAt string }`
- `internal/crypto/crypto.go`: new `KindComposeSnapshot Kind = 7` (encryption-model
  ADR amendment 5).
- Build-tagged `client_secure_unix.go` / `client_secure_windows.go`.

### `internal/compose/dotenv.go`
- `type Row struct{ Name, Value string }`
- `type Refusal struct{ Key, Reason string }`
- `func EncodeRaw(rows []Row) ([]byte, []Refusal, error)` — non-empty refusals ⇒ no
  file. Refuses embedded `\n`/`\r`, NUL, and names not `^[A-Za-z_][A-Za-z0-9_]*$`.
- `FuzzEncodeRawRoundTrip` + JSON corpus `testdata/roundtrip/*.json`.

### `internal/compose/loadercontrol.go`
- `func IsLoaderControl(name string) bool` (case-sensitive; exact + `LD_`/`GIT_`).
- `func RefuseUnacknowledged(names, acknowledged []string) []string` (sorted).
- Baseline pinned by test.

### `internal/compose/config.go`
- `type Config`, `type SnapshotSettings`, `type Target`.
- `func ParseConfig(data []byte) (*Config, error)` — yaml.v3 `KnownFields(true)`,
  https/loopback-http origin, target-name grammar, downward-only `snapshot.max_age`,
  rejects `token`/`token_file`/`credential` naming both channels.
- `func (c *Config) SnapshotMaxAge() time.Duration`, `func (c *Config) TargetNames() []string`.
- `const DefaultSnapshotMaxAge = 7*24h`.

### `internal/compose/generation.go`
- `func TargetStamp(keys *crypto.LocalKeys, content []byte) string` — prepends
  `"hikyo-target-content-v1\x00"`, then `keys.Stamp`.
- `type Probe interface{ BeforeGenerationComplete(stamp string) error; BeforeStampRename() error }`
- `type Writer`; `func NewWriter(stateDir string, probe Probe) *Writer`.
- `func (w *Writer) BeginRender() (unlock func(), err error)` — non-blocking flock.
- `func (w *Writer) WriteGeneration(runtimeDir, stamp string, files map[string][]byte) error`
- `func (w *Writer) CommitStamps(projectDir string, stamps map[string]string) error`
- `func (w *Writer) Recover(runtimeDir string) error`
- `func (w *Writer) GC(runtimeDir string, currentStamps map[string]string, keep int) error`
- `func GenerationState(runtimeDir, stamp string) (present, complete bool)`
- `func CurrentStamps(projectDir string) (map[string]string, error)`
- `const DefaultGenerationsKept = 3`.
- `fsio.go` (+ build-tagged `fsyncDir`): `writeFileFsync`, `atomicWrite`.

### `internal/compose/snapshot.go`
- `type SnapshotRow`, `type SnapshotPayload{ Rows []SnapshotRow; GenerationStamps map[string]string }`
- `func SaveSnapshot(stateDir string, keys *crypto.LocalKeys, aad crypto.SnapshotAAD, payload SnapshotPayload) error`
- `func LoadSnapshot(stateDir string, keys *crypto.LocalKeys, aad crypto.SnapshotAAD, now time.Time, maxAge time.Duration) (SnapshotPayload, time.Time, error)`
- `var ErrSnapshotExpired, ErrSnapshotRollback`.

### `internal/compose/offlinelog.go`
- `type OfflineRecord{ RecordID, KeyID, KeyName, Classification, OccurredAt, CredentialID, Generation, ServedFrom string }`
- `func NewRecordID() (string, error)` (128-bit hex).
- `func Append(stateDir string, records []OfflineRecord) error` — one fsynced batch
  file before plaintext release; refuses an empty RecordID.
- `func Pending(stateDir string) ([]OfflineRecord, []string, error)`
- `func MarkFlushed(files []string) error`.

### `internal/compose/cursor.go`
- `type CursorState{…}` (JSON).
- `func HashTargetIDs(ids []string) string` (order-independent, length-prefixed).
- `func LoadCursor(stateDir string) (*CursorState, error)` (missing ⇒ nil,nil, strict).
- `func SaveCursor(stateDir string, c CursorState) error` (atomic).
- `func EligibleCursor(state *CursorState, currentStamps map[string]string, runtimeDir, credentialID, env string, configOnly bool, targetIDs []string) (string, bool)` — three-part test.

### `internal/compose/argmax.go`
- `func ExecSizeOK(env, argv []string, limit int) (total int, ok bool)` (`limit-64KiB`).
- `func DefaultArgMax() int` — build-tagged: darwin `sysctl kern.argmax`, other unix
  `RLIMIT_STACK/4` (clamped), windows `32767`.

### `internal/compose/merge.go`
- `type Collision{ Key, InheritedVal, FetchedVal string }`
- `func MergeEnv(inherited []string, fetched map[string]string, allowOverride []string) ([]string, []Collision, error)` — fetched wins; differing collision is a hard error unless in `allowOverride`.

### `internal/compose/doctor.go`
- `type Severity` (`SeverityError`/`SeverityWarn`), `type Finding{ Severity; Code, Message string }`.
- `type ComposeConfig`, `ComposeService`, `EnvFileRef`, `FileMode`, `StateEntry`, `DoctorInput`.
- `func ParseComposeConfig(data []byte) (*ComposeConfig, error)`.
- `func Doctor(in DoctorInput) []Finding` — the full ADR check list, sorted (Code, Message).
- `var ComposeVersionFloor = [3]int{2,30,0}`.

## Decisions taken (brief-sanctioned) and deviations

1. **Writer lock uses `github.com/gofrs/flock` (existing direct dep), not a
   build-tagged `syscall.Flock`/Windows-O_EXCL pair.** *Deviation from the brief's
   prescribed mechanism.* Grounds: gofrs/flock is already a dependency (no new
   dep), is non-blocking cross-platform (`TryLock`), compiles everywhere, and is
   *safer* than the brief's Windows fallback — a crashed process's OS flock
   releases on death, whereas an O_EXCL lock file wedges the lock forever. The
   ADR only requires "a per-project writer lock" (mechanism unprescribed), so
   this is not an ADR conflict. Same-process contention is real because gofrs/flock
   uses `flock()` (per-open-description) on linux/darwin — the two-Writer test
   confirms the second `BeginRender` fails fast.
2. **`HIKYO_*` naming throughout** (env var `HIKYO_GEN_<TARGET>`, state file names,
   HKDF/stamp domain labels). The ADR text says `WENV_*`; the repo is renamed
   hikyo and the brief specifies `HIKYO_*`. Branding, not an ADR conflict.
3. **Managed-block line endings.** Foreign lines in `.env` preserved byte-for-byte
   including CRLF; the managed block's *own* lines always written LF (it is
   generated, not hand-edited). Tested with LF and CRLF fixtures.
4. **`DefaultArgMax` on non-darwin unix uses `RLIMIT_STACK/4`** (glibc's
   `_SC_ARG_MAX` derivation), not `unix.Sysconf`: `golang.org/x/sys/unix` v0.47.0
   exposes `Sysconf`/`SC_ARG_MAX` on Solaris only, so the brief's suggested call
   does not compile cross-platform. Clamped to [128 KiB, 6 MiB]; failed lookup ⇒
   128 KiB conservative floor. darwin reads `kern.argmax` via sysctl.
5. **`SnapshotAAD` list fields (Projection, TargetNames) are inner
   length-prefixed** into one AAD field each, so the list boundary stays
   injective. `IssuedAt`/`ExpiresAt` are bound as the exact server RFC3339
   strings, never re-formatted. New `KindComposeSnapshot` implements the sealed
   AAD interface in-package (amendment 5 is the ADR sanction the aad.go comment
   asks for).
6. **`EncodeRaw` refusals are exactly bad-name / newline / NUL** — no max-length
   re-validation, per the ADR reconciliation ("validation is authoritative at
   publish; delivery does not re-validate"). `internal/schema` is therefore not
   imported.
7. **Ownership checks are the unix leg only.** Windows legs of the crypto
   protection-model check and `fsyncDir` are documented no-ops/weaker (Windows is
   a client platform; the server runs on unix) — mirrors `internal/disclose`.

Where the ADR and the brief could conflict, the ADR wins; the only brief
deviation is #1 (lock mechanism), and #2/#4 are branding/toolchain facts, not ADR
conflicts.

## Deferred (out of this stream)
- Runtime/state directory *resolution* from env (`$HIKYO_STATE_DIR`,
  `$XDG_RUNTIME_DIR`, project slug, ops-spec §6 defaults) is the CLI's job
  (stream C): every primitive here takes resolved absolute paths as inputs, so
  path/env resolution and its golden tests live with the verbs. No
  `DefaultRuntimeDir` shipped, to keep platform/env resolution in one place.
- **Snapshot-AAD persistence (stream C MUST wire).** `OpenSnapshot` needs the
  byte-exact `SnapshotAAD` tuple — including the server's verbatim
  `issued_at`/`expires_at` strings, the sorted projection list, `config_only`,
  the target-name set, and the revision/pin. B persists NONE of these
  (`cursor.json` does not carry them). After a reboot the CLI cannot reconstruct
  the AAD from anywhere, so the offline snapshot is unopenable exactly when it is
  needed. Stream C must persist the AAD inputs alongside `snapshot.bin` (a
  sidecar record, or an extended cursor/state file) or offline serve fails with
  `ErrDecrypt`. Deliberate scope cut, flagged loudly.
- `BeginRender()` intentionally drops the brief's `ctx` parameter: the lock is
  non-blocking (`TryLock`), so there is nothing for a context to cancel. Noted
  rather than left silent.
- All CLI verbs, help/golden, e2e, demo stack — streams C/D.

## Commands run (all from repo root)
- `go build ./... && go vet ./...` → **BUILD+VET OK**
- `gofmt -l .` → **empty (clean)**
- `go test ./internal/compose/... ./internal/crypto/... ./internal/boundary/ -count=1` →
  `ok internal/compose`, `ok internal/crypto`, `ok internal/crypto/backup`,
  `ok internal/boundary`
- `go test ./internal/compose/ -run '^$' -fuzz=FuzzEncodeRawRoundTrip -fuzztime=20s` →
  **PASS** (~4.1M execs, no crashers; fuzz lives in `internal/compose` where the
  encoder lives, adjusting the brief's `internal/crypto` path per its parenthetical)
- Cross-compile spot-check: `GOOS=linux` and `GOOS=windows go build ./internal/compose ./internal/crypto` → both exit 0.

Not run (per brief): isolation/conformance suites; `-race`.

Ready for the orchestrator's blocking cross-model (Codex) review of this
Claude-authored work.

## Stream D

The real-Compose demo lives in `install/compose/demo` and is driven by
`scripts/compose-demo.sh`. It boots a clean loopback dev instance, establishes
and MFA-enrols the bootstrap account, creates the hierarchy and complete
representable raw-dotenv corpus, publishes it, mints an environment-scoped
read-only workload credential, renders, and starts Alpine through Docker
Compose. The script asserts byte-exact container values, refusal-by-name for an
embedded newline with no generation/stamp change, doctor findings, and a
publish → sync → stamp move → container restart round-trip.

Run it from the repository root with `./scripts/compose-demo.sh`. CI runs the
same command in the selective `compose-demo` job after enforcing the Docker
Compose 2.30.0 floor. The required-job checker and changed-path classifier
include the job and its source paths.

The new `/docs/compose/` page documents both delivery mechanisms, setup,
project config, raw dotenv, offline behavior, doctor/sync, token custody,
systemd references, and current limits. The CLI reference now lists `run` and
`compose`; `install/systemd/hikyo-compose-sync.service` and `.timer` provide the
documented five-minute one-shot example.

The missing hierarchy grant is fixed: the bootstrap principal receives
`instance-config` at instance scope and the exact union required by the demo's
tenant operations at org scope: `definitions-edit`, `edit`,
`manage-identities`, `manage-members`, `manage-projects`, `publish`, and `read`.
`project create` and `env create` now succeed, and the demo reaches machine
delivery, render, the embedded-newline refusal, Docker Compose startup, and the
container byte checks.

The apparent leading-whitespace failure was an incorrect demo expectation, not
a CLI defect. The schema ADR requires Go `strings.TrimSpace` on every write
path, followed by byte-exact storage and delivery. The demo now computes the
expected stored value with the same Unicode whitespace set and compares those
stored bytes with the container's delivered bytes. Its leading- and
trailing-whitespace rows prove that trimming is the only transformation;
`allow_empty: true` also makes an empty post-trim value representable.

The complete local run passes hierarchy creation, all 20 representable corpus
values plus `GREETING`, publication, machine delivery, render, the named
embedded-newline refusal with exit 4 and unchanged generation/stamp, Docker
Compose startup, the doctor allowlist, publish-to-sync stamp movement, and the
container restart assertion. Its terminal evidence is:

```text
compose demo passed: 21 stored values including GREETING delivered byte-exactly; surrounding whitespace proved trim-only transformation
compose demo passed: embedded newline refused by name with exit 4 and no generation/stamp change
compose demo passed: doctor returned only allowed findings; sync moved the stamp and restarted app
```

Final run time: `real 95.08s` (`user 8.16s`, `sys 5.53s`). No Go change or
API/datastore bypass was needed.
