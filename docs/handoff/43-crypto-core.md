# Handoff: #43 crypto core

Issue: https://github.com/Dunky13/hikyo/issues/43 (parent #41). Specs:
`docs/adr/encryption-model.md` (incl. secret-scanning + flat-model amendment
banners) and `docs/adr/system-architecture.md` § Encryption boundary, both on
`wayfinder-docs`.

## What exists

- `internal/crypto` — the envelope package, sole crypto chokepoint, and a
  **leaf** (imports nothing under `internal/`; persistence arrives through
  its `KeyStore` interface):
  - `aad.go` — injective length-prefixed encoding (uint32 BE length + bytes,
    absent = length zero) and the **six** per-kind AAD schemas. `value`
    binds `env_id` per the flat-model amendment.
  - `envelope.go` — versioned header (`format ‖ kind ‖ alg ‖
    LP(wrapping_key_id) ‖ key_version ‖ LP(nonce)`), header authenticated as
    AAD prefix, XChaCha20-Poly1305 (`chacha20poly1305.NewX`), random 192-bit
    nonce, strict bounds on parse. RNG failure/short read aborts every seal.
  - `keyring.go` — root→master→tier-3; first boot mints master + instance
    DEK + root token key in one `CreateHierarchy` transaction; project DEKs
    minted on demand, unwrapped into a bounded LRU (128, ops-spec value);
    mint races converge on the winner via `ErrKeyExists`. Scoped sealers
    make invariant 16 structural: `ForProject` only takes `value` /
    `project_field` AADs matching its org+project; `ForInstance` only
    `instance_field`.
  - `rootkey.go` — hex-64 encoding fixed; file source checks `mode & 0o077`;
    distinct errors per startup refusal (no key / perms / format /
    mismatch / unknown format version). Root key zeroed by `LoadKeyring`,
    success or failure.
  - `token.go` — `ScopedTokenKey` = stdlib HKDF-SHA256 over the LP-encoded
    `(label, org, project, env)` info; derived per use, never cached.
  - `harden_unix.go` — `RLIMIT_CORE=0` on unix, `PR_SET_DUMPABLE=0` on
    Linux, called first thing in server `Boot`. Windows builds (client
    verbs) get a documented no-op.
- `internal/store/keyring` — `crypto.KeyStore` over the datastore: reads on
  the read pool, creation through `tx.Write` with
  `TouchHierarchyGeneration` (pg `SELECT … FOR UPDATE`) in the same
  transaction. `internal/store/keys.go` maps rows ⇄ `crypto.WrappedKey`
  (blobs only), unique violations ⇄ `crypto.ErrKeyExists`, no-rows ⇄
  `crypto.ErrNoKey`.
- Migration `00002_keyring` (both dialects): `master_keys` — a row is one
  **wrapper** of one master version under one root epoch, PK
  `(version, root_key_epoch)`, so the dual-wrapped root-rotation transition
  state is representable and boot tries every active wrapper (unknown
  format version still aborts, refusal 5, even if another wrapper opens);
  `tier3_keys` (purpose CHECK includes reserved `'scanning'`; no FK on
  `master_key_version` — versions stop being unique rows once dual-wrapped,
  the in-fence check below replaces it); `key_generations` with the seeded
  `'hierarchy'` row; partial unique indexes enforce one active wrapper per
  epoch and one active key per tier-3 scope. The five rotation operations,
  retirement and zero-reference checks are the rotations ticket's.
- The hierarchy fence has teeth: `CreateTier3` verifies, inside the
  transaction with the generation row held, that the key's
  `MasterKeyVersion` is still the active master — `crypto.ErrStaleMaster`
  otherwise (invariant 9's writer-race, structurally refused; unreachable
  until rotations land).
- Wiring: `app.Boot` = harden → migrate → root key → store → keyring →
  listen. `hikyo migrate` and client verbs never touch any of it.
- `internal/boundary` — invariant 12: `golang.org/x/crypto/*`,
  `crypto/cipher`, `crypto/aes`, `crypto/hkdf`, `crypto/hmac` importable
  only by `internal/crypto`; `filippo.io/age` only by the future
  `internal/crypto/backup`; `internal/crypto` is a leaf. `crypto/sha256`
  and `crypto/subtle` deliberately unrestricted (verifier hashing is not
  envelope encryption).

## Invariants covered (encryption ADR § CI-enforced)

1 (dump grep, incl. root-key bytes), 3 (transplant incl. cross-environment
and cross-kind), 4 (header tamper, every byte + truncations), 5 (AAD
injectivity + strict header bounds), 6 (startup refusals, distinct errors),
10 (scoped-token-key injectivity), 11 (ciphertext uniqueness), 12
(chokepoint), 14 (RNG failure fatal), 16 (project/instance routing —
structural + cross-domain test). Deferred with their tickets: 2 (auth), 7–9
+ 15 (rotations), 13 (backup).

## Verified empirically

- Full suite green on sqlite + postgres 18 (local container), incl. the
  keyring conformance scenarios on both engines.
- `hikyo server --dev` clean dir: generates `hikyo-dev.rootkey` (0600, warned
  loudly), healthz/readyz 200; reboot reuses the key.
- `hikyo server` with DB but no root key: refuses, names the fix.
- `hikyo migrate` with no root key anywhere: succeeds.

## Deliberate deviations (for human disposition)

1. **`--dev` generates a persisted root key** (`hikyo-dev.rootkey` beside the
   dev db, 0600, loud warning) — deviates from encryption-ADR refusal 1
   ("server never auto-generates a root key"), forced by the architecture
   ADR's zero-config `--dev`. Non-dev boots enforce refusal 1 verbatim, no
   override flag. Rationale in `app.resolveRootKey`'s comment.
2. **Six envelope kinds, not seven.** The architecture ADR's "seven per-kind
   AAD schemas" is stale text; the encryption ADR's normative table has six
   and the scanning amendment explicitly adds no new schema.
3. Master key at first boot is minted by the server (root key present,
   operator-held) — `hikyo init` (#25) will front-run this later; refusal 1
   covers the *root* key only.

## Review trail

In-house two-axis review (Standards + Spec sub-agents): 2 hard findings
fixed (DEK-eviction zeroing under a live sealer — regression-tested; golden
known-answer vector pinning the wire format) plus smell cleanups.
Cross-model (Codex `gpt-5.6-sol`, high effort, 3-round protocol): R1 found
1 blocker + 3 major + 1 minor (dual-wrap representability, fence teeth,
root-key byte-path zeroing, Windows build, vacuous race test) — all fixed;
R2 found one residual blocker (valid wrapper masking an unknown-format
wrapper, refusal 5) — fixed; **R3: CLEAN**.

## Pickup notes

- Root key encoding is fixed: 64 hex chars, whitespace-trimmed. `hikyo init`
  (#25) should use `crypto.GenerateRootKey`/`EncodeRootKey`.
- Rotations ticket: `WrappedKey` has no state field on purpose — only
  'active' rows exist yet; add state transitions in store when retirement
  lands. `TouchHierarchyGeneration` is the fence acquisition point; sqlite
  relies on the single write connection + BEGIN IMMEDIATE.
- The DEK cache has no eviction API yet — rotation/project-delete tickets
  add it with their operations.
- `app.Server.keyring` is held but unconsumed until the first
  value-bearing ticket (flat model).
