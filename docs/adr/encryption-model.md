# Envweave encryption model (ADR, locked 2026-07-30)

Context: Envweave stores secret values and hands them to workloads in plaintext, so the server must be able to decrypt — no zero-knowledge claim is available or attempted. The threat model ([#8](https://github.com/Dunky13/envweave/issues/8), [threat-model.md](./threat-model.md)) fixed the guarantee this ADR must deliver: theft of the database or a backup **without the root key** yields no secret values and no replayable stored credentials; it delegated every mechanism — AEAD choice, associated-data binding, nonce rules, key lifecycle, ciphertext versioning, replay/swap defence, rotation completion and failure atomicity — to this ticket. The encryption research ([#4](https://github.com/Dunky13/envweave/issues/4), [encryption-architectures.md](../research/encryption-architectures.md)) surveyed Infisical, Vault/OpenBao, Bitwarden, Kubernetes etcd encryption, age and SOPS, and established field-level envelope encryption as the only design that behaves identically on sqlite and postgres. This ADR fixes the concrete architecture.

**Amends the revision ADR ([#11](https://github.com/Dunky13/envweave/issues/11)).** [revision-model.md](./revision-model.md) offered the operations spec a choice between a backup-retention bound and "per-revision cryptographic erasure". **The second option is unavailable under this architecture** — the key hierarchy travels inside every backup, so destroying a live key erases nothing already written (§ *Erasure, and why crypto-shredding is not retention*). The retention bound is mandatory in v1, not one of two alternatives.

**Amends the threat model ([#8](https://github.com/Dunky13/envweave/issues/8)).** Trust boundary 5 specifies "age-encrypted exports". The backup container is now a stdlib construction (§ *Backups and exports*); the property the threat model required — an export encrypted to a backup identity **distinct from the root key and stored separately**, with restore requiring both — is unchanged. Mechanism differs, guarantee does not.

Granularity note: this is the wayfinding-level encryption ADR. It fixes the key hierarchy, primitives, envelope format, binding, bootstrap, rotation semantics, the encrypted-field set, the backup container, and the honest compromise statement. Mechanism-level detail is delegated: concrete bounds, quotas, retention defaults and the backup/restore runbook → operations spec; token and credential formats → machine identities ([#17](https://github.com/Dunky13/envweave/issues/17)); which capability gates `reveal`, rotation and restore → RBAC ([#15](https://github.com/Dunky13/envweave/issues/15)); password KDF parameters and session mechanics → human auth ([#16](https://github.com/Dunky13/envweave/issues/16)); which crypto events are audited → audit ([#24](https://github.com/Dunky13/envweave/issues/24)); command surface for `init`, `rotate-root-key`, `rotate-dek`, `reencrypt`, `export`, `restore` → API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25)); language choice and the crypto package's place in the codebase → architecture ([#22](https://github.com/Dunky13/envweave/issues/22)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## Key hierarchy — three tiers

1. **Root key (KEK)** — 256-bit, operator-provided, **never stored in the datastore**. Wraps tier 2 only.
2. **Master key** — 256-bit random, generated at first startup, stored wrapped in a single versioned row. Wraps tier 3 only.
3. **Tier-3 keys** — 256-bit random, stored wrapped by the master key, versioned:
   - one **DEK per project**, covering every layer of that project (project-defaults, base chain, environment) — a project is one key domain;
   - one **instance DEK** for sensitive rows belonging to no project (MFA seeds, recovery codes, instance-level adapter credentials);
   - one **root token key**, used for derivation only and never for encryption (below).

Per-project granularity buys blast-radius isolation, per-project rotation and crypto-shred on project delete. Per-environment DEKs were rejected: project-defaults-layer values belong to no environment, so a per-environment scheme requires the per-project scheme underneath it — it adds a tier rather than replacing one. Per-value DEKs were rejected; see § *Erasure*.

**Per-project routing through an external KMS is explicitly NOT promised by this hierarchy.** Infisical offers it ([security internals](https://infisical.com/docs/internals/security)), and it is tempting to claim per-project DEKs make it free. They do not: per-project KMS unwrapping requires a provider identifier and a per-project key reference in the wrapped-DEK record, and the tier-3 wrapping would no longer be master→DEK. Neither is in the format below. The KMS seam this ADR reserves is **at the root-key boundary only** (§ *Root-key bootstrap*), where one blob is wrapped and the change is invisible to every ciphertext. Per-project KMS routing is a future **format version**, not a drop-in.

**The root token key is a distinct tier-3 key, not a DEK derivation.** The revision ADR fixes the change token as `HMAC(scoped token key, canonical encoding of delivered content)` with the scoped key derived "from a server root token key" ([revision-model.md § Two identifiers](./revision-model.md)). Envweave therefore holds a **root token key** — 256-bit random, wrapped by the master key, sibling to the DEKs and **never used for encryption**. Per-scope keys are derived on demand and never stored:

```
scopedTokenKey = HKDF-SHA256(rootTokenKey, info = LP("envweave/change-token/v1", org_id, project_id, env_id))
```

`LP(...)` is the **same length-prefixed canonical encoding** mandated for associated data (§ *Envelope format*), and it is load-bearing here for the same reason: raw concatenation lets `(org "a", project "bc")` and `(org "ab", project "c")` derive the identical key, which would resurrect precisely the cross-scope equality oracle the revision ADR keyed the token to eliminate.

Deriving these from a **project DEK** instead was considered and rejected: DEK rotation is a routine, operator-initiated hygiene operation, and coupling it to the token key would silently change every change token in the project, driving a full rollout wave of every workload in every environment as an invisible side effect of key hygiene. The revision ADR permits exactly one such wave, on deliberate **token-key** rotation, and requires the operations spec to call it out. Separating the keys keeps encryption rotation and delivery churn independent.

Any future per-purpose key follows the same rule — a distinct tier-3 key with its own purpose, derived per scope with a domain-separated `info` label, never overloaded onto a key that already has a job.

## Primitives — AES-256-GCM, stdlib only

**AES-256-GCM** for every layer, from `crypto/aes` + `crypto/cipher`. **XChaCha20-Poly1305 was rejected** despite being the research's recommendation: it lives in `x/crypto`, is not FIPS-approved, and Envweave keeps FIPS 140-3 alignment reachable. Go 1.24+ ships a natively validated FIPS 140-3 module covering stdlib crypto behind a toolchain flag (`GOFIPS140`), so **every primitive inside Envweave's security boundary MUST come from the standard library** — that is the price of the open door, and it binds the backup container too (§ *Backups*).

**What that door does and does not open, precisely.** This preserves FIPS eligibility for the **cryptographic subsystem**, not compliance for Envweave as a product. Three limits, all stated rather than implied. Go's own documentation is explicit that using the module *facilitates* compliance — the operating environment, the certified module version, the runtime mode, and application-level usage all still matter. A **product FIPS profile does not exist yet** and is not defined here. And the threat model mandates **Argon2id** for human password verifiers, which is neither stdlib nor FIPS-approved: a whole-product FIPS build therefore requires the human-auth ticket ([#16](https://github.com/Dunky13/envweave/issues/16)) to select an approved KDF for that profile. Until then, "FIPS-ready" is a claim about this subsystem only, and documentation must not upgrade it.

The 96-bit GCM nonce is safe for ~2³² encryptions per key. Envweave does not budget that ceiling; it removes it.

**Per-record derived keys.** Every seal generates a fresh 256-bit random salt and derives a single-use record key:

```
salt      = 32 random bytes
recordKey = HKDF-SHA256(dek, salt, info = "envweave/record/v1")
nonce     = 12 random bytes
ct        = AES-256-GCM(recordKey, nonce, plaintext, aad)
```

Each record key is used for exactly one message. Both HKDF-SHA256 (SP 800-56C) and AES-256-GCM are FIPS-approved and both are stdlib (`crypto/hkdf`, Go 1.24+). Cost is 32 bytes per ciphertext and one KDF call.

**The property this delivers, stated exactly.** Catastrophic GCM nonce reuse requires a collision in **both** the 32-byte salt and the 12-byte nonce — 352 bits of fresh randomness per record — so with a healthy CSPRNG it is negligible. It is **probabilistic, not structural**: a salt collision alone reuses a record key, after which nonce uniqueness matters again exactly as it would without the derivation. Compared to raw per-DEK GCM this replaces a *birthday bound reached by counting* (2³² records) with one *reached only by RNG failure*, which is the improvement claimed and the only one claimed.

Two consequences follow and must not be elided. **`crypto/rand` failure must be fatal** at every seal — a degraded or short read aborts the operation, never proceeds with weak randomness. And **RNG rollback breaks the property**: restoring a VM snapshot or forking a container image can replay the CSPRNG state and repeat salt and nonce together. This is an operations-spec hazard (documented alongside restore), not something the crypto layer can detect.

**Rejected:** usage counters with rotation thresholds (makes every encrypt's safety depend on a counter write succeeding under concurrent writers); deterministic nonce construction (a restore-from-backup rewinds the counter, and GCM nonce reuse on one key is catastrophic — the threat model makes restore a first-class event, so this is a trap, not a trade-off).

## Envelope format and AAD binding

Every ciphertext — wrapped keys and data alike — carries a versioned header:

```
header = format_version ‖ envelope_kind ‖ algorithm_id ‖ key_id ‖ key_version ‖ salt ‖ nonce
record = header ‖ ciphertext ‖ tag
```

The header is **authenticated as part of the AAD**, so format version, envelope kind, algorithm id and key version cannot be edited independently of the payload.

**Encoding is injective, and that is normative.** Concatenation of variable-length fields is ambiguous — `a ‖ b` cannot be distinguished from `a' ‖ b'` when the split moves. Every AAD is therefore a **length-prefixed sequence**: each field emitted as a `uint32` big-endian byte length followed by its bytes, absent fields emitted as length zero, field order fixed by the schema for that envelope kind, no separators, no text formatting. A conforming implementation MUST reject a header whose declared lengths do not consume the buffer exactly.

**There is one AAD schema per envelope kind, not one universal tuple.** The `envelope_kind` byte selects it, so identifiers from different tables can never collide into the same context:

| Kind | AAD fields after the header |
|---|---|
| `value` | `org_id`, `project_id`, `layer_id`, `key_id`, `row_id`, `field_tag` |
| `wrapped_dek` | `org_id`, `project_id` (empty for the instance DEK), `dek_id`, `dek_version`, `master_key_version` |
| `wrapped_master` | `master_key_version`, `root_key_epoch` |
| `wrapped_token_key` | `token_key_version`, `master_key_version` |
| `instance_field` | `owner_table`, `owner_row_id`, `field_tag` |
| `backup_payload` | container header digest (§ *Backups*) |

`layer_id`, **not** `env_id`, for `value` — inheritance-ADR values live on layers and project-defaults has no environment; binding to `env_id` would leave that layer unbound.

**Identifiers bound into an AAD are immutable and never reused.** A table that renumbers rows, reuses a freed id, or moves a row between tables during a storage migration renders its existing ciphertext undecryptable. This constrains every future migration and belongs in the architecture ADR's schema rules, not only here.

The attack this defeats is intra-project, not merely cross-tenant: a datastore writer copies a production ciphertext onto a development-layer row for a key they legitimately hold `reveal` on, then asks the server to decrypt it. Cross-org or cross-project binding alone does not stop that; row-anchoring makes a ciphertext decryptable at exactly one row and one column and nowhere else. Every AAD component is already a column on the row being decrypted, so the binding costs nothing.

Consequence, accepted: **any operation that produces a new row re-encrypts; a ciphertext is never copied between rows.** This covers copying a value to another environment, re-keying, and — importantly — **rollback**. The revision ADR is explicit that restoring an earlier state "creates a **new** revision through the normal publish pipeline", staging pending changes owned by the restoring user, and that restoring an inherited value flattens it into a local override ([revision-model.md § Rollback](./revision-model.md)). There is no existing row to point at: the target layer differs, the row id differs, so the AAD differs and the value must be decrypted and re-sealed.

That re-encryption is an **internal server operation, not a disclosure**: the server decrypts and re-seals without rendering plaintext to any principal, so restoring a secret requires no `reveal` capability. This preserves the revision ADR's rule that a principal may restore a secret value while holding only write-presence over it.

**Residual, documented:** AAD prevents *transplant*. It does not prevent *deletion*, nor *resurrection of a row's own earlier ciphertext*. An actor who can do either already holds datastore write access and is operator-equivalent under the threat model. "AAD-bound" must never be presented in documentation as "tamper-proof".

## Root-key bootstrap

`ENVWEAVE_ROOT_KEY` (env var) or `--root-key-file` (path), 256-bit. `envweave init` generates the key, prints it exactly once with a blunt instruction to store it off this machine, and creates the wrapped master key. Unattended restart works — Shamir/manual unseal was rejected as the wrong default for single-node self-hosting, and passphrase-derived roots for the same reason.

Startup refusals, all **hard failures with no override flag**:

1. **No root key present** — abort. The server never auto-generates a root key on first run: a silently generated key is a key nobody backed up, discovered at restore time.
2. **Key file readable by group or other** — abort. One `os.Stat` check.
3. **Not exactly 256 bits after decoding** — abort. No padding, no stretching, no derivation from a short string. (Infisical's 128-bit default is the anti-pattern the research flagged.)
4. **Master key's GCM tag fails to verify** — abort with "root key does not match this datastore". Never a partial boot.
5. **Datastore contains a master key wrapped at an unknown format version** — abort rather than guess.
6. **Backup export with zero configured recipients** — refuse (§ *Backups*); never silently write plaintext.

**Env-var delivery is supported but documented as the weakest tier**: the value is visible in `/proc/<pid>/environ`, `docker inspect`, and process listings for the process's whole lifetime, which also defeats the root-key wipe in § *Key material in memory*. Documentation steers to the file path and to systemd `LoadCredentialEncrypted` (TPM2- or host-key-bound, unattended restart *and* offline-theft protection, **zero Envweave code** since the key still arrives as a file) — always paired with an escrowed copy, because TPM-bound blobs die with the mainboard.

**External KMS is interface-reserved, not implemented, in v1.** A `wrap(keyBytes) / unwrap(blob)` seam sits at the root-key boundary with one local implementation. That is the entire contract, so Vault transit, AWS/GCP KMS, or a hardware-backed provider become drop-ins with no data migration. Shipping one in v1 means shipping and testing cloud credential handling for a userbase that self-hosts to avoid it. The OpenBao failure mode is documented against the future provider: permanent KMS loss without recovery material means unrecoverable data.

Deployment-docs requirement, restated from the threat model: **the root key must not share a backup or storage domain with the database.**

## Rotation

Five operations across the three key tiers; all ship in v1, all **operator-initiated** — nothing auto-rotates, because § *Primitives* removed the usage-count trigger that would justify it.

- **`rotate-root-key`** — replace the operator-held root. Re-wraps the master key only; no data touched. Crash-safe protocol below. This is the rotation operators actually need after an env-file leak.
- **`rotate-master-key`** — generate a new master key and re-wrap **every** tier-3 key (all project DEKs, the instance DEK, the root token key) under it. Retire the old master only after a fenced zero-reference check. Bounded by the number of projects, so seconds.
- **`rotate-dek --project X` / `--instance`** — append a new DEK version. New writes use it; old versions remain readable (Vault keyring semantics). Free, and incomplete on its own.
- **`rotate-token-key`** — new root token key version. Changes every change token, so it forces exactly one benign rollout wave across every workload; the revision ADR permits that wave and requires the operations spec to document it. Separate command precisely so it is never a side effect of another rotation.
- **`reencrypt --project X` / `--instance`** — walk every ciphertext onto the current version, then retire the old one. **Resumable and per-row transactional**: interrupt and re-run; rows already current are skipped. No global lock. Scope is **every ciphertext including historical revision payloads and pinned revisions** — a rotation that skips history is not one.

**`rotate-master-key` is not optional, and its absence would have made post-compromise recovery a fiction.** The threat model's recovery posture after a running-server compromise is to rotate *everything*. An attacker who held the process memory holds the **master key**; every DEK — including DEKs minted after the incident — is wrapped under it, so rotating the root re-wraps the same compromised master and rotating a DEK produces a new key the attacker can still unwrap. Recovery is therefore ordered and complete, each key named exactly once:

1. `rotate-root-key` — new operator-held root.
2. `rotate-master-key` — new master; every tier-3 key re-wrapped under it.
3. `rotate-dek` for every project and `--instance` — new DEK versions.
4. `reencrypt` every project and the instance scope — retire the compromised DEK versions.
5. `rotate-token-key` — **last, and once**, because it is the only step that forces a rollout wave. Deferring it to the end means the wave happens after the data is safe, and running it exactly once means there is exactly one wave.

Nothing less restores confidentiality against that attacker for future datastore copies. Steps 3–5 are the "new versions of every tier-3 key" — the root token key is one of them, ordered last for the rollout reason, not rotated twice.

**Key-state changes are fenced, at two levels, because a per-scope fence alone does not compose.** A writer that resolved the old DEK version before rotation could otherwise commit its row *after* the zero-reference query and strand a ciphertext under a retired key. Worse, a *scope*-level fence cannot order a scope-local operation against a hierarchy-wide one: creating a project DEK concurrently with `rotate-master-key` can wrap a brand-new tier-3 key under the master being retired, which the retirement's zero-reference check has already passed.

So:

- **Scope generation** — guards tier-3 key state for one project or the instance scope (version append, retirement). Writers carry the generation they resolved; a stale commit is rejected and retried against the current key; the zero-reference check runs inside the fence.
- **Hierarchy generation** — guards the tier-1 and tier-2 state (root rotation, master rotation) and is acquired by **any tier-3 key creation or version append**, which therefore serializes against master rotation. Master rotation's zero-reference check over tier-3 keys runs inside this fence, so no tier-3 key can appear under a retiring master after the check.

**`rotate-master-key` is refused while the root is dual-wrapped**, and `rotate-root-key --prepare` is refused while a master rotation is in flight. Allowing them to interleave would require dual-wrapping the new master under both roots to preserve the "either root boots" guarantee, and that state — two masters times two roots — is a four-way matrix nobody will reason about correctly at 3am during an incident. Refusing the overlap costs an operator one `--finalize` and removes the matrix. The recovery order above already runs them sequentially.

"No global lock" means no lock over *data*. Key-state transitions are serialized: per scope for tier-3, hierarchy-wide for tier-1 and tier-2.

**A key version is retired only when zero ciphertexts reference it, verified by query inside the fence, never assumed.** Retiring a still-referenced version is refused loudly; this is the Kubernetes "mistakes can make data unrecoverable" failure mode, and a count query prevents it.

**Root-key rotation is crash-safe across two storage domains.** The wrapped master lives in the datastore; the root key lives in a file, environment, systemd credential or secret mount that no database transaction can update atomically. Writing either side first has a failure window that bricks startup. So rotation is a three-phase protocol over a **dual-wrapped master**:

1. **prepare** — store the master wrapped under *both* the old and the new root, each tagged with its `root_key_epoch`. Both rows committed before the operator touches the key source.
2. **verify** — the operator installs the new root; `rotate-root-key --verify` confirms the new wrapper unwraps to the same master key.
3. **finalize** — delete the old wrapper and advance the epoch.

**Startup accepts any root key that unwraps any present wrapper**, so a crash at any point leaves the instance bootable with either the old or the new key. An instance left in the dual-wrapped state boots normally and **warns on every start** until finalized — a rotation half-done is a rotation not done, and it must be visible rather than silent.

Lazy-only rotation was rejected: without the eager pass, old-key ciphertext survives forever and the word "rotated" in the documentation is false. At the v1 scale envelope (≤10k entries) the eager pass takes seconds.

**Rotation cannot protect a copy that was already readable when it was taken.** Documentation must state this plainly rather than let "rotate and re-encrypt" imply retroactive protection. The quantifiers matter, so all three cases are stated separately:

- **Root key leaked, no datastore copy in the attacker's hands** → re-wrapping the master key is sufficient **provided the accounting is complete**: every raw backup, snapshot, replica, and any dual-wrapped transition state still carrying a wrapper under the old root must be inventoried, since each is a copy the old key still opens. Rotation protects nothing the operator forgot to enumerate.
- **Root key leaked and a matching datastore copy taken** → that pair is already readable. No rotation changes it; re-encryption protects **future** copies only.
- **Datastore copy taken while the attacker had no root key** → rotating the root **does** protect that copy against a *later* theft of the current root, because the stolen copy stays wrapped under the retired root. This is a genuine win and the reason rotation after a suspected dump exfiltration is worthwhile — the blanket phrasing "rotation does not protect what is already stolen" would wrongly discard it.

Re-encryption earns its place after a **running-server compromise**, where master-key and DEK plaintext were within the attacker's reach, and it is only effective as the last step of the full recovery order above.

**Secret-value rotation** — rotating the actual credential at its provider — is a product feature, not encryption at rest, and is out of scope here.

## What is encrypted

**Every Value, of both classifications**, current and historical, plus:

- MFA seeds and recovery codes;
- adapter / deployment-module outbound credentials and provider config secrets.

Encrypting `config`-classified values as well as `secret` ones is deliberate. The schema ADR permits reclassification `config → secret`; if `config` values were plaintext, every historical row written before that moment would remain plaintext in the datastore and in every backup already taken, and the reclassification would protect nothing that already exists. It also keeps classification out of the envelope layer entirely — no `if classification == secret` branch in the one place where a wrong branch is unrecoverable. The cost is one AEAD call on a `DATABASE_HOST`.

**Not encrypted, documented as exposed to datastore theft** (consistent with the threat model's secondary-asset stance): org, project, environment, folder and key names; descriptions; JSON Schema declarations and patterns; presence state; revision lineage metadata; audit metadata; timestamps; ciphertext sizes.

**Session and service-account tokens are hashed verifiers, not ciphertext** — fixed by the threat model, and correct: a hash cannot be reversed by a root-key holder.

Two consequences, recorded rather than discovered later:

1. **No SQL predicate can touch a value.** Value search or filtering means decrypt-and-scan, server-side, authorization-checked per value. Acceptable at ≤10k entries; not acceptable at 10M, which is outside the v1 scale envelope.
2. **No length padding in v1.** Ciphertext length leaks approximate value length — already an accepted metadata exposure. Padding buckets are the extension path; documentation must not imply constant-size ciphertext.

## Backups and exports

`envweave export` produces a container holding the already-field-encrypted datastore export, encrypted again to one or more **operator-held recipients**. The recipient wrapping is **`crypto/hpke`** (Go 1.26+), RFC 9180 base mode, ciphersuite **DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM** — a specified KEM with published test vectors rather than a hand-composed ECDH-to-AEAD path:

```
header       = LP(magic, format_version, recipient_count, stanza_0 … stanza_n, payload_length)
fileKey      = 32 random bytes
headerDigest = SHA-256(header)

stanza (hpke)       = LP(recipient_kind, recipient_fingerprint,
                         hpke.Seal(pk_i, HKDFSHA256, AES256GCM,
                                   info = LP(domain, magic, format_version, recipient_fingerprint),
                                   fileKey))
stanza (passphrase) = LP(recipient_kind, pbkdf2_salt, pbkdf2_iterations, wrap_nonce,
                         AES-256-GCM(PBKDF2-HMAC-SHA256(passphrase, pbkdf2_salt, pbkdf2_iterations, 32),
                                     wrap_nonce, fileKey,
                                     aad = LP(domain, magic, format_version, pbkdf2_salt, pbkdf2_iterations, wrap_nonce)))

payload   = envelope record, envelope_kind = backup_payload, key = fileKey,
            aad = header schema for that kind, i.e. LP(headerDigest)
container = header ‖ payload
```

The payload is **an ordinary envelope record** (§ *Envelope format*), not a bespoke construction — so its format version, algorithm id, salt and nonce are carried and authenticated by the standard header exactly as every other ciphertext's are, rather than being referenced and never serialized. That also resolves the `backup_payload` row of the AAD-schema table instead of contradicting it: the file key takes the place of a DEK, and the per-record HKDF derivation of § *Primitives* applies unchanged.

Fixed by this ADR, because "same envelope layer" does not answer them — a file container has no row identity to anchor to:

- **Ephemeral key material and encoding** are HPKE's, not Envweave's. No custom KEM.
- **Domain separation** — the HPKE `info` is a constant domain string concatenated with the header prefix, so a stanza cannot be lifted into another container.
- **Recipient fingerprint** — SHA-256 over the recipient's public key, present so restore can select a stanza without trial decryption, and authenticated as part of the stanza.
- **Whole-header binding** — the payload record's AAD is a digest over the complete header including every stanza and the recipient count, so a stanza cannot be added, removed or reordered.
- **Strict parsing bounds** — declared lengths must consume the buffer exactly; a recipient count, stanza length or payload length beyond configured maxima is rejected before allocation.
- **Every stanza is self-describing and authenticated.** A passphrase stanza carries its own salt, iteration count and wrapping nonce in the clear *and* under its AEAD's associated data, so an attacker cannot downgrade the work factor by editing the plaintext copy. There is no implicit parameter anywhere in the container.
- **Single-shot payload with a hard size cap** (bound set by the operations spec). Above the cap, export refuses rather than silently degrading. This deliberately removes chunk framing, ordering and truncation-detection from the v1 format: authenticated decryption must buffer to verify the tag regardless, and streaming decryption is the standard route to releasing unverified plaintext during a restore. Chunked framing is the documented upgrade path at a new `format_version` if dumps outgrow the cap.
- **Passphrase recipients** are a distinct `recipient_kind`, fully specified above: PBKDF2-HMAC-SHA256 over a 16-byte random salt derives a 32-byte wrapping key that seals `fileKey` under AES-256-GCM with its own nonce; salt, iteration count and nonce are serialized and authenticated; the iteration count must meet a documented minimum work factor, enforced on **read** as well as write so a downgraded container is refused; passphrases are NFC-normalized UTF-8. Documented as the weakest recipient kind. Argon2id is unavailable here — neither stdlib nor FIPS-approved (§ *Primitives*).

**`filippo.io/age` was rejected**, reversing the research recommendation. Its format solves genuinely more of this surface — STREAM chunking, stanza handling, passphrase and hardware-plugin recipients, independent tooling — and it is the better choice for any project that does not care about FIPS. It loses here on one point: X25519 and ChaCha20-Poly1305 are outside the stdlib FIPS boundary, so adopting it would permanently forfeit the door § *Primitives* deliberately bought, for a subsystem where `crypto/hpke` supplies a specified, test-vectored alternative. Its secondary advantage also does not survive this design — "restore with the standard `age` CLI" yields a dump whose every value is still root-key ciphertext, so Envweave is required either way. **This trade is worth revisiting if a product FIPS profile is ever abandoned** (§ *Primitives*); it is the ADR's most reversible decision, since the container is versioned and only ever read by Envweave.

**tink-go** was likewise rejected for this container, on the same grounds as § *Implementation seam*.

Shipping no backup encryption at all — leaving it to restic/borg/kopia — was considered and rejected: the export's **metadata** (§ *What is encrypted*) is the infrastructure map in plaintext, and an unconditional encrypted artifact beats one contingent on the operator having configured their backup tool correctly. It also gives instance migration a first-class artifact.

**The instance stores only public recipients.** The backup private identity never touches the datastore. **Restore requires the identity and the root key, separately** — two failure domains, as the threat model requires: the identity decrypts the container, the root key decrypts values. Restore's fail-closed recovery mode (invalidating every pre-restore authentication artifact) is the threat model's requirement and the operations spec's procedure; this ADR supplies only the cryptography.

## Erasure, and why crypto-shredding is not retention

**In this design, key destruction cannot retroactively protect a backup that has already been written.** Destroying a key — a revision's, a DEK version's, or an entire project's — removes it from the *live* datastore only. Every retained backup contains the wrapped key hierarchy alongside the data, so anyone holding that backup plus the root key reads the supposedly erased value. This is the same asymmetry as § *Rotation*'s stolen-copy rule.

**This is a property of the chosen architecture, not a law.** Cryptographic erasure is achievable in general by holding the key material **outside** the backup domain — an external KMS or HSM whose keys are deliberately excluded from every export, so destroying the external key bricks every retained copy at once. That is a coherent design; it is rejected for v1 because it makes the KMS a hard availability dependency for restore (the OpenBao failure mode: KMS gone means data gone, backups included) and v1's KMS seam is interface-reserved, not implemented (§ *Root-key bootstrap*). If a KMS provider ever ships, per-scope erasure becomes reachable and this section should be revisited rather than re-derived.

For v1, therefore:

- **Per-revision cryptographic erasure is not offered**, and per-value DEKs would not deliver it if it were.
- **Crypto-shred on project delete** is retained, correctly scoped: destroying a project's DEK after its rows are gone protects **future** copies of the datastore, not retained ones.
- The construction that *does* erase history is **destroying a backup container's recipient identities** — but only under conditions that must be stated, because "destroy the identity" is easy to believe and hard to achieve. Erasure of a container holds only when **every** identity capable of opening it is gone: each recipient private key, every escrowed or offline copy, every hardware token holding one, and any passphrase recipient's passphrase wherever it is written down or memorized. **One surviving recipient defeats erasure entirely.** Conversely a shared identity spans containers, so destroying it erases every backup wrapped to it, including ones the operator meant to keep. Recipient-set hygiene — one identity per retention class, inventoried — is an operations-spec requirement, not a detail.

**Binding on the operations spec, sharper than the revision ADR's version:** payload GC retires a secret from the live datastore only; retiring it from history requires **deleting the backups, or destroying every identity that opens them** under the conditions above; the **backup-retention bound is mandatory in v1**, because the cryptographic alternative the revision ADR offered is unavailable in a design where the key hierarchy travels inside the backup.

## Implementation seam

The envelope layer is **hand-rolled over stdlib** — header struct, injective AAD encoder, `seal(ctx, plaintext)` / `open(ctx, ciphertext)`, keyring lookup, HKDF derivation. Recipient wrapping for backups is **not** hand-rolled; it is `crypto/hpke` (§ *Backups*).

**`tink-go` was rejected on a concrete comparison, not on "it has its own format".** Tink exists to reduce primitive misuse, which is a real benefit and the reason the rejection needs a real argument. Against it: Tink's unit of work is a **keyset** whose serialization would sit underneath Envweave's storage format, duplicating the key-version and key-state machinery that § *Rotation*'s four operations already own — the adapter would have to keep Tink keysets and Envweave's fenced keyring consistent, which is more custom code than the layer it replaces. Its AEAD abstraction does not express the per-record HKDF derivation of § *Primitives* or the per-kind AAD schemas of § *Envelope format*; both would be fought rather than used. It pulls its own primitive implementations, breaking the stdlib-only boundary § *Primitives* requires. And it conflicts with the threat model's minimal-dependency mandate. What remains hand-written after adopting it — derivation, AAD schemas, fencing, rotation — is most of what Tink was meant to supply.

The custom cryptographic surface this ADR retains is therefore small and enumerable: an injective AAD encoder, a header codec, and a keyring lookup. Every primitive and every key-agreement construction comes from the standard library. Key management is Envweave's product; the format stays under Envweave's control and Envweave's version number.

**The envelope package is the only caller of a cryptographic primitive in the codebase.** No import of `crypto/cipher`, `crypto/aes`, `crypto/hkdf`, `crypto/ecdh` or `crypto/pbkdf2` outside it. Enforced by test (§ *CI-enforced invariants*), not by convention. Together with the threat model's redacting logger types, that is the mechanism half of "plaintext never leaks".

## Key material in memory

Envweave makes **no memory-secrecy claim**. What it does:

- **The root key is zeroed after startup.** It is needed exactly twice — unwrapping the master key at boot, and `rotate-root-key` — and is re-read from its source on demand. This shrinks the extraction window from *always* to *two brief moments*. **It only works when the key arrives as a file or systemd credential**; with `ENVWEAVE_ROOT_KEY` the value sits in the process environment for the whole lifetime regardless, which is the strongest concrete reason documentation steers to the file path.
- `RLIMIT_CORE = 0` (no core dumps) and `PR_SET_DUMPABLE = 0` on Linux (no same-uid ptrace attach, no `/proc/<pid>/mem` read).
- Best-effort zeroing of key buffers whose lifetime is known.
- Master key held unwrapped for the process lifetime; project DEKs decrypted on demand into a bounded LRU cache, evicted on rotation and on project delete.
- **No** `mlock`, no guarded enclaves. Swap hygiene (encrypted swap, or none) is the operator's, documented and not claimed.

`memguard`-style enclaves were rejected: the Go runtime still copies buffers during GC and interface boxing, so the guarantee is partial while reading as total — precisely what the threat model forbids this ADR from doing — and it is a dependency in the crypto path § *Implementation seam* keeps stdlib-only.

**Recorded residual, and an input to the architecture ticket ([#22](https://github.com/Dunky13/envweave/issues/22)):** Go's garbage collector prevents *guaranteed* zeroization of key material — a zeroed `[]byte` may leave residue in freed memory the program never had a handle to. A language with deterministic drop (Rust + `zeroize`) would close this. The residual sits **below** the line the threat model already draws — running-server compromise is conceded as full control-plane compromise in any language, and core-dump/swap/forensic residue is largely covered by the measures above — while Go retains the natively validated FIPS 140-3 module (§ *Primitives*) and the contributor pool of this product's ecosystem. This is an input to #22's language decision, **not a blocker on it**.

## The honest compromise statement (documentation requirement)

Envweave's documentation MUST state, in Vault's enumerate-the-exclusions style and never as marketing:

**Protected:** stolen datastore files, dumps, disks and backups without the root key; mis-scoped datastore credentials; tamper detection via GCM tags; ciphertext transplant between rows, projects or organizations (§ *Envelope format*); crypto-shred of a deleted project against future copies.

**Not protected:** root or code execution on the app host; memory inspection of the running process (the root key at its two moments, the master key, and cached DEKs are in RAM); an attacker holding API-level admin credentials (that is authorization, not cryptography); a single-box install whose root key sits in the same env file that gets backed up alongside the database — at-rest encryption then defends the dump path only, which remains the most common leak vector; anything already delivered to a workload, a Kubernetes Secret, or a CI provider (the delivery boundary is where Envweave's guarantees end).

**Never claimed:** zero knowledge. The server decrypts by design, because injecting secrets into workloads requires it. Any wording implying otherwise is a documentation bug.

## CI-enforced invariants

Every invariant this ADR creates is a test, not a paragraph:

1. **Known-plaintext dump grep** — a datastore dump containing a known secret value must not contain that plaintext (threat-model mandate).
2. **Stolen-dump authentication** — authentication attempts replayed from dumped credential rows must fail (threat-model mandate).
3. **Transplant** — a ciphertext moved to another row, layer, key, project, organization, or **envelope kind** must fail to decrypt.
4. **Header tamper** — a flipped format version, envelope kind, algorithm id or key version must fail to decrypt.
5. **AAD injectivity** — adversarial field values chosen to collide under naive concatenation (a field ending where the next begins) must produce distinct AADs; a header whose declared lengths do not consume the buffer exactly is rejected.
6. **Startup refusals** — missing root key, wrong root key, non-256-bit key, group/world-readable key file: each aborts with its own distinct error.
7. **Rotation completeness** — after `reencrypt`, zero ciphertexts reference the retired version; retiring a still-referenced version is refused; a writer holding a stale key generation is rejected rather than committing under a retired key.
8. **Crash-safe root rotation** — the instance boots with either the old or the new root at every point in prepare/verify/finalize, and warns while dual-wrapped.
9. **Master rotation completeness** — after `rotate-master-key`, no tier-3 key references the retired master; a tier-3 key created concurrently with master rotation lands under the new master, never the retiring one; `rotate-master-key` during dual-wrapped root state is refused, and vice versa.
10. **Scoped token-key injectivity** — identifier tuples that differ only in where the boundary falls (`org "a" / project "bc"` versus `org "ab" / project "c"`) derive distinct token keys.
11. **Ciphertext uniqueness** — N encryptions of identical plaintext under one DEK produce N distinct ciphertexts (salt and nonce freshness).
12. **Crypto chokepoint** — no import of a crypto primitive package outside the envelope package.
13. **Backup container** — zero recipients refused; a stanza added, removed or reordered fails the payload's header binding; oversize declared lengths are rejected before allocation; a passphrase stanza whose iteration count is below the minimum is refused on read; each recipient kind round-trips.
14. **FIPS build** — the build runs under `GOFIPS140` set to a certified module version, and the test suite **asserts `crypto/fips140.Enabled()` and the expected module version at runtime** rather than merely compiling. Compiling with an unspecified `GOFIPS140` value proves nothing.

## Propagations (binding on downstream tickets)

- **Operations spec** (fog): the **backup-retention bound is mandatory in v1** — § *Erasure* removes the alternative the revision ADR offered. Also owns: root-key escrow and loss procedure; rotation runbooks including the **full post-compromise recovery order** (root → master → tier-3 keys → `reencrypt` → token key) and the dual-wrapped transition state; restore procedure under the threat model's fail-closed recovery mode; **backup recipient-set hygiene** (one identity per retention class, inventoried, since one surviving recipient defeats erasure and a shared identity spans containers); the **backup size cap** and PBKDF2 iteration floor; `reencrypt` scheduling guidance; DEK cache size bound; the **RNG-rollback hazard** (VM snapshot restore and image forking can replay CSPRNG state, § *Primitives*); the **benign rollout wave** triggered by root-token-key rotation (already required by the revision ADR); and the requirement that the root key never share a backup or storage domain with the datastore.
- **RBAC ([#15](https://github.com/Dunky13/envweave/issues/15))**: `rotate-root-key`, `rotate-master-key`, `rotate-dek`, `reencrypt`, `export` and `restore` are operator- or instance-level capabilities, separate grants, never bundled with org administration. A project delete that crypto-shreds a DEK is irreversible and MUST be gated accordingly.
- **Revision model ([#11](https://github.com/Dunky13/envweave/issues/11))**, satisfied rather than amended: the root token key is a distinct key tier (§ *Key hierarchy*), so encryption-key hygiene never perturbs change tokens; and rollback's re-encryption into new rows is an internal server operation requiring no `reveal` (§ *Envelope format*), preserving restore-without-reveal.
- **Architecture ([#22](https://github.com/Dunky13/envweave/issues/22))**, additionally: identifiers bound into an AAD are **immutable and never reused**, which constrains every future storage migration — renumbering rows or reusing freed ids renders existing ciphertext undecryptable.
- **Machine identities ([#17](https://github.com/Dunky13/envweave/issues/17))**: tokens are high-entropy random stored as hash verifiers, never envelope-encrypted — a root-key holder must not be able to recover a token.
- **Human auth ([#16](https://github.com/Dunky13/envweave/issues/16))**: password verifiers use a memory-hard KDF per the threat model; note that Argon2id is neither stdlib nor FIPS-approved, so a FIPS build and Argon2id are mutually exclusive — #16 must choose knowingly rather than inherit the conflict.
- **Architecture ([#22](https://github.com/Dunky13/envweave/issues/22))**: stdlib-only crypto boundary; the envelope package as sole primitive caller, enforced by architecture test; the Go zeroization residual as a recorded input to the language decision; and a **minimum toolchain of Go 1.26**, since `crypto/hpke` (§ *Backups*) and `crypto/hkdf` (§ *Primitives*) are stdlib only from 1.26 and 1.24 respectively.
- **Audit ([#24](https://github.com/Dunky13/envweave/issues/24))**: root-key rotation, DEK rotation, re-encryption start/completion, DEK retirement, project crypto-shred, export, and restore are auditable events.
- **API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25))**: `init`, `rotate-root-key` (with `--prepare` / `--verify` / `--finalize`), `rotate-master-key`, `rotate-dek`, `rotate-token-key`, `reencrypt`, `export`, `restore` command surface; `reencrypt` must be resumable from the CLI and report progress; `rotate-token-key` must warn that it triggers a rollout wave before proceeding.
- **Kubernetes ([#19](https://github.com/Dunky13/envweave/issues/19))** and **Compose ([#18](https://github.com/Dunky13/envweave/issues/18))**: the delivery boundary is where these guarantees end — documentation must carry that statement, including K3s `--secrets-encryption`.
