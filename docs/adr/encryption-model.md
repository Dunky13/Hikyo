# Hikyo encryption model (ADR, locked 2026-07-30)

> **Declared amendment (2026-08-06, [secret-scanning.md](./secret-scanning.md), [#39](https://github.com/Hikyo-Org/Hikyo/issues/39), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** the hierarchy gains one **tier-3 scanning-fingerprint key** (root→master→scanning-fingerprint, sibling of the project DEKs and token key, used for nothing else), honoring this ADR's never-overload rule rather than bending it. Three body sections read as amended: **(1) wrapping** — the key wraps under the existing `wrapped_dek` envelope kind as an instance-scoped tier-3 key (empty `project_id` like the instance DEK, its own `dek_id`/`dek_version`, `master_key_version`) — no new AAD schema; **(2) `rotate-master-key`'s "re-wrap every tier-3 key" set includes it**; **(3) the rotation inventory reads six operations**: the new **`rotate-scanning-key`** replaces the key outright — no version keyring and no `reencrypt` walk, because fingerprints are keyed digests, not ciphertexts to preserve; old fingerprints must die, that is the operation's purpose — and drops every dismissal row (re-fire, the safe direction), operator-initiated like the other five. The envelope package exports exactly one consuming function — a keyed fingerprint over domain-separation label ‖ scope binding (org, project, environment, key) ‖ canonical value bytes — for the scanner's dismissal rows; scanning code imports no hash/HMAC primitive (the architecture test extends to prove it). Restore carries the key inside the hierarchy as usual; project deletion removes the project's dismissal rows. Details in [secret-scanning.md](./secret-scanning.md) §4.

> **Amended by the flat-model ADR ([flat-model.md](./flat-model.md), 2026-08-06, [#40](https://github.com/Hikyo-Org/Hikyo/issues/40), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** the `value` AAD binds `env_id` — every value row now has an owning environment; the `layer_id` rationale, operations-target-layers prose, and transplant CI fixtures (cross-layer → cross-environment) read per that ADR's ripple register. Spec edit, not a migration: nothing is implemented.

Context: Hikyo stores secret values and hands them to workloads in plaintext, so the server must be able to decrypt — no zero-knowledge claim is available or attempted. The threat model ([#8](https://github.com/Hikyo-Org/Hikyo/issues/8), [threat-model.md](./threat-model.md)) fixed the guarantee this ADR must deliver: theft of the database or a backup **without the root key** yields no secret values and no replayable stored credentials; it delegated every mechanism — AEAD choice, associated-data binding, nonce rules, key lifecycle, ciphertext versioning, replay/swap defence, rotation completion and failure atomicity — to this ticket. The encryption research ([#4](https://github.com/Hikyo-Org/Hikyo/issues/4), [encryption-architectures.md](../research/encryption-architectures.md)) surveyed Infisical, Vault/OpenBao, Bitwarden, Kubernetes etcd encryption, age and SOPS, and established field-level envelope encryption as the only design that behaves identically on sqlite and postgres. This ADR fixes the concrete architecture.

**Amends the revision ADR ([#11](https://github.com/Hikyo-Org/Hikyo/issues/11)).** [revision-model.md](./revision-model.md) offered the operations spec a choice between a backup-retention bound and "per-revision cryptographic erasure". **The second option is unavailable under this architecture** — the key hierarchy travels inside every backup, so destroying a live key erases nothing already written (§ *Erasure, and why crypto-shredding is not retention*). The retention bound is mandatory in v1, not one of two alternatives.

**Conforms to the threat model ([#8](https://github.com/Hikyo-Org/Hikyo/issues/8)) as written.** Trust boundary 5 specifies "age-encrypted exports", and § *Backups and exports* ships exactly that. An intermediate revision of this ADR substituted a stdlib container to preserve a FIPS goal that has since been withdrawn (§ *Primitives*); no amendment to the threat model is required.

Granularity note: this is the wayfinding-level encryption ADR. It fixes the key hierarchy, primitives, envelope format, binding, bootstrap, rotation semantics, the encrypted-field set, the backup container, and the honest compromise statement. Mechanism-level detail is delegated: concrete bounds, quotas, retention defaults and the backup/restore runbook → operations spec; token and credential formats → machine identities ([#17](https://github.com/Hikyo-Org/Hikyo/issues/17)); which capability gates `reveal`, rotation and restore → RBAC ([#15](https://github.com/Hikyo-Org/Hikyo/issues/15)); password KDF parameters and session mechanics → human auth ([#16](https://github.com/Hikyo-Org/Hikyo/issues/16)); which crypto events are audited → audit ([#24](https://github.com/Hikyo-Org/Hikyo/issues/24)); command surface for `init`, `rotate-root-key`, `rotate-dek`, `reencrypt`, `export`, `restore` → API & CLI ([#25](https://github.com/Hikyo-Org/Hikyo/issues/25)); language choice and the crypto package's place in the codebase → architecture ([#22](https://github.com/Hikyo-Org/Hikyo/issues/22)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## Key hierarchy — three tiers

1. **Root key (KEK)** — 256-bit, operator-provided, **never stored in the datastore**. Wraps tier 2 only.
2. **Master key** — 256-bit random, generated at first startup, stored wrapped in a single versioned row. Wraps tier 3 only.
3. **Tier-3 keys** — 256-bit random, stored wrapped by the master key, versioned:
   - one **DEK per project**, covering every layer of that project (project-defaults, base chain, environment) **and every project-scoped sensitive field** — a project is one key domain;
   - one **instance DEK** for sensitive rows belonging to no project (MFA seeds, recovery codes, instance-scoped credentials);
   - one **root token key**, used for derivation only and never for encryption (below).

Per-project granularity buys blast-radius isolation, per-project rotation and crypto-shred on project delete. Per-environment DEKs were rejected: project-defaults-layer values belong to no environment, so a per-environment scheme requires the per-project scheme underneath it — it adds a tier rather than replacing one. Per-value DEKs were rejected; see § *Erasure*.

**Per-project routing through an external KMS is explicitly NOT promised by this hierarchy.** Infisical offers it ([security internals](https://infisical.com/docs/internals/security)), and it is tempting to claim per-project DEKs make it free. They do not: per-project KMS unwrapping requires a provider identifier and a per-project key reference in the wrapped-DEK record, and the tier-3 wrapping would no longer be master→DEK. Neither is in the format below. The KMS seam this ADR reserves is **at the root-key boundary only** (§ *Root-key bootstrap*), where one blob is wrapped and the change is invisible to every ciphertext. Per-project KMS routing is a future **format version**, not a drop-in.

**The root token key is a distinct tier-3 key, not a DEK derivation.** The revision ADR fixes the change token as `HMAC(scoped token key, canonical encoding of delivered content)` with the scoped key derived "from a server root token key" ([revision-model.md § Two identifiers](./revision-model.md)). Hikyo therefore holds a **root token key** — 256-bit random, wrapped by the master key, sibling to the DEKs and **never used for encryption**. Per-scope keys are derived on demand and never stored:

```
scopedTokenKey = HKDF-SHA256(rootTokenKey, info = LP("wenv/change-token/v1", org_id, project_id, env_id))
```

`LP(...)` is the **same length-prefixed canonical encoding** mandated for associated data (§ *Envelope format*), and it is load-bearing here for the same reason: raw concatenation lets `(org "a", project "bc")` and `(org "ab", project "c")` derive the identical key, which would resurrect precisely the cross-scope equality oracle the revision ADR keyed the token to eliminate.

Deriving these from a **project DEK** instead was considered and rejected: DEK rotation is a routine, operator-initiated hygiene operation, and coupling it to the token key would silently change every change token in the project, driving a full rollout wave of every workload in every environment as an invisible side effect of key hygiene. The revision ADR permits exactly one such wave, on deliberate **token-key** rotation, and requires the operations spec to call it out. Separating the keys keeps encryption rotation and delivery churn independent.

Any future per-purpose key follows the same rule — a distinct tier-3 key with its own purpose, derived per scope with a domain-separated `info` label, never overloaded onto a key that already has a job.

## Primitives — XChaCha20-Poly1305

**XChaCha20-Poly1305** for every layer, from `golang.org/x/crypto/chacha20poly1305` (`NewX`), with a random 192-bit nonce per message:

```
nonce = 24 random bytes
ct    = XChaCha20-Poly1305(key, nonce, plaintext, aad)
```

**FIPS 140-3 alignment is explicitly NOT a goal of this project.** An earlier revision chose AES-256-GCM to keep it reachable; that goal is withdrawn, and this section records the reasoning so it is not re-litigated.

The argument is **cost versus target requirement**, and it must not be overstated in either direction. Two things that are *not* claimed, because they would be false: that FIPS-regulated organizations never adopt open-source self-hosted software, and that validation is technically unreachable. Go's cryptographic module holds a CMVP certificate, and an application may incorporate a validated module without holding a certificate of its own — full compliance then remains dependent on operating environment, module version, runtime mode, and usage.

What is claimed: **FIPS is outside the requirements of Hikyo's target users, and retaining it as a goal imposes primitive and product constraints that are not justified by that absence of demand.** Positioning ([#3](https://github.com/Hikyo-Org/Hikyo/issues/3)) is self-hosting developers and platform engineers at 1–3 orgs and ≤25 users under a "fully open, no enterprise tier" wedge. Against zero identified demand, the goal was extracting two concrete costs: a hand-specified backup container in place of a reviewed one (§ *Backups*), and pressure on [#16](https://github.com/Hikyo-Org/Hikyo/issues/16) toward PBKDF2 over Argon2id — a **genuine security downgrade**, since PBKDF2 is not memory-hard. Paying reduced password-cracking resistance for an unrequested capability is the trade being declined.

If a real FIPS requirement ever appears, this is revisitable: the envelope format is versioned, and the constraint would be a primitive swap plus a `reencrypt` pass, not a redesign.

With that constraint gone, XChaCha20-Poly1305 wins on the merits:

- **The 192-bit nonce makes random nonces safe without a counting ceiling** — 2⁸⁰ messages per key stays under a 2⁻³² collision probability, *assuming a secure RNG* (the XChaCha specification's own condition). There is no ceiling to budget and no derivation trick needed to dodge one. AES-GCM's 96-bit nonce is safe only to ~2³² messages per key.
- **Constant-time in software, by construction.** ChaCha20 uses no data-dependent table lookups. Go's software AES fallback is table-driven and cache-timing sensitive, and hardware AES is not universal on the ARM boards this product is deployed to — the **Raspberry Pi 4 has no ARMv8 crypto extensions** (verify the Pi 5 separately rather than assuming).
- **Zero marginal dependency.** `filippo.io/age` (§ *Backups*) already imports `golang.org/x/crypto`, so the module is in the build either way, and it is Go-team maintained.
- **One cipher family end to end** — ChaCha20-Poly1305 protects database records and, inside age, backup payloads. Not the *same primitive*: Hikyo uses XChaCha20-Poly1305 with random 192-bit nonces, while age's payload uses ChaCha20-Poly1305 with derived keys and counter nonces under its STREAM construction. One family, two profiles.

**A per-record derived key is therefore NOT used.** An earlier revision derived a single-use record key via `HKDF-SHA256(dek, 32-byte random salt)` purely to escape the GCM nonce ceiling. XChaCha removes that ceiling natively, so the salt, the KDF call and 32 bytes per record are deleted.

**Three properties are lost with it, and are accepted explicitly rather than waved away.** The per-kind AAD of § *Envelope format* supplies *context binding*, which is a different thing from key separation, so it does not substitute for any of these:

1. **Record-level key isolation** — every ciphertext under a given DEK version now shares one key. Accepted: the DEK is the real unit of compromise in this design; an attacker who extracts a record key from process memory has the DEK alongside it, so the isolation was theoretical rather than operational.
2. **Nonce-reuse containment** — with derivation, a repeated nonce was harmless unless the salt repeated too. Now a repeated nonce under one DEK is directly damaging (ChaCha20-Poly1305 reuse leaks the XOR of plaintexts and enables Poly1305 key recovery). Accepted, and it is the reason the RNG conditions below are stated as requirements rather than notes.
3. **Blast radius of a single leaked key** — a leaked record key exposed one record; a leaked DEK exposes a project. Accepted: crypto-shred, rotation and `reencrypt` are all already scoped to the DEK, so the DEK was the blast-radius unit regardless.

HKDF-SHA256 survives in exactly one place in **Hikyo's own** code — deriving scoped change-token keys from the root token key (§ *Key hierarchy*) — where it is doing key *derivation*, its actual job. (Age uses HKDF internally for its own recipient and payload keys; that is age's business, not this ADR's.)

Two properties must not be elided. **`crypto/rand` failure is fatal** at every seal: a degraded or short read aborts the operation and never proceeds with weak randomness.

And **VM snapshot rollback or cloning can replay kernel CSPRNG state**, repeating a nonce under a live DEK. Scoped precisely, because the sloppy version of this warning is worse than none: the hazard is restoring or cloning a **virtual machine** where the hypervisor lacks VMGenID support, the guest ignores it, or the mechanism is broken — modern VMGenID exists exactly to notify the guest and reinitialize its RNG. **Forking a container image is not this hazard**: an image carries no host-kernel CSPRNG state, and `crypto/rand` reads from the host kernel. This is an operations-spec item covering VM-level snapshot and clone workflows, and it is not something the crypto layer can detect.

**Rejected:** AES-256-GCM (nonce ceiling, software-timing exposure on target hardware, and its only remaining advantage — stdlib purity — was already forfeited by adopting age); usage counters with rotation thresholds (makes every encrypt's safety depend on a counter write under concurrent writers); deterministic nonce construction (a restore rewinds the counter, and the threat model makes restore a first-class event — a trap, not a trade-off).

## Envelope format and AAD binding

Every ciphertext — wrapped keys and data alike — carries a versioned header:

```
header = format_version ‖ envelope_kind ‖ algorithm_id ‖ wrapping_key_id ‖ wrapping_key_version ‖ nonce
record = header ‖ ciphertext ‖ tag
```

`format_version`, `envelope_kind` and `algorithm_id` are single bytes; `wrapping_key_version` is a `uint32` big-endian; `wrapping_key_id` and `nonce` are length-prefixed as below. **`wrapping_key_id` names the key that encrypted this record** — a DEK, the master key, or a backup file key — and is deliberately *not* called `key_id`, because `key_id` in the `value` AAD schema means the domain object (a configuration key). Two different things sharing one name in one format is a decoding bug waiting to be written. For `wrapped_master`, whose wrapping key is the operator's root and has no stored identifier, `wrapping_key_id` carries the **`root_key_epoch`** and `wrapping_key_version` is zero.

The header is **authenticated as part of the AAD**, so format version, envelope kind, algorithm id and key version cannot be edited independently of the payload.

**Encoding is injective, and that is normative.** Concatenation of variable-length fields is ambiguous — `a ‖ b` cannot be distinguished from `a' ‖ b'` when the split moves. Every AAD is therefore a **length-prefixed sequence**: each field emitted as a `uint32` big-endian byte length followed by its bytes, absent fields emitted as length zero, field order fixed by the schema for that envelope kind, no separators, no text formatting. A conforming implementation MUST reject a header whose declared lengths do not consume the buffer exactly.

**There is one AAD schema per envelope kind, not one universal tuple.** The `envelope_kind` byte selects it, so identifiers from different tables can never collide into the same context:

| Kind | AAD fields after the header |
|---|---|
| `value` | `org_id`, `project_id`, `layer_id`, `key_id`, `row_id`, `field_tag` |
| `wrapped_dek` | `org_id`, `project_id` (empty for the instance DEK), `dek_id`, `dek_version`, `master_key_version` |
| `wrapped_master` | `master_key_version`, `root_key_epoch` |
| `wrapped_token_key` | `token_key_version`, `master_key_version` |
| `project_field` | `org_id`, `project_id`, `owner_table`, `owner_row_id`, `field_tag` |
| `instance_field` | `owner_table`, `owner_row_id`, `field_tag` |

There is no `backup_payload` kind: § *Backups* delegates the entire container to age, so no Hikyo envelope record appears in an export.

`layer_id`, **not** `env_id`, for `value` — inheritance-ADR values live on layers and project-defaults has no environment; binding to `env_id` would leave that layer unbound.

**Identifiers bound into an AAD are immutable and never reused.** A table that renumbers rows, reuses a freed id, or moves a row between tables during a storage migration renders its existing ciphertext undecryptable. This constrains every future migration and belongs in the architecture ADR's schema rules, not only here.

The attack this defeats is intra-project, not merely cross-tenant: a datastore writer copies a production ciphertext onto a development-layer row for a key they legitimately hold `reveal` on, then asks the server to decrypt it. Cross-org or cross-project binding alone does not stop that; row-anchoring makes a ciphertext decryptable at exactly one row and one column and nowhere else. Every AAD component is already a column on the row being decrypted, so the binding costs nothing.

Consequence, accepted: **any operation that produces a new row re-encrypts; a ciphertext is never copied between rows.** This covers copying a value to another environment, re-keying, and — importantly — **rollback**. The revision ADR is explicit that restoring an earlier state "creates a **new** revision through the normal publish pipeline", staging pending changes owned by the restoring user, and that restoring an inherited value flattens it into a local override ([revision-model.md § Rollback](./revision-model.md)). There is no existing row to point at: the target layer differs, the row id differs, so the AAD differs and the value must be decrypted and re-sealed.

**That re-encryption is an internal server operation, but it is NOT unauthorized.** The crypto layer renders no plaintext to any principal, so the *cryptographic* step needs no capability — but the schema ADR gates the *operation*, and this ADR conforms rather than contradicting it. [schema-model.md § Newly inheriting a secret](./schema-model.md) requires **`reveal-history` on the key** to restore a `secret` occurrence, plus the routing gate, precisely because the plaintext comes from server-held historical material rather than from the publisher: without it, a principal holding publish-on-dev and no reveal could restore production's superseded secret into a development environment they control and read it out of the workload. The same gate covers **any other server-side duplication of stored secret material** — cross-environment copy, environment clone, bulk apply.

The rule this ADR states, precisely: **an internal decrypt-and-reseal is never itself a disclosure, and never itself an authorization.** Whether the operation is permitted is decided by the schema and RBAC ADRs, evaluated before the crypto layer is called.

**Residual, documented:** AAD prevents *transplant*. It does not prevent *deletion*, nor *resurrection of a row's own earlier ciphertext*. An actor who can do either already holds datastore write access and is operator-equivalent under the threat model. "AAD-bound" must never be presented in documentation as "tamper-proof".

## Root-key bootstrap

`HIKYO_ROOT_KEY` (env var) or `--root-key-file` (path), 256-bit. `hikyo init` generates the key, prints it exactly once with a blunt instruction to store it off this machine, and creates the wrapped master key. Unattended restart works — Shamir/manual unseal was rejected as the wrong default for single-node self-hosting, and passphrase-derived roots for the same reason.

Startup refusals, all **hard failures with no override flag**:

1. **No root key present** — abort. The server never auto-generates a root key on first run: a silently generated key is a key nobody backed up, discovered at restore time.
2. **Key file readable by group or other** — abort. One `os.Stat` check.
3. **Not exactly 256 bits after decoding** — abort. No padding, no stretching, no derivation from a short string. (Infisical's 128-bit default is the anti-pattern the research flagged.)
4. **Master key's Poly1305 tag fails to verify** — abort with "root key does not match this datastore". Never a partial boot.
5. **Datastore contains a master key wrapped at an unknown format version** — abort rather than guess.
6. **Backup export with zero configured recipients** — refuse (§ *Backups*); never silently write plaintext.

**Env-var delivery is supported but documented as the weakest tier**: the value is visible in `/proc/<pid>/environ`, `docker inspect`, and process listings for the process's whole lifetime, which also defeats the root-key wipe in § *Key material in memory*. Documentation steers to the file path and to systemd `LoadCredentialEncrypted` (TPM2- or host-key-bound, unattended restart *and* offline-theft protection, **zero Hikyo code** since the key still arrives as a file) — always paired with an escrowed copy, because TPM-bound blobs die with the mainboard.

**External KMS is interface-reserved, not implemented, in v1.** A `wrap(keyBytes) / unwrap(blob)` seam sits at the root-key boundary with one local implementation. That is the entire contract, so Vault transit, AWS/GCP KMS, or a hardware-backed provider become drop-ins with no data migration. Shipping one in v1 means shipping and testing cloud credential handling for a userbase that self-hosts to avoid it. The OpenBao failure mode is documented against the future provider: permanent KMS loss without recovery material means unrecoverable data.

Deployment-docs requirement, restated from the threat model: **the root key must not share a backup or storage domain with the database.**

## Rotation

Five operations across the three key tiers; all ship in v1, all **operator-initiated** — nothing auto-rotates, because § *Primitives* removed the usage-count trigger that would justify it.

- **`rotate-root-key`** — replace the operator-held root. Re-wraps the master key only; no data touched. Crash-safe protocol below. This is the rotation operators actually need after an env-file leak.
- **`rotate-master-key`** — generate a new master key and re-wrap **every** tier-3 key (all project DEKs, the instance DEK, the root token key) under it. Retire the old master only after a fenced zero-reference check. Bounded by the number of projects, so seconds.
- **`rotate-dek --project X` / `--instance`** — append a new DEK version. New writes use it; old versions remain readable (Vault keyring semantics). Free, and incomplete on its own.
- **`rotate-token-key`** — new root token key version, then **invalidate the change-token cache and recompute it eagerly for every current published snapshot**. Separate command precisely so it is never a side effect of another rotation. Protocol below, because "rotate the key and tokens change" is false as stated: a token is served from a cache, so a new key changes nothing a consumer sees until that cache is invalidated.
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

**Token-key rotation is a cache invalidation, and needs its own completion protocol.** The two-level fencing above guards *encryption* key state; the change-token cache is neither key state nor snapshot content, so rotating the root token key touches data the encryption fences do not cover. Fixed here:

- **The change token is a derived projection, not immutable snapshot content.** This is what makes rotation coherent, and it follows the revision ADR rather than amending it: [revision-model.md § Two identifiers](./revision-model.md) fixes snapshot *identity* as the revision number plus the pinned input revisions, and states those are "separate fields, **not folded into the token**". The token is `HMAC(scoped token key, canonical encoding of delivered content)` — a pure function of immutable content and the current key — so it is **stored as a version-tagged cache beside the snapshot, never as part of it**. Rotation invalidates that cache and recomputes; the snapshot's content, identity, revision number and pinned input revisions are untouched. Nothing is rewritten in place and no new revision is created.
- **Every token changes, including historical and pinned ones**, because every token derives from the same rotated key. An earlier draft of this protocol tried to recompute "current" snapshots while preserving "pinned" ones; that is impossible, since a current revision can also be pinned, and it contradicted immutability besides. Uniform recomputation is both simpler and what the revision ADR already describes when it says rotating the token key changes every token.
- **Version-tagged tokens.** Every stored token records its token-key version alongside the `v1:` scheme prefix. A comparison across two versions is **not equality-comparable** and must be treated as "changed", never as equal — this is what makes a partially completed rotation safe rather than silently wrong.
- **Fencing.** Recomputation takes the project's publish serialization (the inheritance ADR's serializable per-project publish), so a concurrent publish either precedes it and has its cache entry recomputed, or follows it and caches its token under the new key. No cache entry is written under the old key version after its environment has been recomputed.
- **Retirement.** The old token-key version retires once no cache entry references it. Because tokens are derived rather than stored-forever facts, retirement is reachable — unlike a scheme where historical snapshots pin an old key permanently.
- **Recomputation is eager for current snapshots and lazy for the rest.** Current snapshots are recomputed immediately so the wave happens once, promptly, and observably; historical and pinned snapshot tokens are recomputed on read. A cache entry is always tagged with the key version that produced it, so a stale entry is detectable rather than silently wrong.
- **Atomicity is per environment, not global.** A rollout wave crossing environments over a few seconds is acceptable; a cache entry with a half-written token is not. Interrupted rotation is resumable, and because the token is derived, an interruption can lose no information — worst case some entries recompute lazily later.
- **Exactly one wave** follows from recomputing each current snapshot exactly once. Running the command twice produces two waves, which is the operator's choice and is warned about, not prevented.

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
- adapter / deployment-module outbound credentials and provider config secrets — under the **project DEK** with envelope kind `project_field` when the adapter belongs to a project, under the instance DEK with `instance_field` when it is instance-scoped. A project-owned secret must never land under the instance DEK: it would survive that project's crypto-shred and escape its rotation.

Encrypting `config`-classified values as well as `secret` ones is deliberate. The schema ADR permits reclassification `config → secret`; if `config` values were plaintext, every historical row written before that moment would remain plaintext in the datastore and in every backup already taken, and the reclassification would protect nothing that already exists. It also keeps classification out of the envelope layer entirely — no `if classification == secret` branch in the one place where a wrong branch is unrecoverable. The cost is one AEAD call on a `DATABASE_HOST`.

**Not encrypted, documented as exposed to datastore theft** (consistent with the threat model's secondary-asset stance): org, project, environment, folder and key names; descriptions; JSON Schema declarations and patterns; presence state; revision lineage metadata; audit metadata; timestamps; ciphertext sizes.

**Session and service-account tokens are hashed verifiers, not ciphertext** — fixed by the threat model, and correct: a hash cannot be reversed by a root-key holder.

Two consequences, recorded rather than discovered later:

1. **No SQL predicate can touch a value.** Value search or filtering means decrypt-and-scan, server-side, authorization-checked per value. Acceptable at ≤10k entries; not acceptable at 10M, which is outside the v1 scale envelope.
2. **No length padding in v1.** Ciphertext length leaks approximate value length — already an accepted metadata exposure. Padding buckets are the extension path; documentation must not imply constant-size ciphertext.

## Backups and exports

`hikyo export` produces an **age-encrypted** archive (`filippo.io/age`) holding the already-field-encrypted datastore export, encrypted to one or more **operator-held recipients**. This restores the research recommendation and conforms to the threat model's trust boundary 5 as originally written.

**Hikyo specifies no container format of its own.** Age supplies the whole of it — X25519 recipient stanzas, `scrypt` passphrase recipients, plugin recipients for hardware tokens, the STREAM chunked payload construction with chunk ordering and truncation detection, and a parser hardened by wide deployment. An earlier revision of this ADR hand-specified an equivalent container over ECDH and later over HPKE; cross-model review correctly called the first version a sketch rather than a specification, and the honest conclusion is that **the pieces it kept getting wrong are exactly the pieces age already gets right**. The threat model mandates minimal dependencies and maintainer review of all crypto contributions; adopting a reviewed format is the cheaper side of that mandate, not the expensive one.

What Hikyo still owns — the contract around the container, which delegation does not supply:

- **Recipient policy.** Multi-recipient wrapping means any single recipient restores. The instance stores only **public recipients**; the private identity never touches the datastore.
- **Refusing a zero-recipient export**, loudly, rather than writing plaintext.
- **Passphrase recipients** use age's `scrypt` recipient — memory-hard, where the FIPS-constrained PBKDF2 it replaces was not. **An `scrypt` stanza must be the only stanza in its container**, per the age specification, so passphrase mode is mutually exclusive with multi-recipient policy: `export` either takes public recipients or a passphrase, never both, and says so rather than silently dropping one.
- **Distinct keys are not automatically distinct failure domains.** The threat model requires backup identity and root key to fail separately, which is a **custody** requirement, not a cryptographic one: the deployment docs must require separate storage and separate access control for the two, exactly as they already do for the root key versus the datastore. Two keys in one password manager is one failure domain wearing two names.
- **Restore authenticates the whole archive before committing any state.** Age detects truncation only by reaching a verified final chunk, so a restore that streams-and-applies would commit a prefix of a truncated archive. Restore therefore verifies to the final chunk **first**, and only then begins mutating the instance. Export likewise publishes its artifact atomically — a partially written backup must never be mistakable for a complete one.
- **Recipient-set hygiene** — see § *Erasure* for the conditions under which destroying identities actually erases anything.

**`crypto/hpke` was considered and rejected.** It is a specified KEM with published test vectors and would have been the right answer *if* the stdlib-only constraint had survived — but it wraps a key, and a backup needs a container: framing, chunking, truncation detection, stanza encoding and parser bounds would all still have been Hikyo's to write and test. Since the FIPS goal that motivated staying in stdlib is withdrawn (§ *Primitives*), there is no longer a reason to reimplement what age has already shipped.

**tink-go** was likewise rejected for this container, on the same grounds as § *Implementation seam*.

**Restoring with the standard `age` CLI yields a dump whose every value is still root-key ciphertext** — Hikyo is required to read it either way. That was previously argued as a reason age's interoperability was worthless; it is more honestly stated as a limit on what interoperability buys: the operator can verify, copy, re-key and archive the artifact with standard tooling, but not read secrets out of it without the instance and its root key.

Shipping no backup encryption at all — leaving it to restic/borg/kopia — was considered and rejected: the export's **metadata** (§ *What is encrypted*) is the infrastructure map in plaintext, and an unconditional encrypted artifact beats one contingent on the operator having configured their backup tool correctly. It also gives instance migration a first-class artifact.

**The instance stores only public recipients.** The backup private identity never touches the datastore. **Restore requires the identity and the root key, separately** — two failure domains, as the threat model requires: the identity decrypts the container, the root key decrypts values. Restore's fail-closed recovery mode (invalidating every pre-restore authentication artifact) is the threat model's requirement and the operations spec's procedure; this ADR supplies only the cryptography.

## Erasure, and why crypto-shredding is not retention

**In this design, key destruction cannot retroactively protect a backup that has already been written.** Destroying a key — a revision's, a DEK version's, or an entire project's — removes it from the *live* datastore only. Every retained backup contains the wrapped key hierarchy alongside the data, so anyone holding that backup plus the root key reads the supposedly erased value. This is the same asymmetry as § *Rotation*'s stolen-copy rule.

**This is a property of the chosen architecture, not a law.** Cryptographic erasure is achievable in general by holding the key material **outside** the backup domain — an external KMS or HSM whose keys are deliberately excluded from every export, so destroying the external key bricks every retained copy at once. That is a coherent design; it is rejected for v1 because it makes the KMS a hard availability dependency for restore (the OpenBao failure mode: KMS gone means data gone, backups included) and v1's KMS seam is interface-reserved, not implemented (§ *Root-key bootstrap*). If a KMS provider ever ships, per-scope erasure becomes reachable and this section should be revisited rather than re-derived.

For v1, therefore:

- **Per-revision cryptographic erasure is not offered**, and per-value DEKs would not deliver it if it were.
- **Crypto-shred on project delete** is retained, correctly scoped: destroying a project's DEK after its rows are gone protects **future** copies of the datastore, not retained ones.
- The construction that *does* erase history is **destroying a backup container's recipient identities** — but only under conditions that must be stated, because "destroy the identity" is easy to believe and hard to achieve. Erasure of a container holds only when **every** identity capable of opening it is gone *and* **no decrypted form of its contents survives anywhere**. That means: each recipient private key, every escrowed or offline copy, every hardware token holding one, any passphrase wherever written or memorized — **and** every decrypted dump, extracted file key, restored replica, downstream copy, and storage-layer or filesystem snapshot taken while the data was readable. **One surviving recipient, or one surviving decrypted copy, defeats erasure entirely.** Conversely a shared identity spans containers, so destroying it erases every backup wrapped to it, including ones the operator meant to keep. Recipient-set hygiene — one identity per retention class, inventoried — is an operations-spec requirement, not a detail.

**Binding on the operations spec, sharper than the revision ADR's version:** payload GC retires a secret from the live datastore only; retiring it from history requires **deleting the backups, or destroying every identity that opens them** under the conditions above; the **backup-retention bound is mandatory in v1**, because the cryptographic alternative the revision ADR offered is unavailable in a design where the key hierarchy travels inside the backup.

## Implementation seam

The envelope layer is **thin and hand-written over vetted primitives** — header struct, injective AAD encoder, `seal(ctx, plaintext)` / `open(ctx, ciphertext)`, keyring lookup. It composes `x/crypto`'s XChaCha20-Poly1305 and stdlib HKDF; it implements no primitive and no key agreement. The backup container is **not** hand-written at all; it is age (§ *Backups*).

**`tink-go` was rejected on a concrete comparison, not on "it has its own format".** Tink exists to reduce primitive misuse, which is a real benefit and the reason the rejection needs a real argument. Against it: Tink's unit of work is a **keyset** whose serialization would sit underneath Hikyo's storage format, duplicating the key-version and key-state machinery that § *Rotation*'s five operations already own — the adapter would have to keep Tink keysets and Hikyo's fenced keyring consistent, which is more custom code than the layer it replaces. Its AEAD abstraction does not express the per-kind AAD schemas of § *Envelope format*, which would be fought rather than used. And it conflicts with the threat model's minimal-dependency mandate. What remains hand-written after adopting it — AAD schemas, fencing, rotation — is most of what Tink was meant to supply.

The custom cryptographic surface this ADR retains is therefore small and enumerable: **an injective AAD encoder, a header codec, and a keyring lookup**. Every primitive, every key agreement, and the entire backup container come from reviewed external code. Key management is Hikyo's product; the storage format stays under Hikyo's control and Hikyo's version number.

**The envelope package is the only caller of a cryptographic primitive in the codebase.** No import of `golang.org/x/crypto/chacha20poly1305`, `crypto/cipher`, `crypto/aes`, `crypto/hkdf` or `crypto/hmac` outside it, and no import of `filippo.io/age` outside the backup package. Enforced by test (§ *CI-enforced invariants*), not by convention. Together with the threat model's redacting logger types, that is the mechanism half of "plaintext never leaks".

## Key material in memory

Hikyo makes **no memory-secrecy claim**. What it does:

- **The root key is zeroed after startup.** It is needed exactly twice — unwrapping the master key at boot, and `rotate-root-key` — and is re-read from its source on demand. This shrinks the extraction window from *always* to *two brief moments*. **It only works when the key arrives as a file or systemd credential**; with `HIKYO_ROOT_KEY` the value sits in the process environment for the whole lifetime regardless, which is the strongest concrete reason documentation steers to the file path.
- `RLIMIT_CORE = 0` (no core dumps) and `PR_SET_DUMPABLE = 0` on Linux (no same-uid ptrace attach, no `/proc/<pid>/mem` read).
- Best-effort zeroing of key buffers whose lifetime is known.
- Master key, **instance DEK** and **root token key** held unwrapped for the process lifetime; project DEKs decrypted on demand into a bounded LRU cache, evicted on rotation and on project delete. Derived scoped token keys are computed per use and not cached.
- **No** `mlock`, no guarded enclaves. Swap hygiene (encrypted swap, or none) is the operator's, documented and not claimed.

`memguard`-style enclaves were rejected: the Go runtime still copies buffers during GC and interface boxing, so the guarantee is partial while reading as total — precisely what the threat model forbids this ADR from doing — and it adds a dependency to the crypto path for a property it cannot actually deliver.

**Recorded residual, and an input to the architecture ticket ([#22](https://github.com/Hikyo-Org/Hikyo/issues/22)):** Go's garbage collector prevents *guaranteed* zeroization of key material — a zeroed `[]byte` may leave residue in freed memory the program never had a handle to. A language with deterministic drop (Rust + `zeroize`) would close this. The residual sits **below** the line the threat model already draws — running-server compromise is conceded as full control-plane compromise in any language, and core-dump/swap/forensic residue is largely covered by the measures above — while Go retains the contributor pool and operator ecosystem of this product's niche. Note that withdrawing the FIPS goal (§ *Primitives*) **removes one argument that previously favoured Go**, since Go's validated module no longer counts for anything here; the remaining case is ecosystem, not cryptography. This is an input to #22's language decision, **not a blocker on it**.

## The honest compromise statement (documentation requirement)

Hikyo's documentation MUST state, in Vault's enumerate-the-exclusions style and never as marketing:

**Protected:** stolen datastore files, dumps, disks and backups without the root key; mis-scoped datastore credentials; tamper detection via AEAD authentication tags; ciphertext transplant between rows, projects or organizations (§ *Envelope format*); crypto-shred of a deleted project against future copies.

**Not protected:** root or code execution on the app host; memory inspection of the running process (the root key at its two moments, the master key, and cached DEKs are in RAM); an attacker holding API-level admin credentials (that is authorization, not cryptography); a single-box install whose root key sits in the same env file that gets backed up alongside the database — at-rest encryption then defends the dump path only, which remains the most common leak vector; anything already delivered to a workload, a Kubernetes Secret, or a CI provider (the delivery boundary is where Hikyo's guarantees end).

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
8. **Crash-safe root rotation** — the instance boots with either root while dual-wrapped, and warns on every start; **after finalize only the new root boots** and the old is rejected.
9. **Master rotation completeness** — after `rotate-master-key`, no tier-3 key references the retired master; a tier-3 key created concurrently with master rotation lands under the new master, never the retiring one; `rotate-master-key` during dual-wrapped root state is refused, and vice versa.
10. **Scoped token-key injectivity** — identifier tuples that differ only in where the boundary falls (`org "a" / project "bc"` versus `org "ab" / project "c"`) derive distinct token keys.
11. **Ciphertext uniqueness** — N encryptions of identical plaintext under one key produce N distinct ciphertexts (nonce freshness).
12. **Crypto chokepoint** — no import of a cryptographic primitive package outside the envelope package.
13. **Backup round-trip** — zero recipients refused; X25519 and passphrase recipients each round-trip; a tampered container fails to decrypt; an **`scrypt` stanza combined with any other recipient is refused** at export; a **truncated archive is detected before any restored state is committed**; a restore requires the identity **and** the root key, and neither alone yields a value.
14. **`crypto/rand` failure is fatal** — with randomness injected to fail or short-read, every seal aborts and no ciphertext is written.
15. **Token-key rotation** — after `rotate-token-key`, every current published snapshot serves a token under the new key version and no snapshot's content, revision number or pinned input revisions change; a lazily recomputed historical token matches the eagerly recomputed value for identical content; a publish racing the rotation lands under exactly one key version; tokens of differing versions never compare equal; an interrupted rotation is resumable and loses nothing.
16. **Project-scoped field routing** — a project-owned sensitive field encrypted under the instance DEK is rejected; after a project crypto-shred, no `project_field` ciphertext for that project remains readable.

## Propagations (binding on downstream tickets)

- **Operations spec** (fog), additionally from this revision: **separate custody and access control for the backup identity versus the root key** (distinct keys are not distinct failure domains if one password manager holds both); the **VM snapshot/clone RNG hazard** (VMGenID absent, ignored or broken) with ordinary container image forking explicitly excluded; passphrase-versus-recipient exclusivity in export runbooks; and token-key rotation as a **deliberate, warned, one-wave operation**.
- **Operations spec** (fog): the **backup-retention bound is mandatory in v1** — § *Erasure* removes the alternative the revision ADR offered. Also owns: root-key escrow and loss procedure; rotation runbooks including the **full post-compromise recovery order** (root → master → tier-3 keys → `reencrypt` → token key) and the dual-wrapped transition state; restore procedure under the threat model's fail-closed recovery mode; **backup recipient-set hygiene** (one identity per retention class, inventoried, since one surviving recipient defeats erasure and a shared identity spans containers); `reencrypt` scheduling guidance; DEK cache size bound; the **RNG-rollback hazard** (VM snapshot restore or clone where VMGenID is absent, ignored or broken, § *Primitives* — ordinary container image forking is explicitly NOT this hazard); the **benign rollout wave** triggered by root-token-key rotation (already required by the revision ADR); and the requirement that the root key never share a backup or storage domain with the datastore.
- **RBAC ([#15](https://github.com/Hikyo-Org/Hikyo/issues/15))**: `rotate-root-key`, `rotate-master-key`, `rotate-dek`, `reencrypt`, `export` and `restore` are operator- or instance-level capabilities, separate grants, never bundled with org administration. A project delete that crypto-shreds a DEK is irreversible and MUST be gated accordingly.
- **Revision model ([#11](https://github.com/Hikyo-Org/Hikyo/issues/11))**, satisfied rather than amended: the root token key is a distinct key tier (§ *Key hierarchy*), so encryption-key hygiene never perturbs change tokens; and the change token is implemented as a **version-tagged derived cache**, never as immutable snapshot content, which is what #11 already implies by keeping the token out of snapshot identity. Snapshot immutability is preserved, not amended.
- **Schema model ([#12](https://github.com/Hikyo-Org/Hikyo/issues/12))**, conformed to: rollback re-encrypts into new rows as an internal server operation, which is **not** an authorization — restoring a `secret` occurrence still requires **`reveal-history`** plus the routing gate, and so does every other server-side duplication of stored secret material (§ *Envelope format*).
- **Architecture ([#22](https://github.com/Hikyo-Org/Hikyo/issues/22))**, additionally: identifiers bound into an AAD are **immutable and never reused**, which constrains every future storage migration — renumbering rows or reusing freed ids renders existing ciphertext undecryptable.
- **Machine identities ([#17](https://github.com/Hikyo-Org/Hikyo/issues/17))**: tokens are high-entropy random stored as hash verifiers, never envelope-encrypted — a root-key holder must not be able to recover a token.
- **Human auth ([#16](https://github.com/Hikyo-Org/Hikyo/issues/16))**: password verifiers use **Argon2id**, per the threat model, with **no conflict to resolve** — an earlier revision of this ADR flagged Argon2id as incompatible with a FIPS build, and that constraint is withdrawn (§ *Primitives*). #16 chooses parameters, not algorithms-under-duress.
- **Architecture ([#22](https://github.com/Hikyo-Org/Hikyo/issues/22))**: the envelope package as sole caller of a cryptographic primitive, enforced by architecture test; the Go zeroization residual as a recorded input to the language decision, now with the FIPS argument for Go removed; a **minimum toolchain of Go 1.24** for stdlib `crypto/hkdf`; and two accepted dependencies in the crypto path — `golang.org/x/crypto` (XChaCha20-Poly1305) and `filippo.io/age` (backup container), both of which the threat model's crypto-contribution review rule covers.
- **Audit ([#24](https://github.com/Hikyo-Org/Hikyo/issues/24))**: root-key rotation, DEK rotation, re-encryption start/completion, DEK retirement, project crypto-shred, export, and restore are auditable events.
- **API & CLI ([#25](https://github.com/Hikyo-Org/Hikyo/issues/25))**: `init`, `rotate-root-key` (with `--prepare` / `--verify` / `--finalize`), `rotate-master-key`, `rotate-dek`, `rotate-token-key`, `reencrypt`, `export`, `restore` command surface; `reencrypt` must be resumable from the CLI and report progress; `rotate-token-key` must warn that it triggers a rollout wave before proceeding.
- **Kubernetes ([#19](https://github.com/Hikyo-Org/Hikyo/issues/19))** and **Compose ([#18](https://github.com/Hikyo-Org/Hikyo/issues/18))**: the delivery boundary is where these guarantees end — documentation must carry that statement, including K3s `--secrets-encryption`.
