# Encryption-at-Rest Architectures for Self-Hosted Secret Managers

Research for Hikyo (Go single binary, sqlite + postgres, single-node v1). Dated **2026-07-29**. All claims cite primary sources (official docs, source repos, IETF drafts). This document informs — it does not decide; open decisions are listed at the end for the encryption-model grilling ticket.

## 1. Envelope encryption patterns

### KEK/DEK hierarchy

The universal pattern is envelope encryption: data is encrypted with a data-encryption key (DEK); the DEK is itself encrypted ("wrapped") with a key-encryption key (KEK) and stored alongside or near the data; only the KEK needs privileged protection ([AWS KMS concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping), [Tink envelope encryption](https://developers.google.com/tink/client-side-encryption)). Tink describes it exactly: the client "creates a new AEAD DEK, encrypts it with a cloud KMS KEK, and stores it as part of the ciphertext" ([Tink docs](https://developers.google.com/tink/client-side-encryption)).

Real deployments add one more level so the operator-provided root key wraps a single intermediate key rather than every DEK:

- **Infisical** (4 levels): operator-supplied Root Encryption Key (env var, memory-only) → Internal KMS Root Key (random, generated on first startup, encrypted by the root key, stored in DB) → per-organization and per-project 256-bit data keys (encrypted by the KMS root key, stored in DB) → secret values ([Infisical security internals](https://infisical.com/docs/internals/security)).
- **Vault/OpenBao** (3 levels): unseal key → root key → keyring of barrier encryption keys → data ("To decrypt the data, Vault needs the root key so that it can decrypt the encryption key") ([Vault seal concepts](https://developer.hashicorp.com/vault/docs/concepts/seal), [OpenBao seal concepts](https://openbao.org/docs/concepts/seal/)).
- **SOPS** (2 levels): one random data key per file encrypts all values; the data key is wrapped once per master key (age, KMS, PGP) ([SOPS security docs](https://getsops.io/docs/security/)).

The intermediate level matters operationally: rotating the operator's root key then means re-wrapping **one** key blob, not touching data ([Infisical security internals](https://infisical.com/docs/internals/security)).

### Per-tenant / per-project DEKs

Infisical scopes DEKs to organizations and projects: "Each organization and project receives dedicated 256-bit AES keys" ([Infisical security internals](https://infisical.com/docs/internals/security)). Benefits: blast-radius isolation, per-project rotation, per-project export/delete (crypto-shredding a project = destroy its DEK), and a natural hook for routing individual projects through an external KMS (Infisical does exactly this — external KMS unwraps *project* data keys) ([Infisical KMS integration](https://infisical.com/docs/documentation/platform/kms/overview)). Cost: a key table + cache; negligible for a single-node system.

### AEAD choice: AES-256-GCM vs XChaCha20-Poly1305

- AES-256-GCM with 96-bit random nonces is what Vault ([security model](https://developer.hashicorp.com/vault/docs/internals/security): "a 256-bit Advanced Encryption Standard (AES) cipher in the Galois Counter Mode (GCM) with 96-bit nonces"), Infisical ([security internals](https://infisical.com/docs/internals/security)), and SOPS ([security docs](https://getsops.io/docs/security/)) all use.
- The 96-bit nonce space is the weak point: random nonces are only safe up to ~2³² messages per key. Vault mitigates by auto-rotating the barrier key "before reaching 2^32 encryption operations, following NIST SP 800-38D guidelines" ([vault operator rotate](https://developer.hashicorp.com/vault/docs/commands/operator/rotate)); the Go x/crypto docs carry the same warning for 96-bit-nonce ChaCha20-Poly1305 ([pkg.go.dev/golang.org/x/crypto/chacha20poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)).
- XChaCha20-Poly1305 removes the problem with a 192-bit nonce: "users can safely generate a random 192-bit nonce for each message and not worry about nonce-reuse vulnerabilities"; 2⁸⁰ messages per key stays under 2⁻³² collision probability ([draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)). Go's x/crypto docs: "It should be preferred when nonce uniqueness cannot be trivially ensured, or whenever nonces are randomly generated" ([chacha20poly1305 docs](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)). age uses ChaCha20-Poly1305 for payloads with a fresh per-file key, which sidesteps nonce reuse entirely ([age README](https://github.com/FiloSottile/age)).

Practical read: with per-project DEKs, a busy Hikyo install will never approach 2³² writes per DEK, so both are safe; XChaCha20-Poly1305 buys freedom from ever having to think about nonce counters, AES-GCM buys hardware acceleration (AES-NI, irrelevant at secret-manager volumes) and FIPS-alignment (Infisical's FIPS mode swaps key formats but stays AES ([Infisical envars](https://infisical.com/docs/self-hosting/configuration/envars))).

### Nonce management

Two safe strategies seen in the field: (a) random nonce per operation + key-usage ceiling + rotation (Vault ([operator rotate](https://developer.hashicorp.com/vault/docs/commands/operator/rotate))); (b) big-nonce AEAD so random is always safe (XChaCha ([draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)), age's fresh-key-per-file ([age README](https://github.com/FiloSottile/age))). Counter-based nonces are a foot-gun in anything that restarts or runs concurrent writers; nobody in this survey uses them for at-rest data.

### Key-wrapping format

Everyone stores wrapped DEKs as ordinary AEAD ciphertext (nonce ‖ ciphertext ‖ tag) with a key-version identifier, not NIST AES-KW: Vault's keyring tracks key versions so "new key encrypts new data, while older keys in the ring decrypt older data" ([operator rotate](https://developer.hashicorp.com/vault/docs/commands/operator/rotate)); Kubernetes stores a provider/key name with each object so any listed key can decrypt ([Kubernetes encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)). Ciphertext rows therefore need: key-version reference, algorithm identifier, nonce, tag — i.e. a small versioned header. Tink's keyset abstraction is the formalized version of this ([Tink docs](https://developers.google.com/tink/client-side-encryption)).

## 2. Root-key bootstrap and storage for a standalone install

Options, as actually shipped by comparable systems:

| Mechanism | Used by | Unattended restart | Recovery story | Backup-theft protection |
|---|---|---|---|---|
| Env var with raw key | Infisical `ENCRYPTION_KEY` ([envars](https://infisical.com/docs/self-hosting/configuration/envars)) | Yes | Operator must have saved the key | Yes, if backup excludes env/compose file |
| Key file on disk | Kubernetes `EncryptionConfiguration` ([k8s docs](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)) | Yes | Same | Yes, **only** if the key file isn't in the same backup — k8s docs warn keys are "readable by anyone with file access" and backups must be handled separately |
| Passphrase-derived (Argon2id/scrypt) | age scrypt recipients ([age README](https://github.com/FiloSottile/age)); Bitwarden's master-password KDF (PBKDF2 600k / optional Argon2id) ([Bitwarden whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)); Argon2id parameters per [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) | **No** — someone must type it | Human memory / written passphrase | Strong (offline attack must brute-force the passphrase) |
| Shamir shares (manual unseal) | Vault/OpenBao default ([seal concepts](https://developer.hashicorp.com/vault/docs/concepts/seal)) | **No** — "Prior to unsealing, the only possible Vault operations are to unseal the Vault" | k-of-n shares; robust against single loss | Strong |
| Auto-unseal via external KMS/HSM | Vault/OpenBao ([seal](https://developer.hashicorp.com/vault/docs/concepts/seal), [OpenBao seal](https://openbao.org/docs/concepts/seal/)) | Yes | ⚠ OpenBao: if the KMS is permanently lost, "the OpenBao cluster cannot be recovered, even from backups" | Strong (root key never at rest locally) |
| systemd `LoadCredentialEncrypted` + TPM2 | systemd-creds, AES-256-GCM, TPM2/host-key/hybrid modes ([systemd CREDENTIALS](https://systemd.io/CREDENTIALS/)) | Yes | ⚠ hardware-bound: "can only be decrypted and validated on the local hardware and OS installation" — dead motherboard = dead key unless separately escrowed | Strong (ciphertext useless off-host) |

Key trade-off triangle: **unattended restart vs offline-theft protection vs recovery simplicity**. Env-var/file gives restart + simple recovery but depends on the key being excluded from stolen backups. Passphrase/Shamir give theft protection but block unattended restart — Vault's whole "sealed state" ceremony exists to serve that trade ([seal concepts](https://developer.hashicorp.com/vault/docs/concepts/seal)). TPM/systemd-creds gives both but ties recovery to hardware, so it must always be paired with an escrowed recovery copy ([systemd CREDENTIALS](https://systemd.io/CREDENTIALS/)).

Note Infisical's default is surprisingly weak: `ENCRYPTION_KEY` "must be a random 16-byte hex string" — i.e. 128 bits — only the FIPS mode uses a 256-bit key ([Infisical envars](https://infisical.com/docs/self-hosting/configuration/envars)). Hikyo should require 256-bit from day one.

## 3. What "rotation" means per tier

Three distinct operations that get conflated; comparable systems implement them very differently:

1. **KEK/root-key rotation = re-wrap only.** Vault `operator rekey` "generates a new set of unseal keys" and re-protects the root key — "zero downtime", no data touched ([rekey tutorial](https://developer.hashicorp.com/vault/tutorials/operations/rekeying-and-rotating)). In an Infisical-shaped hierarchy, rotating the operator root key means decrypting and re-encrypting one intermediate-key blob ([Infisical security internals](https://infisical.com/docs/internals/security)). Cost: O(number of wrapped keys), milliseconds. This is the rotation operators actually perform (leaked env file, departed admin).

2. **DEK rotation = new key version; re-encryption optional and separate.** Vault `operator rotate` "installs a new key in the key ring. This new key encrypts new data, while older keys in the ring decrypt older data" — it explicitly does **not** re-encrypt existing entries ([operator rotate](https://developer.hashicorp.com/vault/docs/commands/operator/rotate)). Kubernetes does the same lazily: add new key first in the provider list, then force re-encryption by rewriting every object (`kubectl get secrets -A -o json | kubectl apply -f -`), then remove the old key ([k8s encryption docs](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)). SOPS `sops rotate` is the eager variant: generate a fresh data key and re-encrypt the whole file, practical because a file is small ([SOPS docs](https://getsops.io/docs/)). Cost: keyring append is free; full re-encryption is O(all ciphertexts) and requires old key versions retained until complete — k8s warns "mistakes can make data unrecoverable" ([k8s encryption docs](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)).

3. **Secret-value rotation** (rotating the actual credential at the provider) is a product feature, not encryption at rest — out of scope here.

Design consequence: every ciphertext must carry its key version from v1, or lazy rotation is impossible later. That's cheap now and unfixable retroactively.

## 4. Optional external KMS integration (without requiring one)

Patterns that keep KMS optional:

- **Seal-wrap the root**: Vault auto-unseal "delegates the responsibility of securing the unseal key... to a trusted device or service"; on start the server asks the KMS to unwrap the root key ([Vault seal](https://developer.hashicorp.com/vault/docs/concepts/seal)). Smallest possible integration surface — the KMS wraps exactly one blob; everything below is unchanged. OpenBao documents the failure mode to design around: permanent KMS loss = unrecoverable cluster, hence recovery keys ([OpenBao seal](https://openbao.org/docs/concepts/seal/)).
- **Per-project DEK unwrapping via KMS**: Infisical lets orgs route project data keys through AWS KMS/GCP KMS so "the external KMS performs the key unwrapping operation" — per-tenant, opt-in, coexists with the internal KMS ([Infisical security internals](https://infisical.com/docs/internals/security)). More granular, but puts a network call on the hot path.
- **Pluggable provider socket**: Kubernetes KMS v1/v2 talks to a KMS plugin over a unix socket; providers are tried in order for decryption, so `identity`/local-key and KMS entries can coexist during migration ([k8s encryption docs](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)).
- **Multi-recipient wrapping**: SOPS wraps the same data key to *every* configured master key (age, several KMSes, PGP) so any one suffices to decrypt ([SOPS security docs](https://getsops.io/docs/security/), [README](https://github.com/getsops/sops)); age's plugin system (e.g. age-plugin-yubikey) does hardware-backed recipients through the same recipient abstraction ([age README](https://github.com/FiloSottile/age)). This is the right mental model for backup exports (see §8).
- Vault's [transit engine](https://developer.hashicorp.com/vault/docs/secrets/transit) is itself a popular "KMS endpoint" for other software — an Hikyo KMS interface should treat "unwrap this blob" as the whole contract so transit, AWS KMS, and age-plugin backends are interchangeable.

The common denominator: define one internal interface — `wrap(keyBytes) / unwrap(blob)` at the root-key boundary — default implementation local, KMS implementations optional. Tink's `KmsEnvelopeAead` is precisely this interface in library form ([Tink docs](https://developers.google.com/tink/client-side-encryption)).

## 5. Honest server-compromise analysis

Hikyo's job is to hand plaintext secrets to workloads; therefore the server can decrypt, and no zero-knowledge claim is possible. Bitwarden *can* claim zero knowledge only because decryption happens exclusively in clients and "the servers deliberately lack the Stretched Master Key needed to decrypt anything" ([Bitwarden whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)) — a model incompatible with server-side secret injection into CI/k8s. Vault's own threat model is the honest template ([Vault security model](https://developer.hashicorp.com/vault/docs/internals/security)):

**What encryption at rest DOES protect:**
- Stolen DB dumps, stolen disks, stolen backups (ciphertext without the root key), and mis-scoped DB credentials — the entire "storage backend is less trusted than the app" class.
- Tamper detection via AEAD tags ("GCM authentication tag" verification detects modification) ([Vault security model](https://developer.hashicorp.com/vault/docs/internals/security), [Infisical security internals](https://infisical.com/docs/internals/security)).
- Crypto-shredding: destroying a DEK renders its data unrecoverable, useful for project deletion and backup expiry.

**What it does NOT protect:**
- Root/code-execution on the app host: "If an attacker can gain code execution or write privileges to the underlying host, then the confidentiality or the integrity of data may be compromised" ([Vault security model](https://developer.hashicorp.com/vault/docs/internals/security)).
- Memory inspection of the running process: "the confidentiality of data may be compromised" ([same](https://developer.hashicorp.com/vault/docs/internals/security)) — the root key and unwrapped DEKs live in RAM (Infisical: root key "never leaves the server's memory during operation" — which means it *is* in memory) ([Infisical security internals](https://infisical.com/docs/internals/security)).
- An attacker with API-level admin credentials — that's authz, not crypto.
- Single-box installs where DB and app share the host and the key sits in the same env: at-rest encryption then only defends the *backup/dump* path, which is still the most common leak vector (k8s makes the same caveat about config-file keys next to etcd ([k8s encryption docs](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/))).

Docs for Hikyo should state this Vault-style: enumerate the excluded threats explicitly, never say "zero knowledge".

## 6. How comparable systems actually do it

- **Infisical**: AES-256-GCM, 96-bit random nonces everywhere; 4-level hierarchy (operator env-var root key → internal KMS root key → org/project data keys → data); external KMS optional per project; HSM option for the root ([security internals](https://infisical.com/docs/internals/security)). Bootstrap is a single `ENCRYPTION_KEY` env var — 128-bit hex by default, 256-bit only in FIPS mode ([envars](https://infisical.com/docs/self-hosting/configuration/envars)). Closest existing shape to Hikyo.
- **Vault/OpenBao**: everything below the barrier is AES-256-GCM/96-bit; keyring with versioned keys; sealed-at-start, Shamir unseal by default, auto-unseal via KMS/HSM optional; `rotate` = new keyring version (lazy), `rekey` = new unseal shares (re-wrap) ([seal](https://developer.hashicorp.com/vault/docs/concepts/seal), [security model](https://developer.hashicorp.com/vault/docs/internals/security), [rotate](https://developer.hashicorp.com/vault/docs/commands/operator/rotate), [OpenBao seal](https://openbao.org/docs/concepts/seal/)). The cost of its strong at-rest posture is the unseal ceremony on every restart — wrong default for a homelab-friendly single binary.
- **Bitwarden / Vaultwarden**: client-side E2E — PBKDF2-600k/Argon2id-derived master key wraps a random user symmetric key; the server stores only wrapped keys and client-encrypted blobs ([Bitwarden whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)). Vaultwarden the *server* adds no database encryption of its own; its hardening guide is filesystem/container hygiene, relying on vault items already being client-encrypted ([Vaultwarden hardening guide](https://github.com/dani-garcia/vaultwarden/wiki/Hardening-Guide)). Great model for password managers; not applicable when the server must inject secrets.
- **Kubernetes etcd encryption**: per-resource providers (`aescbc`, `aesgcm`, `secretbox`, `kms v1/v2`); local-key providers keep the key in a config file on the API-server disk (explicitly flagged as the weakness); KMS providers do proper envelope encryption with the KEK held externally; rotation = prepend new key, rewrite all objects, drop old key ([k8s encryption docs](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)).
- **age / SOPS**: age — per-file key wrapped to N recipients (X25519, scrypt passphrase, ssh keys, plugins), payload ChaCha20-Poly1305, Go library `filippo.io/age` ([age README](https://github.com/FiloSottile/age)). SOPS — per-file data key, values encrypted AES-256-GCM, data key wrapped to each master key, threat model = "compromised master key credentials" ([SOPS security docs](https://getsops.io/docs/security/)). Both are the reference design for multi-recipient *export/backup* encryption rather than live-DB encryption.

### Go crypto library landscape

- **stdlib**: `crypto/aes` + [`crypto/cipher.NewGCM`](https://pkg.go.dev/crypto/cipher#NewGCM) gives AES-256-GCM; `crypto/rand` for keys/nonces. Zero dependencies.
- **golang.org/x/crypto/chacha20poly1305**: `NewX` for XChaCha20-Poly1305, docs explicitly recommend it "whenever nonces are randomly generated" ([pkg.go.dev](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)); maintained by the Go team, effectively stdlib-adjacent.
- **filippo.io/age**: library-usable; ideal for encrypted exports/backups to operator-held recipients incl. hardware plugins ([age README](https://github.com/FiloSottile/age)).
- **tink-go** (`github.com/tink-crypto/tink-go/v2`): keysets, versioned rotation, `KmsEnvelopeAead`, KMS clients for AWS/GCP ([Tink docs](https://developers.google.com/tink/client-side-encryption)). Buys a key-management framework at the cost of a heavyweight dependency and Tink's own keyset serialization format. For a system whose *product* is key management, wrapping x/crypto directly keeps the format under Hikyo's control; Tink is the fallback if hand-rolling the versioned-header/keyring layer starts to sprawl.

Realistic Go stack: x/crypto XChaCha20-Poly1305 (or stdlib AES-GCM) for the envelope layers + `filippo.io/age` for export/backup files. No cgo anywhere.

## 7. The sqlite angle: whole-DB vs field-level

**Whole-DB encryption (SQLCipher)**: transparent page-level encryption, AES-256-CBC per 4096-byte page with per-page IVs + HMAC-SHA512, PBKDF2-HMAC-SHA512 key derivation ([SQLCipher design](https://www.zetetic.net/sqlcipher/design/)). Problems for Hikyo:

- It's a C extension: Go support means cgo builds against SQLCipher/OpenSSL (e.g. [mutecomm/go-sqlcipher](https://github.com/mutecomm/go-sqlcipher)) — kills the pure-Go single-binary story (the common pure-Go driver [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) has no encryption support; SQLite's own SEE codec is commercial).
- It's sqlite-only: postgres would need a completely different mechanism (pgcrypto/TDE), breaking "field-level must work identically on postgres".
- SQLCipher 3.x/4.x file-format incompatibilities push migration burden onto the operator ([go-sqlcipher README](https://github.com/mutecomm/go-sqlcipher)).
- It protects the file, not the rows: once the process has the passphrase, every column is plaintext to any SQL path; no per-project DEKs, no crypto-shredding, no lazy rotation.

**Field-level envelope encryption**: secret values (and other sensitive columns) are AEAD ciphertext blobs in ordinary columns; the schema and the crypto are identical on sqlite and postgres because the datastore only ever sees `BLOB`/`bytea`. This is exactly how Infisical (postgres) ([security internals](https://infisical.com/docs/internals/security)) and Vault (any storage backend — "all data leaving Vault" is barrier-encrypted, storage is untrusted) ([security model](https://developer.hashicorp.com/vault/docs/internals/security)) achieve storage-engine independence. Trade-off: non-secret metadata (names, paths, timestamps) stays plaintext unless explicitly enumerated for encryption — which is fine, and honest, as long as docs say so (Vault's approach: encrypt everything below the barrier; Infisical's: encrypt designated sensitive fields).

**Verdict for a pluggable datastore: field-level envelope encryption, unambiguously.** Whole-file protection of the sqlite DB is then an *operator-optional* layer (LUKS/ZFS dataset encryption), not Hikyo's concern.

## 8. Ranked recommendation for Hikyo

### R1 — Key hierarchy (recommended design)

Three levels, Infisical-shaped but 256-bit from day one:

1. **Root key (KEK)**: 256-bit, operator-provided, never stored in the DB. Wraps only level 2.
2. **Master key**: 256-bit random, generated at first startup, stored wrapped in the DB (single row, versioned). Wraps level 3. (Mirrors Infisical's "Internal KMS Root Key" ([source](https://infisical.com/docs/internals/security)) and Vault's root-key/keyring split ([source](https://developer.hashicorp.com/vault/docs/concepts/seal)).)
3. **Per-project DEKs**: 256-bit random, stored wrapped by the master key. Encrypt secret values (and designated sensitive config fields). Gives blast-radius isolation, per-project rotation, crypto-shred on project delete ([Infisical precedent](https://infisical.com/docs/internals/security)).

AEAD: **XChaCha20-Poly1305** (`golang.org/x/crypto/chacha20poly1305.NewX`) for all layers — 192-bit random nonces eliminate the nonce-management problem permanently ([x/crypto docs](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305), [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)). AES-256-GCM is the acceptable runner-up if FIPS alignment ever matters (Vault/Infisical precedent ([1](https://developer.hashicorp.com/vault/docs/internals/security), [2](https://infisical.com/docs/internals/security))), at the cost of needing Vault-style usage-count rotation discipline ([source](https://developer.hashicorp.com/vault/docs/commands/operator/rotate)).

Every ciphertext (wrapped keys and data) carries a versioned header: format version, algorithm ID, key ID + key version, nonce. Non-negotiable in v1 — it is what makes lazy rotation (§3) and future KMS backends possible. Use AAD to bind ciphertexts to their context (e.g. project ID) so rows can't be swapped between projects.

### R2 — Root-key bootstrap: default + hardening tiers

- **Tier 0 (default)**: `HIKYO_ROOT_KEY` env var or `--root-key-file` path, 256-bit; generated by `hikyo init` which prints it once with a blunt "store this outside this machine" warning. Unattended restarts work; matches Infisical's operational model ([source](https://infisical.com/docs/self-hosting/configuration/envars)) but at 256-bit, and matches homelab reality (k8s local-key caveats apply and should be documented ([source](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/))).
- **Tier 1 (Linux/systemd hardening, docs-only)**: deliver the same key via `LoadCredentialEncrypted` (TPM2/host-key bound, AES-256-GCM) — unattended restart *and* offline-theft protection, zero Hikyo code since the key still arrives as a file/env ([systemd CREDENTIALS](https://systemd.io/CREDENTIALS/)). Docs must mandate an escrowed copy because TPM-bound blobs die with the board ([same source](https://systemd.io/CREDENTIALS/)).
- **Tier 2 (optional, post-v1)**: external KMS unwrap of the master key (Vault-style auto-unseal boundary ([source](https://developer.hashicorp.com/vault/docs/concepts/seal))) behind a `wrap/unwrap` provider interface; document the OpenBao failure mode (KMS gone = data gone without recovery material ([source](https://openbao.org/docs/concepts/seal/))).
- **Rejected for v1**: Shamir/manual unseal (kills unattended restart — the cost Vault pays deliberately ([source](https://developer.hashicorp.com/vault/docs/concepts/seal)) and the wrong default for single-node self-hosters) and passphrase-derived root keys as the primary mechanism (same restart problem; Argon2id ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)) only becomes relevant if a passphrase mode is ever added, e.g. for encrypted exports).

### R3 — Rotation semantics for v1

- **Root-key rotation**: supported in v1. `hikyo rotate-root-key`: unwrap master key with old root, re-wrap with new. One row rewritten, instant, no data touched (rekey semantics ([source](https://developer.hashicorp.com/vault/tutorials/operations/rekeying-and-rotating))). This is the rotation people actually need after an env-file leak.
- **DEK rotation**: v1 ships versioned keyrings + lazy rotation (new version encrypts new writes, old versions retained for reads — Vault semantics ([source](https://developer.hashicorp.com/vault/docs/commands/operator/rotate))), plus an explicit `hikyo reencrypt --project X` that rewrites rows and then retires old versions (k8s-style eager pass ([source](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/))). Secret managers are small enough that eager re-encryption is cheap; offering only lazy rotation leaves old-key ciphertext around forever.
- **Secret-value rotation**: explicitly out of scope for the encryption layer; separate product feature.

### R4 — Backup encryption stance

DB dumps are already field-level ciphertext, but metadata is not, and a backup that includes the root key is worthless protection (k8s backup caveat ([source](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/))). Stance: `hikyo export` produces an **age-encrypted** archive to one or more operator recipients (X25519 / passphrase / hardware plugin) using `filippo.io/age` ([source](https://github.com/FiloSottile/age)) — SOPS-style multi-recipient wrapping so any one recipient key restores ([source](https://getsops.io/docs/security/)). Docs: never back up the root key alongside the DB; restore requires DB + root key (or export + age identity).

### What remains a DECISION (not research) for the grilling ticket

1. AEAD final call: XChaCha20-Poly1305 (recommended) vs AES-256-GCM — hinges on whether FIPS alignment is a goal Hikyo cares about at all.
2. DEK granularity: per-project (recommended) vs per-project-*environment* vs per-secret — isolation vs key-table size.
3. Which non-secret-value columns are encrypted (secret names? paths? integration configs?) — a data-classification decision.
4. Whether Tier-2 external KMS is in scope for v1 at all, or interface-reserved only.
5. Eager `reencrypt` in v1.0 or v1.x (lazy keyring must be v1.0 either way).
6. Whether `hikyo init` refuses to start with the root key world-readable on disk (strictness vs homelab friction).
7. Hand-rolled versioned envelope layer (recommended, small) vs adopting tink-go's keyset machinery — decide after the envelope layer is speced, against actual size.
