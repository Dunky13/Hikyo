# Envweave v1 operational & deployment spec (ADR, locked 2026-08-05)

Context: every locked ADR delegated its concrete operational values here — bounds, defaults, cadences, and runbook obligations that are policy, not architecture. This ADR consolidates all of them ([#32](https://github.com/Dunky13/envweave/issues/32)). It decides values; it re-derives no mechanism. Where a mechanism is named, the owning ADR is linked and its text governs. The synthesis ticket ([#27](https://github.com/Dunky13/envweave/issues/27)) assembles; contradictions found here reopen the owning ticket, never get silently patched.

Every bound in this document is **loud**: hitting it is a named, user-visible refusal (per-surface error naming the bound), never a silent truncation or a silent degradation. All defaults are overridable at the stated scope unless marked fixed.

## 1. Calibration floor

All defaults must run comfortably on **both** declared minimum deployments; the weaker box per dimension wins:

- **Pi 4, 4 GB RAM, single node, sqlite** — CPU/crypto floor (Cortex-A72, no ARMv8 crypto extensions; the [encryption ADR](./encryption-model.md)'s XChaCha20-Poly1305 choice is constant-time in software here).
- **2 vCPU / 4 GB x86 VPS, single node** — the generic hosted floor.

No shipped profiles; one set of defaults. Bigger hardware buys headroom, not different behavior. Resource numbers marked *(measured)* below are to be verified empirically on Pi-class hardware before implementation freeze and revisited on measurement, per the verification workstyle.

## 2. Retention & erasure

### Revision payloads ([revision model](./revision-model.md), UI locked in #29/#30)

- **Org default: keep-if-either — age ≤ 90 days OR among the last 10 revisions of its environment.** Pure age empties a quiet env's history; pure count starves a busy env's window; either alone fails.
- Inherit-until-modified per project, **project retention ≤ org cap in both directions, audited** (locked #30). `unlimited` is an explicit org-level choice, never the default.
- Lineage permanent; pinned revisions always kept; collected revisions unrestorable and fail loud (all locked #11).

### Backups ([encryption ADR](./encryption-model.md) — retention bound mandatory)

- **Backup retention: 180 days. No `unlimited` option exists.** Crypto-erasure was removed because the key hierarchy travels in every backup; an immortal backup is an immortal ciphertext archive. The bound is enforced by runbook + shipped timer defaults, since Envweave cannot reach off-box files.
- **Honest erasure formula, stated in operator docs:** true erasure of a value = payload retention + backup retention — the payload must GC from the database, then every backup holding it must age out. **Worst case at defaults ≈ 270 days.**
- **Recipient hygiene: exactly one age identity per retention class** (one for backups; one for optional long-term escrow if the operator opts in). Retiring a class = destroying its identity **and** every decrypted copy; one survivor of either kind defeats erasure (locked #14).

### Audit trails ([audit ADR](./audit-model.md) — two classes, instance scope, `instance-config`)

- **`security` class (everything except machine fetches): `unlimited` by default.** Evidence should not die by default; at the ≤25-user envelope its volume is trivial forever.
- **`access` class (the machine-fetch stream, per-key events): 90 days** — matches the payload window: "who fetched this value" is answerable for as long as the value itself is inspectable.
- Envelope + per-key events prune as one atomic unit (locked #24). The operator-shortens-retention-and-waits residual remains inside #24's operator-equivalence boundary, unchanged.

## 3. Reveal & session values ([permission](./permission-model.md) / [human-auth](./human-auth.md) ADRs, ceremony locked #21)

| Value | Default | Scope |
|---|---|---|
| Reveal reauth window (sliding) | **15 min** | `project-settings`, overridable |
| Reveal absolute cap (activity cannot extend) | **4 h** | `project-settings`, overridable |
| Auto-remask countdown | **30 s** | `project-settings`, overridable |
| Protected-environment window cap | **0 — fixed** (per-disclosure ceremony; effective 0 ⇒ WebAuthn required, TOTP structurally cannot honour it, locked #16/#21) | fixed |
| Browser session | **idle 7 d / absolute 30 d** | instance-config |
| CLI session (distinct artifact, #16) | **idle 30 d / absolute 90 d** | instance-config |

Session lifetime is not a plaintext-exposure window — disclosure is independently gated by the reveal ceremony and assurance policy (locked #16). That is why CLI sessions may run longer than browser sessions.

## 4. Auth-flow tokens & pre-auth admission ([human-auth ADR](./human-auth.md), admission required by [threat model](./threat-model.md))

One-shot token expiries:

| Token | Expiry | Note |
|---|---|---|
| Bootstrap token | **24 h** | expired ⇒ re-mint via local host authority only (SystemProof boot path); never remote |
| Invitation | **7 d** | binds to capability set, never email (locked); revocable |
| Credential reset (`credential-reset` atom) | **1 h** | minted deliberately by org/instance admin |
| Credential-establishment window | **15 min** | the no-session, no-assurance enrolment authority; tightest |
| Recovery codes | **batch of 10** | single-use, display-once; regeneration invalidates the entire prior batch |

Pre-auth admission (instance-wide — per-account/per-IP alone never trips on a distributed attempt burning 64 MiB per verification):

- **Concurrent Argon2id verifications: 4** (4 × 64 MiB = 256 MiB inside the 4 GB floor); **queue depth 16**; overflow ⇒ uniform `429 + Retry-After` on **every** pre-auth path — same body, same timing (enumeration-uniform, one layer earlier than #15's unauthorized-≡-nonexistent).
- **Per-IP: 10 auth attempts/min** (sliding). **Per-account: 5 free consecutive failures, then exponential 2ⁿ s delay capped at 60 s**, reset on success. **No hard lockout** — lockout is a free DoS lever against a known username.
- **Argon2id `m=64MiB, t=3, p=2` — locked #16, boot-verified floor, server refuses to start below.** Restated here only for completeness; not a fresh decision.
- **Common-password list: embedded top-100k** (SecLists/HIBP-derived), pinned file, hash-checked in CI, refreshed per release; checked at set/change time only, never at login (timing).

Proxy trust & WebAuthn deployment guidance (runbook): default = no trusted proxies, direct native TLS; non-loopback plaintext requires explicit proxy mode + trusted-proxy CIDRs (locked #22). RP ID and origins are immutable instance config — set them to the final public hostname **before** first WebAuthn enrolment; changing them later strands every passkey (locked #16). The runbook shows the reverse-proxy pattern (proxy terminates TLS, forwards to loopback, CIDRs name the proxy).

## 5. Machine-identity values ([machine-identities ADR](./machine-identities.md))

| Value | Default |
|---|---|
| `envweave-token` lifetime | **90 d** default · **365 d** instance ceiling |
| Federation binding lifetime | **same terms: 90 d / 365 d** (locked "same terms"; these are the numbers) |
| `indefinite` | distinct value behind `allow_indefinite`, **default off** (locked); covers **both** credential lifetimes and federation bindings; flipping the flag is itself audited. Homelab opts in deliberately. |
| Concurrent live credentials per SA | **5** — rotation overlap needs 2; the cap kills mint-spray |
| Expiry warnings | **30 d / 7 d / 1 d, in-product first** (locked); SMTP transport off by default |
| Max `exp − iat` | **24 h** — admits K8s projected SA tokens (kubelet 1 h TTL, presented up to ~80 % elapsed) and ~10 min Forgejo/GitHub tokens; refuses vanity year-tokens |
| Max token age (`now − iat`) | **24 h** |
| Max positive clock skew | **60 s** — also the post-restore quarantine boundary (`iat > reactivated_at + 60 s`, permanent predicate, locked #17) |
| JWKS refresh | **1 h**; **serve-stale up to 24 h** on fetch failure, then fail closed; unknown-`kid` refresh **max 1/min per issuer**, inside the pre-auth admission budget; static JWKS file for air-gap (locked) |
| Machine fetch rate | **30/min sustained, burst 60, per credential** — this is the real disclosure bound for a stale-cursor client (locked honesty, #17): ~43k full fetches/day ceiling, loud in the `access` trail |

Tightening a lifetime ceiling enumerates affected credentials before clamping (locked #17).

## 6. Docker Compose client values ([compose ADR](./compose-integration.md))

- **Offline snapshot max age: 7 d**, server-asserted expiry, per-target overridable **downward only**. Rationale: snapshots exist for boot-ordering (Envweave is a container in the same stack) and short outages; 7 d bounds revocation for a box that never fetches without bricking stacks over a vacation-length outage. Clock-rollback residual stays as #18 stated it.
- **Sync timer: conditional fetch every 5 min** (shipped systemd timer example); cursor makes steady state cheap; well under the per-credential server cap.
- **Render-generation retention: current stamped generation + previous 3.** The stamped generation is never collected (locked).
- **Runtime directories:** plaintext only ever on tmpfs — `/run/envweave/<target>/` (system) or `$XDG_RUNTIME_DIR/envweave/` (user). Durable state (stamps, generations, snapshots) under `/var/lib/envweave/` or `$XDG_STATE_HOME/envweave/`, `0700` dirs / `0600` files (matches #22's client local-state rule, doctor-verified). Reference systemd unit + timer ship; OpenRC/cron documented.
- **Stamp key and snapshot key are deliberately not backed up.** Both are local-random cache keys: loss = harmless full re-render / re-fetch when next online. Backing them up widens the offline-disclosure surface for zero recovery value. Stated so nobody "fixes" it.
- **Reconnect reconciliation is an ordering rule, not a window:** offline per-key audit records flush to the server **before** the next fetch proceeds. A box that can fetch can reconcile. The never-reconnecting box remains #18's stated residual: disclosure with no server-side record.

## 7. Kubernetes operator values ([k8s ADR](./k8s-integration.md))

- **Per-CR conditional fetch (requeue): 5 min** — deliberately the same rhythm as Compose: one revocation/update latency to reason about across both integrations. Per-CR identity (locked) keeps each credential under its own rate limit.
- **Error backoff: exponential, 1 s base → 5 min cap, jittered.** Unreachable server / dead credential ⇒ retain last-synced Secret + loud condition, no staleness scrub (locked).
- **Full informer resync: 10 h** (controller-runtime default) — missed-event insurance, not a delivery mechanism.
- **Operator resources: requests `50m` CPU / `64Mi`, limits `200m` / `128Mi`** *(measured — verify on Pi-class before freeze)*. Single-purpose controller, leader-elected singleton.
- **JWKS bounds per cluster: identical to § 5** — one JWKS policy everywhere.
- **Stamp root (namespace Secret, locked #22): not backed up.** Regeneration ⇒ one benign full-fetch + re-stamp cycle, **no restart wave** (locked #19 amendment). Runbook: rotate, don't restore.
- **K3s `--secrets-encryption` callout: mandatory** (locked); runbook text and the secretbox version floor are carried from the [k8s ADR](./k8s-integration.md) and [k8s-delivery research](../research/k8s-delivery.md) verbatim — facts, not new decisions.

## 8. Structural bounds

### Environments & publish ([inheritance ADR](./inheritance-model.md) — see tombstone, § 13)

- **Base-chain depth: N/A — superseded by the flat-model amendment** (adopted in #20; amendment ADR outstanding). This entry is a named tombstone: if the amendment retains any layering, it supplies its own depth bound.
- **Max environments per project: 50**, loud refusal. The matrix UI is legible to ~15; 50 is 5× headroom over any real matrix at the envelope while stopping runaway env-minting scripts.
- **Publish fan-out cap = the env cap.** Publish materializes all affected envs atomically (locked); with envs bounded, fan-out needs no second number.

### Schema & validation ([schema ADR](./schema-model.md))

- **Library pin: `github.com/santhosh-tekuri/jsonschema/v6`** (2020-12, vocabulary control for the keyword allowlist). **Conformance baseline: the official JSON-Schema-Test-Suite subset covering exactly the allowed keywords, run in CI.**
- **Value size: ≤ 64 KiB per value.** Grounded: Linux `MAX_ARG_STRLEN` is 128 KiB per `name=value` string on the `execve` path (`run --` execs, locked #25), and a K8s Secret tops out at 1 MiB total; 64 KiB delivers safely everywhere with margin.
- **Per-target render total: ≤ 1 MiB** (K8s Secret/etcd limit), **refused by name at publish** for targeted envs — never discovered at delivery.
- **Declaration bounds: ≤ 64 KiB JSON Schema per key; `$ref` nesting ≤ 32** (in-document, acyclic — locked).
- **Evaluation budgets: 100 ms deadline per value; 5 s + 10 000-validation aggregate cap per publish**, abort loud (locked shape; these are the numbers).
- **Pending versions: ≤ 100 per project**, loud. **Superseded never-published versions GC after 30 d.** **Schema-revision rate limit: 60/h per project** — generous for humans, bites scripts.

### Source of truth ([source-of-truth ADR](./source-of-truth.md))

- **Plans: expire 24 h; ≤ 20 open per project.** A plan pins digest + revisions and `apply` rejects on movement (locked); an old plan is already dead — expiry just stops the pile-up.
- **Bundle: ≤ 1 MiB, ≤ 10 000 keys** (the envelope's own ceiling), refused by name.
- **Scaffold input: ≤ 1 MiB, ≤ 5 000 lines.**

### Pins & grants ([permission](./permission-model.md) / [revision](./revision-model.md) ADRs)

- **Pins: no auto-expiry; quota 100 per project.** A pin is a durable authorized resource (locked #11) bound ≤1 per (workload, env) (locked #30); auto-expiry would silently unpin a workload onto newer values — exactly the silent behavior this project refuses. **Cost stated honestly: pinned payloads never GC. A pin is a visible, audited, quota-bounded retention exception.**
- **Grants: ≤ 1 000 per org**, loud sanity cap — exists to make runaway grant-minting loud, not to ration.

## 9. Encryption operations ([encryption ADR](./encryption-model.md))

- **Root-key escrow: mandatory offline copy** — root loss = master unwrappable = database **and every backup** unreadable = total value loss. The runbook requires one offline escrow copy (password manager entry or sealed age-encrypted file), custody-separated from backup storage (§ 2 hygiene). **`doctor` warns until an escrow-verified timestamp exists**, and the quarterly restore test (§ 11) includes proving the escrow copy still unwraps.
- **Re-encryption after rotation: background, chunked 100 rows, 100 ms inter-chunk pause, resumable, per-row compare-and-swap** (CAS locked by #16's amendment — a lock-free reencrypt must not resurrect a superseded password). Worst case at the envelope ≈ 20 s of real work spread wide; Pi-friendly; progress surfaced in UI + CLI.
- **DEK cache: LRU, 1 024 entries** — effectively every DEK at the envelope, but a *declared* bound; eviction is a re-unwrap, not a failure.
- Carried verbatim from the encryption ADR (runbook obligations, no new decisions): the 5-step post-compromise recovery order (root → master → DEKs → reencrypt → token key, token key last and once); the dual-wrapped crash-safe root rotation; `scrypt`-stanza exclusivity for passphrase backups; backup-identity vs root-key custody separation; the VM-snapshot RNG hazard note (don't resume the server from snapshots; regenerate instead).

## 10. Server runtime ([system-architecture ADR](./system-architecture.md))

- **TLS: reload on cert-file change (watch) + SIGHUP**, no restart — acme/certbot renewals picked up automatically.
- **SSE: heartbeat 30 s; admission caps 4 per principal / 32 per org / 128 per instance** (3-level admission, locked shape).
- **Transactions: 3 attempts, jittered backoff 10/50/250 ms** for pg `40001`; **sqlite `busy_timeout` 5 s** with the same whole-closure retry bound (locked shapes; these are the numbers).
- **API rate limit (authenticated): 300 req/min per session, burst 600** — invisible to humans; bounds a leaked session's scrape rate. Machine credentials carry § 5's tighter fetch limits; pre-auth carries § 4's budget.
- **Health: `/healthz`** = process alive; **`/readyz`** = DB reachable + keyring loaded + migrations current — readiness answers "would a request actually work", matching fail-closed serving (locked).
- **Metrics cardinality: no per-key, per-principal, or per-env labels, ever** — a label value is a name leaked into the metrics store; #24's trust-boundary logic applies to Prometheus too. Org/project totals are gauges. **Target ≤ 1 000 active series, CI-checked against the registered set.**

## 11. Backup, restore & upgrade

- **Backup cadence default: daily `backup-export`** (shipped systemd timer + K8s CronJob examples) **+ automatic pre-migration export** when public recipients are configured, loud skip otherwise (locked #22). Retention per § 2.
- **Pre-migration auto-exports: keep last 3.**
- **RPO = 24 h at defaults** (tighten by raising cadence — one timer line). **RTO = one restore-runbook execution, target < 30 min on floor hardware** — verified by the restore test, not promised from hope.
- **Restore-test cadence: quarterly (90 d)** — full runbook execution against a scratch instance, **including the root-key escrow unwrap proof**. `doctor` warns when the recorded last-test timestamp exceeds 90 d. Restore remains a fail-closed security event (locked #8/#16/#17: verifiers re-epoch, restored grants inert until an operator commits the reconciled set — carried text).
- **Migrations: roll-forward only** (locked); **downgrade = restore from backup, stated flatly** — no down-migrations exist. Version-skip upgrades within a major are supported (migrations run sequentially internally). Client/server skew is governed by #25's per-operation minimum-revision registry, not by this spec.

## 12. Cross-cutting posture

- **Air-gap: first-class documented mode, free by construction** — every egress dependency was already rejected by locked decisions (hosted IdPs killed on egress-as-boot-requirement #16; static JWKS exists for exactly this #17; no telemetry; release signatures verified client-side at install). The runbook lists the three things that change: static JWKS file, offline install artifacts, manual update cadence. **CI invariant: the server boots and serves with outbound network denied.**
- **HA: none in v1, said plainly.** Single server replica; sqlite is single-writer; the operator's leader election is failover for the operator, not the server. Scale-out is a post-v1 trigger recorded at the MVP boundary (#26).
- **Signing re-key/revocation** (existence required by #22): offline cosign key custody; re-key = publish new key in-repo + release notes with a one-release overlap; revocation = advisory + immediate re-key. The human ceremony (custody, steps, ownership) is governance → [OSS project mechanics #33](https://github.com/Dunky13/envweave/issues/33).
- **Release support policy → #33** (cadence, versioning, support window are governance). This spec keeps only upgrade *mechanics* (§ 11).

## 13. Boundary notes

- **Flat-model amendment ADR outstanding** (adopted in #20; supersedes the inheritance ADR): § 8's chain-depth tombstone anchors it. It blocks synthesis (#27), not this spec.
- **Deferred to #33:** release cadence/support window; signing-ceremony human process; both cross-referenced above.

## 14. CI-enforced invariants added by this spec

1. Argon2id floor: boot refuses below `m=64MiB, t=3, p=2` (restates #16 — the check exists; the values live here).
2. Common-password list file hash pinned; CI fails on drift.
3. Metrics: registered series count ≤ 1 000; no label key from the forbidden set (`key`, `principal`, `credential`, `env`, or values thereof).
4. Air-gap: server boots and serves with outbound network denied.
5. JSON-Schema-Test-Suite subset (allowed keywords) passes against the pinned library version.
6. Postgres durability boot checks (`fsync=on`, `synchronous_commit=on`) and sqlite pragmas (`synchronous=FULL`) — restates #24/#22; values live in those ADRs, presence of the check is asserted here.

## Decision inventory (quick reference)

| # | Value | Default |
|---|---|---|
| 1 | Calibration floor | Pi 4 4 GB sqlite **and** 2 vCPU/4 GB VPS |
| 2 | Payload retention | keep-if-either: 90 d OR last 10 |
| 3 | Backup retention | 180 d, no unlimited; erasure ≈ 270 d worst case |
| 4 | Audit retention | security unlimited · access 90 d |
| 5 | Reveal window / cap / remask | 15 min / 4 h / 30 s (protected fixed 0) |
| 6 | Sessions | browser 7 d/30 d · CLI 30 d/90 d |
| 7 | Flow tokens | bootstrap 24 h · invite 7 d · reset 1 h · establishment 15 min · 10 codes |
| 8 | Admission | 4 concurrent · queue 16 · 429 uniform · 10/min/IP · 5-then-2ⁿ≤60 s · no lockout |
| 9 | Machine credentials | 90 d/365 d · indefinite opt-in · 5 per SA · warn 30/7/1 d |
| 10 | Federated tokens | exp−iat ≤ 24 h · age ≤ 24 h · skew 60 s · JWKS 1 h/24 h/1-min-kid · fetch 30/min burst 60 |
| 11 | Compose | snapshot 7 d · sync 5 min · gens current+3 · keys not backed up · flush-before-fetch |
| 12 | K8s operator | requeue 5 min · backoff 1 s→5 min · resync 10 h · 50m/64Mi–200m/128Mi |
| 13 | Envs/publish | ≤ 50 envs · fan-out = env cap · chain depth N/A (flat) |
| 14 | Schema | value 64 KiB · render 1 MiB/target · decl 64 KiB/depth 32 · 100 ms/5 s/10 k · pending 100 · GC 30 d · 60 rev/h |
| 15 | Plans/pins/grants | plans 24 h/20 · bundle 1 MiB/10 k · scaffold 1 MiB/5 k · pins no-expiry/100 · grants 1 000/org |
| 16 | Encryption ops | escrow mandatory+doctor · reencrypt 100 rows/100 ms CAS · DEK LRU 1 024 |
| 17 | Runtime | SSE 30 s, 4/32/128 · tx 3×10/50/250 ms · busy 5 s · API 300/min burst 600 · series ≤ 1 000 |
| 18 | Backup/restore | daily + pre-migration (keep 3) · RPO 24 h · RTO < 30 min · restore test 90 d · roll-forward only |
