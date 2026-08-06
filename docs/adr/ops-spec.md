# Envweave v1 operational & deployment spec (ADR, locked 2026-08-05)

> **Declared amendment (2026-08-06, [multi-instance.md](./multi-instance.md), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** the composable-maxima catalogue gains the multi-instance entries — directory outbound client bounds (per-remote deadline, response cap, remote count, parallel fan-out, coalescing window, per-viewer and instance-wide aggregate trigger rates) and workspace-session lifetime values (idle/absolute, handoff transaction expiry). Air-gap statement extended: an instance with zero configured remotes performs zero outbound directory connections — behavior unchanged by construction. Details in [multi-instance.md](./multi-instance.md).

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

- **Backup retention: 180 days. No `unlimited` option exists.** Crypto-erasure was removed because the key hierarchy travels in every backup; an immortal backup is an immortal ciphertext archive. The bound is enforced by runbook + shipped timer defaults, since Envweave cannot reach off-box files — **erasure is therefore operator-conditional**: the shipped prune rule only governs copies the operator's tooling manages, and any off-box copy outside it extends the window. The shipped pruner deletes exports where `age > 180 d`, reports its last successful prune (doctor + metric), and pre-migration auto-exports additionally prune on `count > 3` (§ 11).
- **Honest erasure formula, stated in operator docs, scoped precisely:** true erasure = **time to GC eligibility + up to 180 days of backup aging**. GC eligibility is activity-dependent: a payload must age past 90 days **and** be displaced from its environment's last 10 revisions **and** be neither pinned nor current nor under `unlimited` retention. For an actively-publishing environment at defaults that lands at **≈ 270 days**; a quiet environment retains its last 10 **indefinitely** — the keep-if-either rule guarantees rollback material at the deliberate cost of an unbounded erasure clock for those payloads. Pins are visible retention exceptions (§ 8).
- **Recipient hygiene: exactly one age identity per retention class** (one for backups; one for optional long-term escrow if the operator opts in). Retiring a class = destroying its identity **and** every decrypted copy; one survivor of either kind defeats erasure (locked #14).

### Audit trails ([audit ADR](./audit-model.md) — two classes, instance scope, `instance-config`)

- **Class membership is the registry's, restated not redefined** (locked #24): `access` = fetch envelopes + their per-key delivery events (one retention unit), conditional-fetch access records, **and denial events**; `security` = everything else.
- **`security` class: `unlimited` by default** — deliberate evidence-first choice: deleting evidence by default is the wrong default at this envelope. The disk consequence is handled, not ignored: sizing guidance in the ops docs (≈ 350 B/event envelope estimate ⇒ 1 M events ≈ 350 MB), **disk high-water warnings at 80 % and 90 % of the data volume** (doctor + metric + UI banner), and the pruning-health surface (§ 10). Flipping to a bounded window is the explicit compliance/capacity decision, audited as a security-class event (locked #24).
- **`access` class: 90 days.** Note the mismatch honestly: pinned and last-N payloads can outlive 90 days, so "who fetched this value" is *not* answerable for the full life of every inspectable value — the trail answers it for the access window, retention policy governs the rest.
- Envelope + per-key events prune as one atomic unit (locked #24). The operator-shortens-retention-and-waits residual remains inside #24's operator-equivalence boundary, unchanged.

### Audit operations values (delegated by #24)

| Value | Default |
|---|---|
| Free-text field bound (post-sanitization, `ew_`-grammar redaction per locked #24) | **1 KiB per field** |
| Export page size (committed bounded pages, fresh proof per page — locked) | **1 000 events/page** |
| Concurrent audit exports | **2 per org, 6 per instance** |
| Query results | paged, **≤ 1 000 events/page**; no unpaged reads exist |
| Scheduled off-box export | `automation`-kind SA holding `audit-read` (allowlisted, locked #24); credential lifetime & limits per § 5 |

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

Login-transport values (delegated by the [API/CLI ADR](./api-cli-surface.md)):

| Value | Default |
|---|---|
| Loopback authorization code | **10 min expiry, single-use**, PKCE S256 only, ≥128-bit `state` (code+state only in the front channel — locked) |
| Device flow (`RFC 8628`) | user code **8 chars (Crockford base32)** · **15 min expiry** · poll interval **5 s**, `slow_down` doubles to max 30 s · single consumption (locked shape) |
| Meta endpoint | pre-auth, **60 req/min per IP**, closed allowlist (locked #25) |
| All login/reauth endpoints | inside the pre-auth admission budget below; overflow = the same uniform `429` |

Pre-auth admission (instance-wide — per-account/per-IP alone never trips on a distributed attempt burning `m` MiB per verification):

- **Concurrency is derived, not fixed — global-headroom model: `concurrent verifications = clamp(floor((admission_budget − 16 MiB) / m), 1, 8)`**, with **`admission_budget` default 272 MiB** (256 MiB of verification work + 16 MiB global implementation headroom, reserved once, not per worker) and Argon2id `m` as configured. At the locked floor (`m=64 MiB`) that yields 4. Raising `m` lowers concurrency automatically instead of silently doubling the RAM bill. **Boot invariant (fail fast): the server refuses to start unless `admission_budget ≥ m + 16 MiB`** — with the invariant held, the formula's lower bound of 1 always fits inside the budget; a configuration where one verification cannot fit is a config error, not a runtime surprise. The budget is instance-config with the floor-hardware warning attached.
- **Queue depth 16**; overflow ⇒ uniform `429 + Retry-After` on **every** pre-auth path — same body, same timing (enumeration-uniform, one layer earlier than #15's unauthorized-≡-nonexistent).
- **Per-IP: 10 auth attempts/min** (sliding). **Per-account throttle, defined exactly: after 5 consecutive failures, delay = `min(2^(failures−5), 60) s`**, applied before verification begins, shared across concurrent attempts on the account (they queue behind the same delay), reset on success. **No hard lockout** — lockout is a free DoS lever against a known username.
- **Argon2id `m=64MiB, t=3, p=2` — locked #16 as the boot-verified floor; parameters may be raised, never lowered below the floor.** Restated here only for completeness; not a fresh decision.
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
| Max `exp − iat` | **24 h** — see grounding below |
| Max token age (`now − iat`) | **24 h** |
| Max positive clock skew | **60 s** — also the post-restore quarantine boundary (`iat > reactivated_at + 60 s`, permanent predicate, locked #17) |
| JWKS refresh | **1 h**; **serve-stale up to 24 h** on fetch failure, then fail closed; unknown-`kid` refresh **max 1/min per issuer**, inside the pre-auth admission budget; static JWKS file for air-gap (locked) |
| Machine fetch rate | **30/min sustained, burst 60, per service-account principal** — aggregated across all of the SA's live credentials and federated presentations (#17 fixes the bound per-*principal*; a per-credential bound would quintuple it via the credential cap and has no stable key under federation). This is the real disclosure bound for a stale-cursor client (locked honesty, #17): ~43k full fetches/day ceiling per SA, loud in the `access` trail. |

Grounding for the 24 h caps: Kubernetes projected SA token TTL is per-pod configuration (`expirationSeconds`, commonly defaulted to 1 h); the kubelet rotates at 80 % of TTL or 24 h, whichever is sooner — so tokens legitimately presented can carry TTLs up to 24 h, and Forgejo/GitHub Actions tokens run ~10 min. The caps admit every legitimate issuer shape and refuse vanity year-tokens; a binding whose issuer mints `exp − iat > 24 h` is refused **by name** with the cap in the error.

Tightening a lifetime ceiling enumerates affected credentials before clamping (locked #17).

## 6. Docker Compose client values ([compose ADR](./compose-integration.md))

- **Offline snapshot max age: 7 d**, server-asserted expiry, per-target overridable **downward only**. Rationale: snapshots exist for boot-ordering (Envweave is a container in the same stack) and short outages; 7 d bounds revocation for a box that never fetches without bricking stacks over a vacation-length outage. Clock-rollback residual stays as #18 stated it.
- **Sync timer: conditional fetch every 5 min** (shipped systemd timer example); cursor makes steady state cheap; well under the per-principal server cap.
- **Render-generation retention: current stamped generation + previous 3.** The stamped generation is never collected (locked).
- **Runtime directories:** plaintext only ever on tmpfs — `/run/envweave/<target>/` (system) or `$XDG_RUNTIME_DIR/envweave/` (user). Durable state (stamps, generations, snapshots) under `/var/lib/envweave/` or `$XDG_STATE_HOME/envweave/`, `0700` dirs / `0600` files (matches #22's client local-state rule, doctor-verified). Reference systemd unit + timer ship; OpenRC/cron documented.
- **Stamp key and snapshot key are deliberately not backed up.** Both are local-random cache keys: loss = harmless full re-render / re-fetch when next online. Backing them up widens the offline-disclosure surface for zero recovery value. Stated so nobody "fixes" it.
- **Reconnect reconciliation is an ordering rule, not a window:** offline per-key audit records flush to the server **before** the next fetch proceeds. A box that can fetch can reconcile. The never-reconnecting box remains #18's stated residual: disclosure with no server-side record.
- **`run --` preflight (the `execve` composite bound):** before exec, the client sums the rendered environment (`name=value\0` bytes), the inherited environment, and argv against the runtime limit (`sysconf(_SC_ARG_MAX)` minus a 64 KiB safety margin) and **refuses loud pre-exec** naming the overage — the per-value cap (§ 8) bounds one string, not the composite, and `E2BIG` at exec time is the wrong layer to discover it.

## 7. Kubernetes operator values ([k8s ADR](./k8s-integration.md))

- **Per-CR conditional fetch (requeue): 5 min** — deliberately the same rhythm as Compose: one revocation/update latency to reason about across both integrations. Per-CR identity (locked) keeps each CR's SA under the per-principal limit with room to spare.
- **Error backoff: exponential, 1 s base → 5 min cap, jittered.** Unreachable server / dead credential ⇒ retain last-synced Secret + loud condition, no staleness scrub (locked).
- **Full informer resync: explicitly configured to 10 h** (matches the controller-runtime default, which carries ±10 % jitter; the value is set in our config, not inherited, and the controller-runtime version is pinned per #22's supply-chain rules) — missed-event insurance, not a delivery mechanism.
- **Operator resources: requests `50m` CPU / `64Mi`, limits `200m` / `128Mi`** *(measured — verify on Pi-class before freeze)*. Single-purpose controller, leader-elected singleton.
- **JWKS bounds per cluster: identical to § 5** — one JWKS policy everywhere.
- **Stamp root (namespace Secret, locked #22): not backed up.** Regeneration ⇒ one benign full-fetch + re-stamp cycle, **no restart wave** (locked #19 amendment). Runbook: rotate, don't restore.
- **K3s `--secrets-encryption` callout: mandatory** (locked #19); runbook text carried from the [k8s ADR](./k8s-integration.md) and [k8s-delivery research](../research/k8s-delivery.md). **`secretbox` version floor, stated concretely: K3s ≥ v1.30.12+k3s1 / v1.31.8+k3s1 / v1.32.4+k3s1 / v1.33.0+k3s1** (the releases where K3s gates secretbox provider support); below these, the runbook prescribes the AES-CBC default with its stated weaknesses.

## 8. Structural bounds

### Environments & publish ([inheritance ADR](./inheritance-model.md) — see tombstone, § 13)

- **Base-chain depth: N/A — superseded by the flat-model amendment** (adopted in #20; amendment ADR outstanding). This entry is a named tombstone: if the amendment retains any layering, it supplies its own depth bound.
- **Max environments per project: 50**, loud refusal. The matrix UI is legible to ~15; 50 is 5× headroom over any real matrix at the envelope while stopping runaway env-minting scripts.
- **Publish fan-out cap = the env cap.** Publish materializes all affected envs atomically (locked); with envs bounded, fan-out needs no second number.
- **Composability, enforced at configuration time, not discovered at publish:** a project carries a **resolved-cell budget: environments × declared keys ≤ 100 000** — the operation that would exceed it (creating the env, declaring the key) is refused loud, naming the budget. This makes the maxima compose by construction: the per-publish ceiling below can always be met by a legal configuration. Work budgets: **per-environment 10 000 validations / 5 s, per-publish 100 000 validations / 30 s hard deadline**, abort loud. **Storage: per-project payload high-water warning at 1 GiB** (doctor + metric + UI banner) and a **hard refusal of new publishes at 4 GiB** — retention policy (§ 2) is the governing control; the hard stop exists so a pin-heavy or unlimited-retention project cannot exhaust the shared disk, and the refusal names the pins/retention setting holding the space.

### Schema & validation ([schema ADR](./schema-model.md))

- **Library pin: `github.com/santhosh-tekuri/jsonschema/v6`** (2020-12, vocabulary control). **Conformance baseline: the official JSON-Schema-Test-Suite subset covering exactly the allowlisted keywords, run in CI.**
- **Keyword allowlist, enumerated** (the locked ADR fixes the mechanism — allowlist, rejected-at-declaration — and delegates the list): core `$ref` (in-document), `$defs`, `type`, `enum`, `const`, `anyOf`, `allOf`, `not`; objects `properties`, `patternProperties`, `additionalProperties`, `required`, `dependentRequired`, `minProperties`, `maxProperties`; arrays `items`, `prefixItems`, `contains`, `minContains`, `maxContains`, `minItems`, `maxItems`, `uniqueItems`; strings `minLength`, `maxLength`, `pattern`; numbers `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf`; annotations `title`, `description`. **Everything else is rejected at declaration by name** — notably `oneOf` (XOR clash, locked), `format`, `$dynamic*`, `unevaluated*`, `$anchor`, `contentEncoding`/`contentMediaType`, external `$ref`. `const`/`enum`/`examples` remain prohibited on `secret` keys at any depth (locked #13). This list is the CI artifact finding-checked against the test-suite subset.
- **Value size: ≤ 64 KiB per value.** Grounded: Linux `MAX_ARG_STRLEN` (128 KiB) bounds one `name=value` string on the `execve` path; 64 KiB leaves margin for the name and platform variance. The *composite* argv+environment bound is the client preflight (§ 6).
- **Per-target render total: ≤ 1 MiB** — grounded in the Kubernetes Secret validation limit (1 MiB); etcd's separate request bound (default 1.5 MiB) is not the operative constraint. **Refused by name at publish** for targeted envs — never discovered at delivery.
- **Declaration bounds: ≤ 64 KiB JSON Schema per key; `$ref` nesting ≤ 32** (in-document, acyclic — locked); **≤ 256 subschemas per declaration; `enum` ≤ 256 members; `pattern` ≤ 512 chars** (RE2, locked — no ReDoS, this bounds compile cost); **`any_of` ≤ 8 alternatives**.
- **Evaluation budgets — the locked step+deadline+aggregate triple, all three supplied: 10 000 evaluation steps per value** (a step = one keyword application against one instance location, counted by the validation wrapper), **100 ms deadline per value; per-env and per-publish aggregates per § 8-envs above**, abort loud. **Validation error reporting: ≤ 100 errors / 64 KiB per verdict** (schema locations only, never instance paths — locked #12). **Compiled-validator cache: LRU 1 024 schemas.**
- **Pending versions: ≤ 100 per project**, loud; **per-user working state: exactly 1 per (user, project)** (locked #11 shape; restated as the quota it implies). **Superseded never-published versions GC after 30 d.** **Schema-revision rate limit: 60/h per project** — generous for humans, bites scripts.

### Source of truth ([source-of-truth ADR](./source-of-truth.md))

- **Plans: expire 24 h; ≤ 20 open per project.** A plan pins digest + revisions and `apply` rejects on movement (locked); an old plan is already dead — expiry just stops the pile-up.
- **Bundle: ≤ 1 MiB, ≤ 10 000 keys** (the envelope's own ceiling), refused by name.
- **Scaffold input: ≤ 1 MiB, ≤ 5 000 lines.**

### Pins & grants ([permission](./permission-model.md) / [revision](./revision-model.md) ADRs)

- **Pins: mandatory expiry, default 180 d, max 365 d, renewable; quota 100 per project.** The revision ADR fixes that every pin carries an expiry and that only a **live** pin holds its payload against GC (locked #11); this spec supplies the values and the expiry semantics, honoring both that rule and the no-silent-change rule (#18/#30): **expiry ends the pin's retention protection, never silently changes delivery.** Expiry warnings fire at 30/7/1 d (same rhythm as § 5). At expiry the payload re-enters normal retention (§ 2); **delivery continues unchanged while the payload survives**, under a loud condition (UI badge, doctor, CR condition where applicable); if the payload is then collected, delivery **fails loud** — the already-locked collected-revision behavior (#11/#30) — until the workload is re-pinned or released. Nothing silent: the failure mode is a refusal with a name, never a value switch. Renewal is a re-authorization (pin authority re-check, locked #17/#30). **A pin is a visible, audited, quota-bounded, expiry-bounded retention exception.**
- **Grants: ≤ 1 000 per org**, loud sanity cap — exists to make runaway grant-minting loud, not to ration.

## 9. Encryption operations ([encryption ADR](./encryption-model.md))

- **Root-key escrow: mandatory offline copy** — root loss = master unwrappable = database **and every backup** unreadable = total value loss. The runbook requires one offline escrow copy (password manager entry or sealed age-encrypted file), custody-separated from backup storage (§ 2 hygiene). **`doctor` warns until an escrow-verified timestamp exists**, and the quarterly restore test (§ 11) includes proving the escrow copy still unwraps.
- **Re-encryption after rotation: background, chunked 100 rows, 100 ms inter-chunk pause, resumable, per-row compare-and-swap** (CAS locked by #16's amendment — a lock-free reencrypt must not resurrect a superseded password). **Runtime is a function of retained rows, not the entry envelope** — historical ciphertexts and pinned payloads all rewrap, so the job **preflights a row count and reports it** (UI + CLI progress as rows/chunks done); no wall-clock promise is made. Pi-friendly by construction (the pause bounds write contention).
- **DEK cache: LRU, 1 024 entries** — effectively every DEK at the envelope, but a *declared* bound; eviction is a re-unwrap, not a failure.
- Carried verbatim from the encryption ADR (runbook obligations, no new decisions): the 5-step post-compromise recovery order (root → master → DEKs → reencrypt → token key, token key last and once); the dual-wrapped crash-safe root rotation; `scrypt`-stanza exclusivity for passphrase backups; backup-identity vs root-key custody separation; the VM-snapshot RNG hazard note (don't resume the server from snapshots; regenerate instead).

## 10. Server runtime ([system-architecture ADR](./system-architecture.md))

- **TLS: reload on cert-file change (watch) + SIGHUP**, no restart — acme/certbot renewals picked up automatically.
- **HTTP server limits** (delegated hardening values — the floor is 4 GB and must survive a slowloris): `MaxHeaderBytes` **64 KiB**; request body cap **2 MiB** global (the 1 MiB bundle is the largest legitimate body; per-route caps tighter where the route's payload is known); `ReadHeaderTimeout` **10 s**, `ReadTimeout` **30 s**, `WriteTimeout` **60 s** (SSE exempt from `WriteTimeout`, governed instead by the 30 s heartbeat + a per-write deadline of 30 s and the slow-client disconnect rule, locked #22); `IdleTimeout` **120 s**; **in-flight request cap 512**, overflow `429`. **Security headers: the #22 CSP baseline plus `Strict-Transport-Security` (non-loopback TLS), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`** — carried set, values fixed here.
- **DB pools: postgres max 10 connections** (floor-sized; instance-config for bigger hardware); **sqlite: single writer + read pool of 4** (locked engine shape; these are the numbers).
- **SSE: heartbeat 30 s; admission caps 4 per principal / 32 per org / 128 per instance** (3-level admission, locked shape).
- **Transactions: 3 attempts, jittered backoff 10/50/250 ms** for pg `40001`; **sqlite `busy_timeout` 5 s set on every connection** — it bounds each *lock wait*, not the transaction (per-statement waits accumulate), so an **overall per-transaction deadline of 15 s** clamps the cumulative wait; the whole-closure retry (locked #22) runs inside it.
- **API rate limit (authenticated): 300 req/min per session, burst 600** — invisible to humans; bounds a leaked session's scrape rate. Machine principals carry § 5's fetch limits; pre-auth carries § 4's budget.
- **Expensive-path budgets** (the threat model's per-principal *and* per-org availability controls, applied to every fan-out path): search **30/min per principal, 4 concurrent per org**; `values export` / `audit export` **5/min per principal, 2 concurrent per org, 6 per instance**; publish **10/min per principal, 4 concurrent per org**; adapter sync/trigger **10/min per principal, 4 concurrent per org**; machine-fetch aggregates **300/min per org, 1 000/min per instance** (on top of § 5's per-principal 30/min). **Coverage is closed by a fail-closed default: any endpoint category not named above inherits 60/min per principal and 8 concurrent per org** — no path is unbudgeted by omission. All overflow responses are the uniform `429 + Retry-After`.
- **Response caps: any API response ≤ 5 MiB; list endpoints paged, page ≤ 1 000 items** (audit pages § 2; search pages **≤ 200**).
- **Health: `/healthz`** = process alive; **`/readyz`** = DB reachable + keyring loaded + migrations current — readiness answers "would a request actually work", matching fail-closed serving (locked).
- **Retention/GC scheduler** (the jobs behind § 2 and § 8): **hourly pruning run** covering payload retention, audit classes, render-generation and superseded-version GC, expired plans/tokens/exports; **startup catch-up run** (a box that slept through its schedule prunes on boot); each run chunked with a **10 min deadline**, yielding between chunks; **`last_prune_success` timestamp exposed as a metric and checked by `doctor`; > 24 h since success = loud warning** (ops-log + UI banner — a stuck pruner silently converts every retention bound into `unlimited`, so pruning health is a first-class surface). Prune failures are ops-log events (audit-subsystem *health* lives in ops logs, never event content — locked #24).
- **Metrics cardinality: no per-key, per-principal, per-env, or per-org/project *identity* labels — aggregate totals only** (a label value is a name leaked into the metrics store; #24's trust-boundary logic applies to Prometheus too). With no dynamic identity labels the series set is static: **CI checks the registered families against the ≤ 1 000 budget and greps the forbidden label keys**; runtime cardinality cannot then exceed registration.

## 11. Backup, restore & upgrade

- **Backup cadence default: daily `backup-export`** (shipped systemd timer + K8s CronJob examples) **+ automatic pre-migration export** when public recipients are configured, loud skip otherwise (locked #22). Retention per § 2; **pre-migration auto-exports prune on `age > 180 d` OR `count > 3`, whichever bites first** — infrequent migrations must not turn "keep last 3" into multi-year retention.
- **RPO = 24 h at defaults, as a *target gated on monitored success*, not a schedule** — the metric + doctor check is `last_successful_backup_export`; > 26 h since success = loud warning (the same pruning-health philosophy: a silently failing timer converts RPO to ∞). Tighten by raising cadence — one timer line.
- **RTO = one restore-runbook execution, target < 30 min on floor hardware** — verified by the restore test, not promised from hope.
- **Restore-test cadence: quarterly (90 d)** — full runbook execution against a scratch instance, **including the root-key escrow unwrap proof**. `doctor` warns when the recorded last-test timestamp exceeds 90 d.
- **Restore is a fail-closed security event with an enumerated checklist** (assembled from locked #8/#14/#16/#17/#19/#28 — the runbook lists, in order): human credential epoch advances covering **every restored authenticator — password verifiers, TOTP seeds, and recovery-code batches are all invalid pending re-establishment** through the credential-establishment authority (restored verifiers never trusted as-is, locked #16); **WebAuthn credentials re-validated per account before re-trust** (a pre-backup attacker enrolment must not resurrect); all sessions invalid; per-account re-activation is an informed per-principal assertion, **no bulk-accept** (the machine rule #17 states, applied to humans identically); machine bearer verifiers **never re-activated** — re-mint and redistribute per SA; federated bindings survive but presented tokens need `iat > reactivated_at + 60 s` (§ 5); OIDC links re-validated, not trusted; adapter outbound credentials re-entered (write-only, unreadable from the DB by design); single-use artifacts (invitations, resets, bootstrap, establishment windows) void; restored grants inert until an operator commits the reconciled set; audit reconciliation recorded instance-side. **Until redistribution completes, workloads on bearer credentials are down — stated plainly** (locked #17; the standing argument for federation).
- **Migrations: roll-forward only** (locked); **downgrade = restore from backup, stated flatly** — no down-migrations exist. Version-skip upgrades within a major are supported (migrations run sequentially internally). Client/server skew is governed by #25's per-operation minimum-revision registry, not by this spec.

## 12. Adapter operations ([deployment-adapter ADR](./deployment-adapter.md) — delegated values)

| Value | Default |
|---|---|
| Outbox retry curve | exponential **30 s → 1 h cap, jittered**; retries do not give up (matches the no-staleness-scrub stance) but **> 1 h failing = loud condition** on the target + ops-log |
| Outbox depth | **1 000 entries per target**; overflow refuses new syncs loud (a target that far behind needs an operator, not a deeper queue) |
| Outbox concurrency | **1 per target** (the exclusive per-target lease is locked; this states it as the concurrency), **4 targets in flight per org** (§ 10 budget) |
| Provider response body cap | **1 MiB** read limit on every Forgejo API response |
| Ledger bound | **≤ 10 000 rows per target**, loud refusal (mirrors the key envelope) |
| Breadcrumb sentinel | exact string **`MANAGED_BY_ENVWEAVE`** on both surfaces (locked name; this fixes the value as the literal, no interpolation — the *ledger* is authority, the breadcrumb is a human hint, locked) |
| Minimal-token recipe | runbook: Forgejo **scoped PAT, write-only, `write:repository` + `write:organization` only as the target scope requires**, floor ≈ v1.21 verified by `TestConnection` (locked refuse-by-name below floor) |

## 13. Cross-cutting posture

- **Air-gap: first-class documented mode, free by construction** — every egress dependency was already rejected by locked decisions (hosted IdPs killed on egress-as-boot-requirement #16; static JWKS exists for exactly this #17; no telemetry; release signatures verified client-side at install). The runbook lists the three things that change: static JWKS file, offline install artifacts, manual update cadence. **CI invariant: the server boots and serves with outbound network denied.**
- **HA: none in v1, said plainly.** Single server replica; sqlite is single-writer; the operator's leader election is failover for the operator, not the server. Scale-out is a post-v1 trigger recorded at the MVP boundary (#26).
- **Signing re-key/revocation** (existence required by #22): offline cosign key custody; re-key and revocation mechanics are fixed by the [OSS mechanics ADR](oss-mechanics.md) (#33), which this spec delegates to — release-range key validity (cutoff/activation, **no overlapping signing window** — this supersedes an earlier one-release-overlap sketch here), recovery-root-signed revocation, monotonic trust metadata. The human ceremony (custody, steps, ownership) is governance → [OSS project mechanics #33](https://github.com/Dunky13/envweave/issues/33).
- **Release support policy → #33** (cadence, versioning, support window are governance). This spec keeps only upgrade *mechanics* (§ 11).

## 14. Boundary notes

- **Flat-model amendment ADR outstanding** (adopted in #20; supersedes the inheritance ADR): § 8's chain-depth tombstone anchors it. It blocks synthesis (#27), not this spec.
- **Deferred to #33:** release cadence/support window; signing-ceremony human process; both cross-referenced above.

## 15. CI-enforced invariants added by this spec

1. Argon2id floor: boot refuses below `m=64MiB, t=3, p=2` (restates #16 — the check exists; the values live here).
2. Common-password list file hash pinned; CI fails on drift.
3. Metrics: registered families ≤ 1 000 series budget; forbidden label keys (`key`, `principal`, `credential`, `env`, `org`, `project`, or values thereof) fail the build.
4. Air-gap: server boots and serves with outbound network denied.
5. JSON-Schema-Test-Suite subset (exactly the § 8 allowlist) passes against the pinned library version.
6. Postgres durability boot checks (`fsync=on`, `synchronous_commit=on`) and sqlite pragmas (`synchronous=FULL`) — restates #24/#22; values live in those ADRs, presence of the check is asserted here.
7. Keyword allowlist in code matches the § 8 enumeration (single source, generated or diffed).
8. `run --` preflight covers the composite `_SC_ARG_MAX` bound (unit-tested against a synthetic near-limit environment).

## Decision inventory (quick reference)

| # | Value | Default |
|---|---|---|
| 1 | Calibration floor | Pi 4 4 GB sqlite **and** 2 vCPU/4 GB VPS |
| 2 | Payload retention | keep-if-either: 90 d OR last 10 |
| 3 | Backup retention | 180 d, no unlimited; erasure = GC eligibility + ≤ 180 d (≈ 270 d active env; quiet-env last-10 unbounded, stated) |
| 4 | Audit retention | security unlimited (+ disk high-water 80/90 %) · access 90 d |
| 5 | Reveal window / cap / remask | 15 min / 4 h / 30 s (protected fixed 0) |
| 6 | Sessions | browser 7 d/30 d · CLI 30 d/90 d |
| 7 | Flow tokens | bootstrap 24 h · invite 7 d · reset 1 h · establishment 15 min · 10 codes · authz code 10 min · device 15 min/5 s poll |
| 8 | Admission | budget 272 MiB, concurrency `floor((budget−16 MiB)/m)` (4 @ floor) · boot refuses `m+16 MiB > budget` · queue 16 · 429 uniform · 10/min/IP · `min(2^(f−5),60)s` · no lockout |
| 9 | Machine credentials | 90 d/365 d · indefinite opt-in · 5 per SA · warn 30/7/1 d |
| 10 | Federated tokens | exp−iat ≤ 24 h · age ≤ 24 h · skew 60 s · JWKS 1 h/24 h/1-min-kid · fetch 30/min burst 60 per SA principal |
| 11 | Compose | snapshot 7 d · sync 5 min · gens current+3 · keys not backed up · flush-before-fetch · ARG_MAX preflight |
| 12 | K8s operator | requeue 5 min · backoff 1 s→5 min · resync 10 h (explicit) · 50m/64Mi–200m/128Mi · secretbox floor named |
| 13 | Envs/publish | ≤ 50 envs · fan-out = env cap · resolved cells ≤ 100 k (config-time) · 10 k/5 s per env · 100 k/30 s per publish · storage warn 1 GiB / refuse 4 GiB · chain depth N/A (flat) |
| 14 | Schema | allowlist enumerated · value 64 KiB · render 1 MiB/target · decl 64 KiB/depth 32/256 subschemas/enum 256/pattern 512/any_of 8 · 10 k steps + 100 ms/value · errors ≤ 100 · cache 1 024 · pending 100 · GC 30 d · 60 rev/h |
| 15 | Plans/pins/grants | plans 24 h/20 · bundle 1 MiB/10 k · scaffold 1 MiB/5 k · pins expiry 180 d (protection ends, delivery loud-fails on collection) /quota 100 · grants 1 000/org |
| 16 | Encryption ops | escrow mandatory+doctor · reencrypt 100 rows/100 ms CAS, row-count preflight · DEK LRU 1 024 |
| 17 | Runtime | HTTP limits + headers fixed · pools pg 10/sqlite 1+4 · SSE 30 s, 4/32/128 · tx 3×10/50/250 ms · busy 5 s + 15 s tx deadline · API 300/min · expensive-path budgets · responses ≤ 5 MiB/paged · pruner hourly + health |
| 18 | Backup/restore | daily + pre-migration (age 180 d OR count 3) · RPO 24 h monitored · RTO < 30 min · restore test 90 d · restore checklist · roll-forward only |
| 19 | Adapter ops | outbox 30 s→1 h, depth 1 000, 1/target · response cap 1 MiB · ledger 10 k/target · PAT recipe |
| 20 | Audit ops | free text 1 KiB · pages 1 000 · exports 2/org 6/instance |
