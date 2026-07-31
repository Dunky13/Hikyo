# Envweave machine identities & service accounts (ADR, locked 2026-07-31)

Context: the threat model ([#8](https://github.com/Dunky13/envweave/issues/8)) fixed the *floor* for machine credentials — service-account tokens ≥256-bit random, stored as fast-hash verifiers only, scoped to `(project, environment | explicit env list)`, read-only in v1, individually revocable, every fetch audit-logged with token identity, revocation stopping future fetches with the blast radius stated honestly. The permission ADR ([#15](https://github.com/Dunky13/envweave/issues/15)) then fixed *what machine principals may hold* — two normative capability allowlists, `manage-identities` as the administering capability, the mint/widen authorization formula, the pin authority re-check, and the rule that machines never reauthenticate. The human-auth ADR ([#16](https://github.com/Dunky13/envweave/issues/16)) fixed what machine credentials must **not** be — never the human session mechanism, always a distinct artifact type with its own revocation surface, carrying the credential epoch. This ADR fixes **what a machine principal is, what credential kinds authenticate it, the token format and its delivery, lifetime and rotation, federation, restore behaviour, and audit attribution**.

Granularity note: this is the wayfinding-level machine-identity ADR. It fixes the principal model, the credential kinds, the wire format, the mint/rotate/revoke lifecycle, the federation trust model and the audit shape. Mechanism-level detail is delegated: the `EnvweaveSecret` CRD shape, resync semantics, rollout triggering and per-namespace wiring → Kubernetes integration ([#19](https://github.com/Dunky13/envweave/issues/19)); the offline-fallback question on a single Compose box, run-wrapper merge semantics and the systemd recipes → Compose integration ([#18](https://github.com/Dunky13/envweave/issues/18)); the endpoints and CLI verbs carrying each formula → API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25)); the concrete event shapes → audit ([#24](https://github.com/Dunky13/envweave/issues/24)); the chokepoint's siting and the JWKS cache's home → architecture ([#22](https://github.com/Dunky13/envweave/issues/22)); cross-project and cross-org lookup enforcement → tenant isolation ([#23](https://github.com/Dunky13/envweave/issues/23)); the adapter's own outbound credentials → deployment-module seam ([#28](https://github.com/Dunky13/envweave/issues/28)); every concrete duration, quota, threshold and rate → operations spec. Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

> **Amends the permission ADR ([permission-model.md § Authorization formulas](./permission-model.md), [#15](https://github.com/Dunky13/envweave/issues/15)):** that ADR's formula reads *"Mint or widen a credential's scope → `manage-identities(project)` ∧ `reveal(E)` for every **added** environment + reauthentication."* Read literally, a **replacement** credential adds no environment and therefore requires `reveal` on nothing. Because a minted token is delivered display-once **to the acting principal** (§ *Delivery*), that reading lets a principal holding `manage-identities` and no `reveal` rotate a production workload credential and walk away with a live production-reading bearer token — obtaining by rotation exactly what #15 forbids them to obtain by minting. This ADR replaces "every added environment" with **every environment in the resulting credential's scope** (§ *Minting*). It is a tightening of that ADR's own governing principle — *disclosure by proxy* — not a new rule.

## The machine principal

**A service account is a principal in the grant table, and a credential is an authenticator for it.** One service account may hold several live credentials; every credential of a service account confers **identical** authority, because authority is the union of the grants on the principal and nothing else. There is no per-credential scope, no intersection semantics, and no second permission language for machines — as #15 requires.

- **A service account is project-owned.** It is created and administered under `manage-identities(project)`.
- **Its grants are confined to its owning project's subtree.** A grant naming a scope outside that project is refused, regardless of the granter's authority. A workload legitimately spanning two projects holds two service accounts and two credentials.
- **`kind` is declared at creation and is immutable**, one of `workload` or `automation`. The grant API refuses any capability outside that kind's normative allowlist ([#15](https://github.com/Dunky13/envweave/issues/15) § *Machine principals*). A project that guessed wrong creates a second service account; there is no in-place widening of a credential class that N workloads already hold.
- **Machine principals are visibly distinct from human principals** everywhere they appear — grant lists, membership UI, audit attribution (#16's propagation).

*Rejected: per-credential scope narrowing* (one service account, many narrowly-scoped tokens). It is precisely the second permission language #15 forbids: effective authority becomes `grants ∩ credential scope`, and #15's atomic-revocation guarantee acquires a second object to reason about. Narrower access is expressed by creating another service account, which keeps blast radius readable in one list.

*Rejected: the credential **is** the principal* (no service-account container). Rotation becomes a re-grant, so #15's mint formula fires on every routine rotation as a fresh authorization act, and audit attribution loses its stable subject across rotations.

*Rejected: org-owned service accounts, or grants free to land anywhere the granter may grant.* A project-scoped object holding grants in other projects lands on [#23](https://github.com/Dunky13/envweave/issues/23) — "a grant lookup crossing an org boundary is an isolation failure, not an authorization result" — and makes *what can this project's credentials reach* unanswerable from inside the project that administers them.

## Credential kinds

A service account authenticates through one or more **credential kinds**. v1 implements two.

| Kind | Shape | At rest |
|---|---|---|
| `envweave-token` | Envweave-issued opaque bearer token | on the workload's host |
| `oidc-federation` | externally issued OIDC ID token, validated against a configured issuer | nothing |

**Grants attach to the service account, never to a credential kind.** Adding a future kind — machine attestation, a platform-native scheme — is a new row type: no change to the grant model, no re-granting, no principal churn. The API and schema MUST NOT assume the bearer token is the only kind.

## The bearer token — `envweave-token`

### Format

```
ew_<version>_<type>_<body><checksum>
```

- `version` — format version, so a format change is not a flag day.
- `type` — `wl` workload, `au` automation, `cli` CLI session ([#16](https://github.com/Dunky13/envweave/issues/16)), `bs` bootstrap, `inv` invitation, `rst` reset. One family, one scanner rule.
- `body` — ≥256 bits of CSPRNG output, base62.
- `checksum` — CRC over the body, so a CLI or a scanner rejects a truncated or mistyped token with **zero server calls** and secret-scanning false positives collapse.

**Normative: the server trusts nothing inside the token.** The prefix is a hint for humans and for secret scanners. Kind, scope, project, expiry and epoch are read from the database row the verifier resolves to. A token whose prefix says `au` presented against a row of kind `workload` is a workload token.

**Storage is an unsalted SHA-256 verifier under a unique index.** This is the threat model's rule for high-entropy artifacts, not a shortcut: fast hashing is safe *because* ≥256 bits makes brute force infeasible, and it is what makes authentication a single indexed read. Constant-time comparison is used on the resolved row.

*Rejected: JWTs, signed or otherwise.* #15 forbids any cross-request authorization cache and requires revocation effective at next fetch; #16 rejected the same shape for human sessions on the same grounds. A JWT cannot be revoked, and the standard remedy — a denylist — is a credential table with extra steps and a window in which a revoked workload still reads production.

*Rejected: a bare random string with no prefix or checksum.* Unscannable by Forgejo, GitHub or gitleaks, and indistinguishable from any other base64 blob in a leaked file. The scannability of a credential is a security property.

*Rejected: `<credential-id>.<secret>` with a per-row salted hash.* A salt buys nothing against 256 bits of entropy and costs the single-index lookup.

**Accepted cost:** the prefix tells whoever finds a leaked token what they found. It helps an attacker triage marginally, and helps automated scanners and incident responders considerably more.

### Delivery

**A credential value is displayed exactly once, at mint, and is never retrievable afterwards.** List and get return metadata only — prefix, kind, scope, expiry, creation, last-used — never the value; rotation never returns the prior value. This is the write-only rule #15 already fixed for adapter outbound credentials, for the same reason.

**Delivery is never ordinary stdout by default.** #16 settled this argument for the bootstrap token and the physics are identical here: under Docker, Kubernetes, systemd, a NAS application manager or any log shipper, stdout is retained and readable by principals holding neither host access nor the root key. The CLI therefore:

- prints the token **only when stdout is an interactive TTY**;
- otherwise writes it to a path given by `--output-file`, created `O_EXCL` with mode `0600` explicitly (never umask-dependent);
- accepts `--print-token` as an **explicit, deliberate** opt-in for pipelines that consciously want stdout;
- **refuses** a non-TTY stdout write without that flag, rather than downgrading silently.

*Rejected: a blanket non-TTY refusal.* It breaks `envweave sa create --json | jq` and the Kubernetes bootstrap-Secret workflow, both legitimate. The escape is a flag the operator types, not a default.

*Rejected: retrievable from the API until first use.* A stolen database would then *be* a stolen token, breaking the headline guarantee that a dump yields no directly replayable credentials.

### Consumption

**The token reaches a workload through exactly two channels: `--token-file <path>` and the `ENVWEAVE_TOKEN` environment variable.**

**There is no `--token` flag.** A secret in `argv` is visible in `ps`, in `/proc/<pid>/cmdline`, in process listings, and in shell history. The run-wrapper's one clean property — that shell history stays free of secret material — holds only if the flag does not exist to be misused.

When both channels are populated, `--token-file` wins and the collision **warns loudly**; a silent precedence rule on a credential is the kind of quiet ambiguity the fail-loud principle exists to prevent.

**Placement on the host is an operator act supported by documentation, not by Envweave machinery.** The recipes are `systemd` `LoadCredentialEncrypted=` (TPM-sealed at rest, plaintext only in non-swappable ramfs under `$CREDENTIALS_DIRECTORY`, access-checked per open) and, on Kubernetes, a bootstrap Secret.

*Rejected: a single-use enrolment token exchanged at first boot for the real credential.* The credential it hands back sits at rest, long-lived, exactly like the one it replaced — it shortens the clipboard's exposure and nothing else. The honest version of that idea is a credential with **nothing at rest**, which is federation, below.

*Rejected: machine-bound credentials (token plus host attestation) on Compose hosts.* There is no attestation source there to bind to.

### Lifetime

**Every credential carries a lifetime: a finite duration, or the distinct value `indefinite`.** `indefinite` is a value, not a large number — it is unreachable by raising any ceiling.

- **The instance sets a maximum finite lifetime**, under `instance-config`, clamping every project. The per-credential *default* is finite, so the easy path is bounded and a long-lived credential is a typed choice someone made.
- **`allow_indefinite` is a separate instance opt-in, default off.** Raising the ceiling can never manufacture it.
- **Tightening either control enumerates every affected credential to the actor before the change commits**, then clamps — mirroring #16's effective-window transition. A settings change never silently kills a live credential.
- Both controls are audited.

**Expiry warning is in-product first.** Credential-list badges, a warning field on API and CLI responses, a Kubernetes CR status condition and event, and an audit event at each threshold. **Where SMTP is configured it carries the same signal as an additional transport** to the credential's creating principal, to current `manage-identities` holders on the project, and to an optional per-credential contact address. Email is never the only signal: #16 fixed that most self-hosted installations have no mail server, and a warning that exists only in an unconfigured channel is not a warning.

**Recorded operator decision, stated rather than hidden:** an `indefinite` credential has an unbounded validity window, and the threat model's blast radius for a leaked credential is *everything fetchable during that window*. The dominant leak case is the one nobody notices, which is exactly the case expiry bounds. `indefinite` exists because an operator may knowingly accept that for a stable workload; the default-off opt-in and the audit trail are what keep it a decision rather than an accident.

*Rejected: no expiry at all (long-lived static tokens as the only shape).* Revocation is already immediate and re-checked per fetch, so expiry buys exactly one thing — a bound on the unnoticed leak — and without it that bound is infinite for every credential in the installation.

*Rejected: self-renewal* (a live token exchanging itself for a successor). It is a mint performed by a principal holding neither `manage-identities` nor `reveal`, so the token manufactures its own successor and #15's formula is bypassed by design. It also inverts the threat: an attacker actively using a stolen token renews it forever, while the honest unused one dies.

## Minting, rotation, revocation

### Minting

**Every mint — a first credential, a replacement, or a widening — requires `manage-identities(project)` ∧ `reveal(E)` for *every environment in the resulting credential's scope*, plus reauthentication** (see the amendment note above). Creating an `oidc-federation` binding **is a mint** and carries the same formula: it creates a working path from an external identity to this project's plaintext.

Where the service account's grants include `reveal` under #13's explicit per-project opt-in, the UI states at opt-in time that a machine principal holding `reveal` is a standing decryption capability — and that a CI runner holding it is that capability in the most-attacked box in the system.

### Rotation

**Rotation is overlap-based**: mint a second credential, distribute it, revoke the first. Multiple live credentials per service account are permitted precisely so rotation has no downtime; their number is capped, with the value in the operations spec.

**A lost credential is not recoverable, ever.** The service account and its grants survive; a replacement is minted and the lost one revoked. Nothing in the system can return a credential value after mint.

### Revocation

- **Revocation bites at the next fetch, never at expiry** (#15's explicit propagation).
- **Revoking one credential is not deprovisioning.** Grants are untouched; sibling credentials keep working.
- **Deleting a service account revokes every credential and every grant in one transaction** (#15's atomic revocation).
- **Revoking, deleting, narrowing and listing stay under the plain capability** — #15's symmetric limit. Requiring `reveal` to revoke a leaked token would be a self-inflicted incident-response delay.

## Federation — `oidc-federation`

**v1 validates externally issued OIDC ID tokens as a machine credential kind**, removing the at-rest credential entirely wherever the platform issues one. One mechanism covers Kubernetes projected ServiceAccount tokens, Forgejo Actions and GitHub Actions; the platform-specific wiring belongs to [#19](https://github.com/Dunky13/envweave/issues/19) and the docs.

**Issuer configuration is instance-scoped**, under `instance-config`. #16 fixed this exact argument for human providers: an org-scoped issuer would let an org admin add a provider and mint identities authenticating into the instance.

**Verification uses `go-oidc` and the issuer's JWKS. No hand-rolled JWT verification, no hand-rolled signature checking** — #16's no-hand-rolled-primitive invariant applies unchanged.

### Binding

**The binding is explicit: a canonicalized `(issuer, subject)` pair names exactly one service account.** No wildcards, no namespace patterns, no path prefixes, no JIT provisioning. An unbound identity **is not a login** — it does not create a principal and does not authenticate.

This is #16's rule for human identities, and it is load-bearing in both directions:

- On Kubernetes, a pattern rule such as *any ServiceAccount in namespace `prod`* hands an Envweave principal to anyone holding `create serviceaccount` in that namespace — a far wider group than cluster-admin.
- On Forgejo Actions the subject is `repo:<repository>:ref:<ref>`, and a pull-request run carries a **structurally different** subject, `repo:<repository>:pull_request`. Binding the whole subject string therefore excludes PR-triggered runs by construction rather than by a rule someone must remember. Binding on the repository while ignoring the ref is the well-known footgun in this family, and the no-patterns rule forbids it.

**Audience binding is mandatory, and the issuer's default audience MUST be refused.** Every binding names the audience it accepts, and validation requires it. This is not ceremony: a Kubernetes token minted for the default API-server audience would otherwise authenticate to Envweave, and Forgejo's Actions audience **defaults to `<instance>/<repository owner>`** — shared across every repository that owner has, so accepting the default makes any workflow in any of their repositories satisfy the binding.

**ID token validation is complete, not partial:** exact `iss` match against the configured issuer, signature under an algorithm from that issuer's allowlist (never `none`, never algorithm confusion via an unvalidated `alg`), configured `aud`, `exp`/`iat`/`nbf` within a bounded skew, and the bound `sub`. Failure at any step is a refusal, never a downgrade.

**A federated credential has no lifetime of its own to manage.** The presented token's own short expiry governs it; the § *Lifetime* rules apply to `envweave-token` only, and there is nothing to rotate, expire or notify about.

### JWKS

**Keys are fetched and cached, with a bounded staleness window.** While the issuer is unreachable, validation continues from cache up to that bound and then **fails closed, loudly**. Refresh is scheduled, and additionally triggered by an unknown `kid`.

*Rejected: failing closed the moment a scheduled refresh fails.* The failure this must survive is an API-server blip or a network partition between Envweave and the cluster, and that would stop every workload fetch cluster-wide — a self-inflicted outage on a control plane whose delivery story is explicitly *stale-but-valid beats not-starting*. Kubernetes service-account signing keys rotate rarely, so a bounded window costs very little exposure.

**A per-issuer static JWKS is a configured alternative**, for air-gapped installations and for deployments where the issuer's discovery endpoint is unreachable from Envweave. It is configuration, not machinery, and air-gapped operation is a settled product principle. It is not the default: a static-only installation breaks silently on the day someone rotates the issuer's keys.

**Unknown-`kid` refresh is rate-limited, and that is load-bearing rather than hygiene.** It sits on a pre-authentication path, so a stream of fabricated `kid` values is an outbound-fetch amplifier aimed at the issuer. It falls under #16's instance-wide admission budget and the threat model's no-unbounded-work rule.

## Authentication, authorization and the fetch path

- **Machine credentials never touch the human session mechanism** (#16's propagation). They are their own artifact type with their own storage, lifetime, listing and revocation surface. A machine principal has no CLI session, no cookie and no assurance record.
- **Machines do not reauthenticate**, as #15 fixed: the token *is* the credential and there is no second factor to re-present. Machine disclosure is controlled instead by the per-project `reveal` opt-in, narrow scope, individual revocability and per-fetch audit.
- **Every fetch re-authorizes** against current policy at the single chokepoint, in-transaction, uncached (#15 § *Evaluation*). A revoked grant stops delivery on the next fetch.
- **Pinned delivery re-checks the pin's recorded authority principal** for current `reveal-history(E)` on **every** fetch, and fails closed when it is gone (#15 § *Pins*, propagated here explicitly).
- **Pre-authentication admission limits apply to credential presentation and to federated validation**, under the same instance-wide budget as #16's human paths, with responses uniform between an unknown credential and a revoked one — the same unauthorized-is-indistinguishable-from-nonexistent rule, one layer earlier.

## Restore

**Machine credentials carry the credential epoch** (#16), so a restore makes every one of them inert — the mechanism behind the threat model's requirement that *every* pre-restore authentication artifact be invalidated.

**Recovery is a per-credential, explicit re-activation**, committed alongside #15's reconciled grant set while the instance is in recovery mode. A re-activated bearer credential resumes working without redistribution; anything not re-activated is permanently dead.

**There is no bulk-accept.** This is the load-bearing part of the decision, so it is stated as an invariant rather than a UI preference: the restored database is *old*, and a credential revoked **after** the backup was taken appears in it as active. Nothing in the data distinguishes it from a safe one — the operator's memory is the only source of that fact, which is exactly why #16 refused to trust restored human verifiers at all. An "accept all" control converts this informed per-credential assertion back into a checkbox and reintroduces the resurrection hazard the epoch exists to close.

**Federated bindings are re-validated, not trusted** — #16's rule for OIDC identity links, for the same reason: a restore can resurrect a binding removed precisely *because* that workload was compromised. There is nothing to redistribute for them.

*Rejected: permanently killing every bearer credential on restore* (the strictest reading of #16's human rule). It stops every workload on every host until someone physically redistributes tokens, and the pressure that creates is what produces a hasty, unreviewed restore procedure. The per-credential assertion keeps the fleet recoverable while keeping the judgement human.

*Rejected: machine credentials surviving restore untouched.* That is the resurrect-a-revoked-token hazard #8 names outright.

## Audit attribution

**One audit event per fetch**, carrying: the credential (not merely the service account), the service-account principal, the principal class, project, environment, the resolved revision number and change-token version, **the enumerated key ids delivered** with per-classification counts, and the outcome.

**Identical repeat fetches collapse into a counted aggregate** — same credential, same revision, same key set — with first-seen and last-seen timestamps and a count. This is the threat model's own remedy, in #16's words: *bounded by aggregation, never dropped silently*.

**This conforms to #15's per-key rule rather than weakening it.** That rule exists to forbid the *opaque* row — it must always be answerable which keys a principal saw. A machine fetch's key set is fully determined by `(project, environment, revision)`, and the event **enumerates the key ids inline**, so the question is answered exactly. Enumeration is inline rather than by reference because the revision ADR garbage-collects payloads: a pointer-only event becomes unanswerable the day retention expires.

*Rejected: one event per key for machine fetches.* The Kubernetes operator's default resync is measured in seconds; at 40 keys and a 60-second interval a single workload writes on the order of 58,000 audit rows a day, against a threat model that forbids unbounded audit growth and silent dropping alike. It answers the same question as the enumerated event, at a cost that turns the audit log into the availability problem this ticket was told to avoid.

**Credential-level attribution is the point.** The forensic question after a leak is *which token*, and one service account holds several.

## Reconciliation with upstream ADRs

- **Threat model ([#8](https://github.com/Dunky13/envweave/issues/8))** — ≥256-bit tokens stored as fast-hash verifiers, satisfied literally; the `(project, environment | env list)` scoping is expressed as grants on the principal; read-only-in-v1 is the `workload` allowlist; individual revocability, per-fetch audit with token identity, and revocation-stops-future-fetches are all satisfied. The stated blast radius is what § *Lifetime* bounds. Pre-authentication admission limits extend to credential presentation and JWKS refresh.
- **Permission model ([#15](https://github.com/Dunky13/envweave/issues/15))** — the two credential classes are implemented as an immutable `kind` with the normative allowlists enforced by the grant API; the mint formula is implemented and **tightened** by the amendment above; revocation is effective at next fetch; the pin authority re-check is carried on every pinned delivery; machines do not reauthenticate; no machine principal holds `manage-*`, `project-settings` or any instance capability.
- **Human auth ([#16](https://github.com/Dunky13/envweave/issues/16))** — machine credentials do not reuse the human session mechanism and are a distinct artifact type with their own revocation surface; the human/machine principal distinction is visible in audit attribution; the credential epoch is carried so restore invalidates machine credentials by the same mechanism. The never-ordinary-stdout rule is inherited for token delivery; the no-hand-rolled-primitive invariant governs federation; the explicit `(issuer, subject)` binding, the refusal to treat an unknown identity as a login, and the no-JIT rule are the same decisions applied to machines.
- **Source of truth ([#13](https://github.com/Dunky13/envweave/issues/13))** — machine `reveal` remains an explicit per-project opt-in never implied by `apply`, `publish` or `definitions-edit`; the automation credential is the `apply` path and its default posture remains a human applier.
- **Positioning ([#3](https://github.com/Dunky13/envweave/issues/3))** — federation is chosen over an at-rest credential where the platform supplies an identity, without adding a second always-on process; the single-binary posture is intact.

## Propagations (binding on downstream tickets)

- **Compose ([#18](https://github.com/Dunky13/envweave/issues/18))** — MUST consume credentials only via `--token-file` and `ENVWEAVE_TOKEN`; MUST NOT introduce a `--token` flag. The offline-fallback decision (fail-closed versus an encrypted local snapshot) is that ticket's, and MUST NOT reintroduce a retrievable credential.
- **Kubernetes ([#19](https://github.com/Dunky13/envweave/issues/19))** — MUST support both credential kinds; MUST surface impending `envweave-token` expiry as a CR status condition and event; MUST bind federated identities per `(issuer, subject)` with an explicitly configured audience; MUST document K3s `--secrets-encryption` alongside any sync-to-Secret path.
- **Architecture ([#22](https://github.com/Dunky13/envweave/issues/22))** — MUST resolve machine credentials at the same chokepoint as `authorize()`, in-transaction and uncached; MUST site the JWKS cache with its staleness bound and rate-limited refresh; MUST provide the recovery-mode state in which restored credentials are inert.
- **Tenant isolation ([#23](https://github.com/Dunky13/envweave/issues/23))** — MUST enforce the project-subtree confinement of service-account grants; MUST ensure `(issuer, subject)` lookup cannot resolve across an org boundary; MUST keep unknown and revoked credentials indistinguishable in responses and timing.
- **Audit ([#24](https://github.com/Dunky13/envweave/issues/24))** — MUST carry the fetch event shape above including inline key-id enumeration and aggregation; MUST emit events for service-account create/delete, credential mint/rotate/revoke/expire, lifetime-policy changes, federation issuer and binding create/modify/delete, JWKS refresh failure and staleness-bound breach, restore-time re-activation, and authentication failures by cause.
- **API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25))** — MUST document the complete authorization formula for every service-account and credential verb; MUST NOT expose any route returning a credential value after mint; MUST implement the TTY / `--output-file` / `--print-token` delivery rules and the `--token-file` precedence warning.
- **Deployment-module seam ([#28](https://github.com/Dunky13/envweave/issues/28))** — adapter outbound credentials remain write-only and separate from machine identities; an adapter MUST NOT run under a service-account principal in place of #15's recorded authority principal.
- **MVP boundary ([#26](https://github.com/Dunky13/envweave/issues/26))** — a local agent daemon, `--watch` auto-restart, short-lived exchanged tokens, enrolment tokens, machine attestation on Compose hosts, pattern-based federated binding, and an ESO provider's auth surface are recorded here as deliberate exclusions needing explicit in/out confirmation.
- **Operations spec (fog)** — default credential lifetime; the instance maximum-lifetime ceiling; the concurrent-credential cap per service account; expiry-notification thresholds and SMTP delivery policy; JWKS refresh interval, staleness bound and unknown-`kid` rate limit; the audit aggregation window; and the admission budget shared with #16's pre-authentication paths.
