# Envweave machine identities & service accounts (ADR, locked 2026-07-31)

Context: the threat model ([#8](https://github.com/Dunky13/envweave/issues/8)) fixed the *floor* for machine credentials — service-account tokens ≥256-bit random, stored as fast-hash verifiers only, scoped to `(project, environment | explicit env list)`, read-only in v1, individually revocable, every fetch audit-logged with token identity, revocation stopping future fetches with the blast radius stated honestly. The permission ADR ([#15](https://github.com/Dunky13/envweave/issues/15)) then fixed *what machine principals may hold* — two normative capability allowlists, `manage-identities` as the administering capability, the mint/widen authorization formula, the pin authority re-check, and the rule that machines never reauthenticate. The human-auth ADR ([#16](https://github.com/Dunky13/envweave/issues/16)) fixed what machine credentials must **not** be — never the human session mechanism, always a distinct artifact type with its own revocation surface, carrying the credential epoch. This ADR fixes **what a machine principal is, what credential kinds authenticate it, the token format and its delivery, lifetime and rotation, federation, restore behaviour, and audit attribution**.

Granularity note: this is the wayfinding-level machine-identity ADR. It fixes the principal model, the credential kinds, the wire format, the mint/rotate/revoke lifecycle, the federation trust model and the audit shape. Mechanism-level detail is delegated: the `EnvweaveSecret` CRD shape, resync semantics, rollout triggering and per-namespace wiring → Kubernetes integration ([#19](https://github.com/Dunky13/envweave/issues/19)); the offline-fallback question on a single Compose box, run-wrapper merge semantics and the systemd recipes → Compose integration ([#18](https://github.com/Dunky13/envweave/issues/18)); the endpoints and CLI verbs carrying each formula → API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25)); the concrete event shapes → audit ([#24](https://github.com/Dunky13/envweave/issues/24)); the chokepoint's siting and the JWKS cache's home → architecture ([#22](https://github.com/Dunky13/envweave/issues/22)); cross-project and cross-org lookup enforcement → tenant isolation ([#23](https://github.com/Dunky13/envweave/issues/23)); the adapter's own outbound credentials → deployment-module seam ([#28](https://github.com/Dunky13/envweave/issues/28)); every concrete duration, quota, threshold and rate → operations spec. Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

> **Amends the permission ADR ([permission-model.md § Authorization formulas](./permission-model.md), [#15](https://github.com/Dunky13/envweave/issues/15)):** that ADR's formula reads *"Mint or widen a credential's scope → `manage-identities(project)` ∧ `reveal(E)` for every **added** environment + reauthentication."* Read literally, a **replacement** credential adds no environment and therefore requires `reveal` on nothing. Because a minted token is delivered display-once **to the acting principal** (§ *Delivery*), that reading lets a principal holding `manage-identities` and no `reveal` rotate a production workload credential and walk away with a live production-reading bearer token — obtaining by rotation exactly what #15 forbids them to obtain by minting. This ADR replaces "every added environment" with **every environment reachable in the resulting post-state** (§ *Minting and widening*).
>
> The replacement is deliberately phrased over the *post-state*, not over the *mint*, because this ADR puts a machine principal's whole authority in its grants (§ *The machine principal*) — so a credential has no scope of its own to widen, and an ordinary **grant mutation on the service account instantly widens every credential already in circulation**. Without the post-state phrasing, a principal holding `manage-members` and `read(prod)` but **no** `reveal(prod)` adds `read(prod)` to a service account that already carries the § *Minting and widening* `reveal` opt-in, and a token already in the wild begins returning production plaintext — a disclosure by proxy that never passed through a mint. It is a tightening of #15's own governing principle, not a new rule.

> **Amends the human-auth ADR ([human-auth.md § Identity linking](./human-auth.md), [#16](https://github.com/Dunky13/envweave/issues/16)):** that ADR fixes the identity key as *"`(issuer, subject)`, **canonicalized**, under a database uniqueness constraint"*. This ADR matches `iss` and `sub` **byte-for-byte, with no canonicalization step**, and the amendment applies to human identities too — the two paths MUST NOT diverge on what makes two external identities the same. OpenID Connect defines both `iss` and `sub` as case-sensitive, so an unspecified "canonicalization" is not a tidying step: any normalization that folds case, resolves a URL, strips a trailing slash or alters Unicode form can **merge two distinct external identities into one account**, which is an authentication bypass, and the uniqueness constraint would enforce the merge rather than catch it. Byte-exact matching is additionally what the protocol already requires of the `iss` comparison. Nothing else in #16's identity model changes.

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

**Every credential carries a lifetime: a finite duration, or the distinct value `indefinite`.** `indefinite` is a value, not a large number — it is unreachable by raising any ceiling. **The rules in this section govern both credential kinds** — a federation binding is a standing permission to present tokens and expires on the same terms (§ *Federated bindings expire*).

- **The instance sets a maximum finite lifetime**, under `instance-config`, clamping every project. The per-credential *default* is finite, so the easy path is bounded and a long-lived credential is a typed choice someone made.
- **`allow_indefinite` is a separate instance opt-in, default off.** Raising the ceiling can never manufacture it.
- **Tightening either control enumerates every affected credential to the actor before the change commits**, then clamps — mirroring #16's effective-window transition. A settings change never silently kills a live credential.
- Both controls are audited.

**Expiry warning is in-product first.** Credential-list badges, a warning field on API and CLI responses, a Kubernetes CR status condition and event, and an audit event at each threshold. **Where SMTP is configured it carries the same signal as an additional transport** to the credential's creating principal, to current `manage-identities` holders on the project, and to an optional per-credential contact address. Email is never the only signal: #16 fixed that most self-hosted installations have no mail server, and a warning that exists only in an unconfigured channel is not a warning.

**Recorded operator decision, stated rather than hidden:** an `indefinite` credential has an unbounded validity window, and the threat model's blast radius for a leaked credential is *everything fetchable during that window*. The dominant leak case is the one nobody notices, which is exactly the case expiry bounds. `indefinite` exists because an operator may knowingly accept that for a stable workload; the default-off opt-in and the audit trail are what keep it a decision rather than an accident.

*Rejected: no expiry at all (long-lived static tokens as the only shape).* Revocation is already immediate and re-checked per fetch, so expiry buys exactly one thing — a bound on the unnoticed leak — and without it that bound is infinite for every credential in the installation.

*Rejected: self-renewal* (a live token exchanging itself for a successor). It is a mint performed by a principal holding neither `manage-identities` nor `reveal`, so the token manufactures its own successor and #15's formula is bypassed by design. It also inverts the threat: an attacker actively using a stolen token renews it forever, while the honest unused one dies.

## Minting, widening, rotation, revocation

### Minting and widening

**Every operation that creates, replaces, or expands a working path from a machine credential to plaintext carries `manage-identities(project)` ∧ `reveal` ∧ reauthentication** (see the amendment note above). Three distinct operations fall under it, and naming only the first is the mistake this section exists to prevent. They differ in **which** environments the `reveal` conjunct ranges over, and that difference is deliberate:

| Operation | disclosure capability required over (per class, below) |
|---|---|
| **Minting** a credential — first issue or replacement | **every environment reachable in the resulting post-state** |
| **Creating or replacing an `oidc-federation` binding** | **every environment reachable in the resulting post-state** |
| **A grant mutation that expands a machine principal's effective authority** | **only the newly reachable set** (below) |

**The first two range over the whole post-state** because the actor **receives or redirects the credential itself** (§ *Delivery* makes the token display-once *to them*), so they walk away holding everything that credential can reach — the amendment note's rotation attack.

**The third is the one an implementer will miss.** A grant landing on a machine principal is not an ordinary grant: authority lives entirely in the grants, so it re-scopes **every credential already in circulation** — instantly, with nobody re-presenting anything, including credentials held by people no longer in the room. It therefore requires **both** #15's ordinary granting authorization **and** this formula, **in one transaction**; where the two disagree, the stricter refuses.

**The newly reachable set is computed per authority class, independently, never as one boolean:**

- **Newly reachable current plaintext** — environments where the post-state satisfies `read(E)` ∧ `reveal(E)` and the pre-state did not. Requires `reveal(E)` from the actor.
- **Newly reachable historical plaintext** — environments where the post-state satisfies `read(E)` ∧ `reveal-history(E)` and the pre-state did not. Requires `reveal-history(E)` from the actor.

Each non-empty set imposes its own requirement, and the same per-class split governs the whole-post-state rows of the table above. **Collapsing the two into a single "can reach plaintext" test is a bypass**, and a subtle one: a service account already holding `read(E)` ∧ `reveal(E)` would show an *empty* delta when granted `reveal-history(E)`, so an actor with no historical access at all could hand a machine principal the power to read superseded secrets — credentials that may still be live in an external service. #15 fixed the rule this violates: *"`reveal-history` implies nothing about `reveal`, and vice versa."*

The delta is a delta and not the post-state, and that distinction is what keeps the rule from being self-defeating: a delegated project administrator who deliberately holds no production `reveal` must still be able to add a **development-only** grant to a service account that already reaches production. Requiring production `reveal` for that mutation would refuse a change that discloses nothing new and would pressure administrators into acquiring exactly the production access least privilege withheld from them. The delta still catches the attack it was introduced for — adding `read(prod)` to a service account already carrying the project-wide `reveal` opt-in makes production plaintext newly reachable, so it demands `reveal(prod)` from the actor.

**Narrowing is never a widening**, so its delta is empty: removing a grant, revoking a credential, deleting a binding and reducing scope stay under the plain capability — #15's symmetric limit, so incident response is never gated on disclosure rights.

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

**The binding is explicit: an `(issuer, subject)` pair, matched byte-for-byte, names exactly one service account.** No wildcards, no namespace patterns, no path prefixes, no case folding, no normalization, no JIT provisioning. `iss` and `sub` are case-sensitive by specification, so any canonicalization step is an opportunity to merge two distinct external identities into one binding. An unbound identity **is not a login** — it does not create a principal and does not authenticate.

This is #16's rule for human identities as amended above, and it is load-bearing on Kubernetes: a pattern rule such as *any ServiceAccount in namespace `prod`* hands an Envweave principal to anyone holding `create serviceaccount` in that namespace — a far wider group than cluster-admin.

**A binding also names the required claims it demands, and validation requires every one of them.** The subject alone is not a sufficient statement of *which* workload this is, and on CI issuers it is actively misleading:

- Forgejo's Actions subject is `repo:<repository>:ref:<ref>` for every event **except** an exact `pull_request` trigger, which alone carries `repo:<repository>:pull_request`. **`pull_request_target` therefore carries the ordinary ref-form subject** — the default branch's subject, the one a production binding names. Forgejo documents that a `pull_request_target` workflow with `enable-openid-connect` that touches untrusted pull-request content **may leak `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, letting that content request ID tokens**. A crafted pull request against such a workflow thus yields a token bearing the bound production subject.
- **Therefore: every CI binding MUST pin `event_name`, and MUST refuse `pull_request` and `pull_request_target` unless one of those is separately, explicitly and deliberately bound.** Binding `workflow_ref` in addition is recommended, so one compromised workflow in a repository does not speak for every workflow in it.
- **Where an issuer exposes immutable numeric identifiers for the repository and its owner, the binding pins those rather than the names.** A rename or transfer otherwise silently re-points a production binding at whatever now occupies the old path.

*Superseded claim, recorded because it was wrong:* an earlier draft asserted that binding the full Forgejo subject "excludes PR-triggered runs by construction". It does not — it excludes only the exact `pull_request` event, and `pull_request_target` is precisely the dangerous one. The protection comes from the pinned `event_name`, not from the subject's shape.

**Audience binding is mandatory, and the issuer's default audience MUST be refused.** Every binding names the audience it accepts, and validation requires it. This is not ceremony: a Kubernetes token minted for the default API-server audience would otherwise authenticate to Envweave, and Forgejo's Actions audience **defaults to `<instance>/<repository owner>`** — shared across every repository that owner has, so accepting the default makes any workflow in any of their repositories satisfy the binding.

**ID token validation is complete, not partial:** exact `iss` match against the configured issuer, signature under an algorithm from that issuer's allowlist (never `none`, never algorithm confusion via an unvalidated `alg`), configured `aud`, `exp`/`iat`/`nbf` within a bounded skew, every pinned claim, and the bound `sub`. **Additionally, the accepted token age and the accepted `exp - iat` span are both capped by Envweave**, independent of what the issuer chose — a configured issuer that mints long-lived tokens must not thereby mint long-lived Envweave access. Failure at any step is a refusal, never a downgrade.

**Bindings are immutable.** Changing the issuer, subject, audience or required claims of an existing binding is not an edit; it is a **replacement mint** carrying § *Minting and widening*'s full formula. Editing in place would let a principal without `reveal` re-point a production binding at an identity they control while the recorded authorization stays behind — the same authority-laundering shape #15 closed for adapters.

### Federated bindings expire

**A binding carries a finite Envweave lifetime, governed by the same instance ceiling and the same default-off `allow_indefinite` opt-in as a bearer credential** (§ *Lifetime*). Renewal is a mint. Expiry warnings follow the same in-product-first path.

This is not symmetry for its own sake. The presented token's own short expiry bounds nothing an attacker cares about: **an attacker who has compromised a bound CI workflow or Kubernetes identity controls token issuance and simply requests another**, indefinitely, because the binding never lapsed. Without a binding lifetime, federation would be the one credential kind with a permanently unbounded compromise window — including in installations that deliberately set `allow_indefinite` to off.

*Corrected from an earlier draft, which stated that "a federated credential has no lifetime of its own to manage" and applied the lifetime rules to `envweave-token` only.* That was false in the direction that matters: it read the presented token's expiry as the bound, when the thing needing a bound is the standing permission to present one.

### JWKS

**Keys are fetched and cached, with a bounded staleness window.** While the issuer is unreachable, validation continues from cache up to that bound and then **fails closed, loudly**. Refresh is scheduled, and additionally triggered by an unknown `kid`.

*Rejected: failing closed the moment a scheduled refresh fails.* The failure this must survive is an API-server blip or a network partition between Envweave and the cluster, and that would stop every workload fetch cluster-wide — a self-inflicted outage on a control plane whose delivery story is explicitly *stale-but-valid beats not-starting*. Kubernetes service-account signing keys rotate rarely, so a bounded window costs very little exposure.

**A per-issuer static JWKS is a configured alternative**, for air-gapped installations and for deployments where the issuer's discovery endpoint is unreachable from Envweave. It is configuration, not machinery, and air-gapped operation is a settled product principle. It is not the default: a static-only installation breaks silently on the day someone rotates the issuer's keys.

**Unknown-`kid` refresh is rate-limited, and that is load-bearing rather than hygiene.** It sits on a pre-authentication path, so a stream of fabricated `kid` values is an outbound-fetch amplifier aimed at the issuer. It falls under #16's instance-wide admission budget and the threat model's no-unbounded-work rule.

## Authentication, authorization and the fetch path

- **Machine credentials never touch the human session mechanism** (#16's propagation). They are their own artifact type with their own storage, lifetime, listing and revocation surface. A machine principal has no CLI session, no cookie and no assurance record.
- **Machines do not reauthenticate**, as #15 fixed: the token *is* the credential and there is no second factor to re-present. Machine disclosure is controlled instead by the per-project `reveal` opt-in, narrow scope, individual revocability and per-fetch audit.
- **Every fetch re-authorizes** against current policy at the single chokepoint, in-transaction, uncached (#15 § *Evaluation*). A revoked grant stops delivery on the next fetch.
- **Fetches are conditional, and the cursor covers authorization, not merely content.** A caller presenting a current cursor is told it is current and receives **no plaintext**; only a fetch that actually delivers values is a disclosure. **Authorization is evaluated on the conditional path exactly as on the delivering path**, so a caller who has lost `read` learns nothing, per #15's unauthorized-is-indistinguishable-from-nonexistent rule.

  **The conditional cursor is bound to `(change token, the caller's authorized delivery projection, the principal's authorization revision, pin generation)` — never to the environment's change token alone.** The change token is computed over a **delivery manifest** (#12's amendment to #11), and a machine principal's manifest depends on what it may see: a `read`-only workload is delivered `config` and secret *presence*, while the same workload after the `reveal` opt-in is delivered secret plaintext. Those are different manifests from identical content. A cursor tracking content alone therefore fails in both directions:

  - **Newly authorized values are never delivered.** A workload granted `reveal` polls, the underlying content has not changed, the content token matches, and it is told "current" — so it runs indefinitely without the secrets it is now entitled to, and the failure is silent.
  - **The stale/current answer becomes a comparison oracle.** For a caller lacking current `reveal`, a cursor derived from secret-bearing content leaks whether hidden values changed — exactly the oracle #11 closed by making secret diffs write-presence only.

  **Any authorization movement invalidates the cursor**: a grant added, removed or narrowed on the principal, a change to the project's machine-`reveal` opt-in, and pin creation, reassignment or release. An invalidated cursor produces a full authorized delivery and its per-key disclosure events, not a "current" answer.
- **Pinned delivery re-checks the pin's recorded authority principal** for current `reveal-history(E)` on **every** fetch, and fails closed when it is gone (#15 § *Pins*, propagated here explicitly).
- **Pre-authentication admission limits apply to credential presentation and to federated validation**, under the same instance-wide budget as #16's human paths, with responses uniform between an unknown credential and a revoked one — the same unauthorized-is-indistinguishable-from-nonexistent rule, one layer earlier.

## Restore

**Machine credentials carry the credential epoch** (#16), so a restore makes every one of them inert — the mechanism behind the threat model's requirement that *every* pre-restore authentication artifact be invalidated.

**A restored bearer verifier is never re-activated. Ever.** The threat model is explicit and this ADR does not amend it: *"previously captured bearer values must not survive restore"* ([threat-model.md § Guarantees](./threat-model.md)). Re-activating a restored row leaves the verifier as `SHA-256(T)` for the same `T` an attacker may already hold, so the credential value survives the restore in every sense that matters — the epoch moved, the secret did not.

**Recovery therefore restores identities and authority, never credential values.** In the reconciliation commit, while the instance is in recovery mode and alongside #15's inert grant set, the operator re-activates **service accounts** — their identity, their `kind`, their grants — per principal, explicitly, with **no bulk-accept**. Every bearer credential of every restored service account is **permanently dead**; a working fleet is re-established by minting fresh credentials under § *Minting and widening* and redistributing them.

**Federated bindings may be re-activated per binding**, because a binding holds no bearer value — there is nothing an attacker can have captured and nothing to redistribute. Re-activation is a re-validation, not a trust: #16's rule for human OIDC links applies for the same reason, since a restore can resurrect a binding removed precisely *because* that workload was compromised.

**A token presented against a re-activated binding must have been issued after re-activation, by a margin that swallows clock skew.** Each re-activation records `reactivated_at`, and the binding refuses any token whose `iat` is not **strictly greater than `reactivated_at` plus the maximum accepted positive clock skew**, at the coarsest timestamp granularity either side uses. **This predicate is permanent for the life of the binding, not a waiting period.** A time-boxed quarantine that simply expires is *not* equivalent and MUST NOT be substituted: once it lifts, a pre-restore token whose `iat` was skewed into the future is admitted by ordinary validation, which is the exact artifact the predicate exists to exclude.

**The margin is the whole point, not padding.** Validation accepts `iat` within a bounded skew in both directions, so an issuer whose clock leads Envweave by the accepted skew `S` mints tokens with an `iat` in Envweave's *future*. An attacker capturing such a token immediately before the restore then holds an artifact that satisfies a naive `iat > epoch_bump` test while being, in fact, a pre-restore credential — precisely the artifact the threat model requires to be invalidated. A rule phrased against the epoch bump alone is defeated by the clock, silently.

**The no-bulk-accept rule survives at the service-account level**, for the reason it was introduced: the restored database is *old*, and a service account deprovisioned **after** the backup was taken appears in it as live. Nothing in the data distinguishes it from a legitimate one — the operator's memory is the only source of that fact, which is exactly why #16 refused to trust restored human verifiers at all. An "accept all" control turns an informed per-principal assertion back into a checkbox.

**Accepted cost, stated plainly:** restoring from backup stops every workload on every host until fresh credentials are minted and redistributed, and the operational pressure that creates is real. It is nonetheless what the locked headline guarantee requires, and the two mitigations are honest ones: federation needs no redistribution at all, which is a further argument for it wherever a platform issues identities; and restore is already a declared security event requiring operator reconciliation, not a routine operation.

*Rejected: re-activating bearer verifiers under a per-credential operator assertion* — the position an earlier draft of this ADR took. It contradicts the locked threat model outright, and the reasoning that made it attractive does not hold: a per-credential confirmation reduces the *probability* of resurrecting a revoked credential but cannot uphold a guarantee, because a single mistaken acceptance hands an attacker a live production token whose value they already hold. "No bulk-accept" does not repair one wrong accept.

*Rejected: machine credentials surviving restore untouched.* The resurrect-a-revoked-token hazard #8 names outright.

## Audit attribution

**#15's per-key disclosure rule applies to machine fetches unchanged: every disclosed key emits its own immutable event, with its own identity and its own occurrence timestamp.** No collapsing, no counters, no mutable last-seen field — a mutable aggregate would also contradict the threat model's application-level append-only stance. Storage MAY batch a fetch's per-key events inside one durable **fetch envelope** carrying the shared context — credential, service-account principal, principal class, project, environment, resolved revision number, change-token version, transport and outcome — but the envelope is a container, never a substitute for the individual events.

**Credential-level attribution is the point of the envelope.** The forensic question after a leak is *which token*, and one service account holds several.

**Every fetch is recorded, and no successful fetch is ever aggregated.** The threat model requires *every* fetch to be audit-logged with token identity, requires the record durable **before** the operation completes, and forbids application-level updates to audit rows. A counted aggregate violates all three: it mutates a row, and a not-yet-flushed counter is a completed fetch with no durable record. #16's aggregation licence is narrower than an earlier draft of this ADR claimed — it covers **failure floods**, not successful operations.

- A conditional fetch that delivers no plaintext emits **one immutable access record**, with its own timestamp. It is not a disclosure and emits no per-key events.
- A fetch that delivers plaintext emits its per-key disclosure events, as above.
- **Aggregation applies only to authentication-failure floods**, per #16, and never to any successful fetch, access record or disclosure event.

**Honest bound on what conditional fetch buys, since an earlier draft overstated it.** Conditional fetch makes *disclosure* volume track the rate values change rather than the rate well-behaved clients poll — a large and real reduction, and the reason #19 must make the operator's resync conditional. It does **not** bound audit volume in general, and it is not a defence: a compromised or merely misconfigured caller can present an absent or stale cursor on every poll and force a full disclosure each time. **The actual bounds are the locked ones** — per-principal fetch rate limits (#8's availability baseline) and the audit log's policy-based retention (#11) — and repeated cursor-less fetching by one credential is itself a signal worth surfacing.

*Rejected: one aggregated event per fetch carrying an inline key-id list* — this ADR's earlier position, which claimed conformance with #15 while reversing its explicit cardinality (*"Every disclosed key emits its own audit event"*, and again in that ADR's propagation to this ticket, *"disclosure (one per key)"*). Inline enumeration preserves the key *set* but destroys per-key event identity, individual disclosure times and ordering, and collapsing repeats destroys them across occurrences too. The volume argument that motivated it is largely answered by conditional fetch, and for the remainder the locked remedies are rate limiting (#8) and the audit log's policy-based retention (#11), not a weaker event model. An ADR may amend an upstream decision explicitly; it may not claim to conform while contradicting one.

## Reconciliation with upstream ADRs

- **Threat model ([#8](https://github.com/Dunky13/envweave/issues/8))** — ≥256-bit tokens stored as fast-hash verifiers, satisfied literally; the `(project, environment | env list)` scoping is expressed as grants on the principal; read-only-in-v1 is the `workload` allowlist; individual revocability, per-fetch audit with token identity, and revocation-stops-future-fetches are all satisfied. The stated blast radius is what § *Lifetime* bounds, for both credential kinds. **The requirement that "previously captured bearer values must not survive restore" is satisfied literally** — restored bearer verifiers are never re-activated (§ *Restore*), so a restore re-establishes identities and authority but never a credential value. Pre-authentication admission limits extend to credential presentation and JWKS refresh.
- **Permission model ([#15](https://github.com/Dunky13/envweave/issues/15))** — the two credential classes are implemented as an immutable `kind` with the normative allowlists enforced by the grant API; the mint formula is implemented and **tightened** by the amendment above to cover grant mutations on machine principals, which widen every credential already in circulation — over the whole post-state where the actor receives the credential, over the newly reachable set for a grant mutation, so least-privilege granting is not itself made to require production `reveal`; **the per-key disclosure rule is honoured at its locked cardinality**, with volume addressed by conditional fetch, rate limiting and retention rather than by a weaker event model; revocation is effective at next fetch; the pin authority re-check is carried on every pinned delivery; machines do not reauthenticate; no machine principal holds `manage-*`, `project-settings` or any instance capability.
- **Human auth ([#16](https://github.com/Dunky13/envweave/issues/16))** — machine credentials do not reuse the human session mechanism and are a distinct artifact type with their own revocation surface; the human/machine principal distinction is visible in audit attribution; the credential epoch is carried so restore invalidates machine credentials by the same mechanism, and — as with restored human verifiers — a restored bearer verifier is **never trusted as-is**, which here means never re-activated at all. The never-ordinary-stdout rule is inherited for token delivery; the no-hand-rolled-primitive invariant governs federation; the byte-exact `(issuer, subject)` binding, the refusal to treat an unknown identity as a login, the no-JIT rule, and the re-validation rather than trust of restored bindings are the same decisions applied to machines.
- **Source of truth ([#13](https://github.com/Dunky13/envweave/issues/13))** — machine `reveal` remains an explicit per-project opt-in never implied by `apply`, `publish` or `definitions-edit`; the automation credential is the `apply` path and its default posture remains a human applier.
- **Positioning ([#3](https://github.com/Dunky13/envweave/issues/3))** — federation is chosen over an at-rest credential where the platform supplies an identity, without adding a second always-on process; the single-binary posture is intact.

## Propagations (binding on downstream tickets)

- **Compose ([#18](https://github.com/Dunky13/envweave/issues/18))** — MUST consume credentials only via `--token-file` and `ENVWEAVE_TOKEN`; MUST NOT introduce a `--token` flag. The offline-fallback decision (fail-closed versus an encrypted local snapshot) is that ticket's, and MUST NOT reintroduce a retrievable credential.
- **Kubernetes ([#19](https://github.com/Dunky13/envweave/issues/19))** — MUST support both credential kinds; MUST surface impending `envweave-token` expiry as a CR status condition and event; MUST bind federated identities per byte-exact `(issuer, subject)` with an explicitly configured audience; **MUST make the reconcile loop's periodic resync a conditional fetch presenting the authorization-bound cursor**, so a resync interval measured in seconds does not become a disclosure rate, and MUST NOT treat a cursor-less fetch as a normal resync; MUST document K3s `--secrets-encryption` alongside any sync-to-Secret path.
- **Architecture ([#22](https://github.com/Dunky13/envweave/issues/22))** — MUST resolve machine credentials at the same chokepoint as `authorize()`, in-transaction and uncached; MUST site the JWKS cache with its staleness bound and rate-limited refresh; MUST provide the recovery-mode state in which restored credentials are inert.
- **Tenant isolation ([#23](https://github.com/Dunky13/envweave/issues/23))** — MUST enforce the project-subtree confinement of service-account grants; MUST ensure `(issuer, subject)` lookup cannot resolve across an org boundary; MUST keep unknown and revoked credentials indistinguishable in responses and timing.
- **Audit ([#24](https://github.com/Dunky13/envweave/issues/24))** — MUST emit **one immutable disclosure event per key** on any fetch that delivers plaintext, optionally batched inside a fetch envelope carrying the shared context, and MUST NOT collapse or count them; MUST emit **one immutable access record per conditional fetch that delivered nothing**, never aggregated — aggregation is permitted only for authentication-failure floods (#16); MUST emit events for service-account create/delete, credential mint/rotate/revoke/expire, **grant mutations on machine principals recorded as widenings**, lifetime-policy changes, federation issuer configuration, binding create/replace/delete (never modify), JWKS refresh failure and staleness-bound breach, restore-time service-account re-activation and binding re-validation, and authentication failures by cause.
- **API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25))** — MUST document the complete authorization formula for every service-account and credential verb; MUST NOT expose any route returning a credential value after mint; MUST implement the TTY / `--output-file` / `--print-token` delivery rules and the `--token-file` precedence warning.
- **Deployment-module seam ([#28](https://github.com/Dunky13/envweave/issues/28))** — adapter outbound credentials remain write-only and separate from machine identities; an adapter MUST NOT run under a service-account principal in place of #15's recorded authority principal.
- **MVP boundary ([#26](https://github.com/Dunky13/envweave/issues/26))** — a local agent daemon, `--watch` auto-restart, short-lived exchanged tokens, enrolment tokens, machine attestation on Compose hosts, pattern-based federated binding, and an ESO provider's auth surface are recorded here as deliberate exclusions needing explicit in/out confirmation.
- **Operations spec (fog)** — default credential **and binding** lifetime; the instance maximum-lifetime ceiling; the concurrent-credential cap per service account; expiry-notification thresholds and SMTP delivery policy; the **maximum accepted federated-token age and `exp - iat` span**; the **maximum accepted positive clock skew**, which sets the post-restore binding quarantine; JWKS refresh interval, staleness bound and unknown-`kid` rate limit; **per-principal fetch rate limits** and audit retention policy for machine fetch events (#8, #11) — together the volume levers, since aggregation is not one; and the admission budget shared with #16's pre-authentication paths.
