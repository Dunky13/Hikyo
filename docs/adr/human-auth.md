# Wenv human authentication (ADR, locked 2026-07-31)

> **Declared amendment (2026-08-06, [scim-provisioning.md](./scim-provisioning.md), [#38](https://github.com/Dunky13/wenv/issues/38), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** (a) **SCIM provisioning is the second named account-creation path** beside invitation (no-self-registration unchanged): a SCIM user create makes a **pre-linked account** — external identity `(kind, issuer, subject)` bound at creation under the byte-exact discipline, zero grants, no invitation token, no credential-establishment authority, no session, no assurance; the SCIM `password` attribute is refused by name. Subject derivation is protocol-specific and binding-declared (OIDC: the raw `sub`; SAML: the locked injective NameID encoding computed by the same encoder as the login path); `userName` is refused as a subject source. (b) The session-generation trigger list gains **SCIM deprovision/delete transitions, unconditionally** — the generation advances even when no grant row changes. (c) Deliberately **no account state machine is introduced**: SCIM deprovisioning is org-grant-scoped release plus the generation advance; accounts and identity links survive. (d) The tenant-propagation clause "`(issuer, subject)` lookup cannot resolve across an org boundary" is **restated as binding tenant-scoped surfaces**; the authz package's import-bounded identity-resolution interface — the login path, and now the SCIM provisioning create/attach as its second named member per [tenant-isolation.md](./tenant-isolation.md)'s amendment — is its single named exception. Restored identity links stay under this ADR's locked operator-reconciliation rule; SCIM re-assertion never re-blesses a link. Details in [scim-provisioning.md](./scim-provisioning.md).

> **Declared amendment (2026-08-06, [mvp-boundary.md](./mvp-boundary.md), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** the "LDAP and SAML are out of v1" decision is **amended for SAML only** — SAML (SP) membership in 1.0 is decided at the MVP boundary ([#26](https://github.com/Dunky13/wenv/issues/26)); the *design* amendment (library under the measurable proven bar, normative policy, byte-exact identity-pair mapping) locks at [#37](https://github.com/Dunky13/wenv/issues/37) under mvp-boundary §2.2's boundary conditions, with a defined fallback ladder (narrowed profile → procedural demotion). SCIM provisioning is likewise promoted, its design at [#38](https://github.com/Dunky13/wenv/issues/38). LDAP stays out. Until #37/#38 lock, this ADR's text governs everything except the membership decisions themselves.

> **Declared amendment (2026-08-06, [saml-sp.md](./saml-sp.md), [#37](https://github.com/Dunky13/wenv/issues/37), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** (a) the "LDAP and SAML are out of v1" decision is discharged for SAML — **SAML SP login ships in v1** under [saml-sp.md](./saml-sp.md)'s design (narrow profile: SP-initiated only, signed assertions mandatory with a structural verification-bound-to-extraction algorithm, no SLO, no xmlenc; gosaml2 — which **meets mvp-boundary §2.2's three-criteria bar**, no fallback rung invoked — under an Wenv-owned strict policy wrapper as mandatory hardening). LDAP stays out. (b) The identity key gains a **protocol discriminator**: `(kind ∈ {oidc, saml}, issuer, subject)` — an IdP's OIDC issuer URL and SAML entityID can be the same string (Keycloak realms), so the unqualified key would merge two protocol identities; existing OIDC rows backfill `kind = oidc` in an executable migration on both engines, no OIDC behaviour changes; the provider row id stays out of the key, and **one active provider per `(kind, issuer)`** is the complementary uniqueness constraint. (c) The per-provider assurance policy model gains its SAML form (accepted `AuthnContextClassRef` set read from the assertion's single `AuthnStatement`, verify-only; `saml:<entityID>` method + provider row id in the assurance record; `ForceAuthn` + `AuthnInstant` + same-pair reauth), and the session-deletion-on-provider-change rule binds SAML providers identically, with certificate-set changes added as a deleting cause. (d) **One narrow, named carve to "email is never a linking key"**: an `emailAddress`-format NameID may be admitted by per-provider explicit opt-in, consumed as opaque bytes in the subject position — never parsed as an address, never matched against any account email; the opt-in names the IdP-reassignment rebinding risk and is audited. Without the opt-in, `emailAddress` NameIDs are refused; `transient` always. SAML has **no JIT** (invitation or SCIM only; named reopen trigger if [#38](https://github.com/Dunky13/wenv/issues/38) demotes). Everything else here stands.

> **Declared amendment (2026-08-06, [multi-instance.md](./multi-instance.md), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** (a) the "every instance capability is MFA-mandatory" rule is restated as binding **human sessions**; the instance-connection machine principal (no assurance record, never reauthenticates) is its single named machine exemption, carrying exactly `instance-directory` — the `audit-read` machine-allowlist amendment is the precedent; (b) one new session artifact class, the **workspace session**: a server-side session row in every locked mechanical respect, differing only in transport (`Authorization` header, never a cookie) plus two bound fields (requesting origin, issuing handoff transaction); joins all locked lifecycle/invalidation rules plus origin-removal atomic revocation. Details in [multi-instance.md](./multi-instance.md).

Context: the threat model ([#8](https://github.com/Dunky13/wenv/issues/8)) fixed the *floor* — Argon2id password verifiers, high-entropy hashed expiring single-use tokens, `httpOnly`+`SameSite`+`Secure` cookies, CSRF tokens, session rotation on privilege change, no secret values in URLs or `localStorage`, and per-source-IP **plus instance-wide** admission limits on pre-authentication paths — and delegated "auth flows/MFA/session mechanics" here. The permission ADR ([#15](https://github.com/Dunky13/wenv/issues/15)) then made this ticket load-bearing for its own guarantees: it requires a reauthentication primitive supporting a `0`-window mode, session rotation on privilege change, deprovisioning atomic with grant revocation, first-administrator bootstrap through the `admin` template, and the local break-glass identity proof. The encryption ADR ([#14](https://github.com/Dunky13/wenv/issues/14)) delegated password KDF parameters here and already placed MFA seeds and recovery codes in the envelope-encrypted field set — so *that* MFA exists in v1 was settled upstream; only its shape was open.

Granularity note: this is the wayfinding-level human-authentication ADR. It fixes the implementation substrate, the login-method set, identity linking, the session and assurance model, the factor set, the reauthentication primitive, recovery, first-administrator bootstrap, and credential storage. Mechanism-level detail is delegated: concrete session lifetimes, idle/absolute timeouts, the reauthentication hard cap's value, token expiry values, admission-limit and throttle values, the common-password list and its update policy, and Argon2id tuning for constrained hardware → operations spec; login, enrolment, reauthentication-prompt and recovery **interaction design** → prototypes ([#20](https://github.com/Dunky13/wenv/issues/20), [#21](https://github.com/Dunky13/wenv/issues/21)); machine credential formats and lifecycle → machine identities ([#17](https://github.com/Dunky13/wenv/issues/17)); which auth events are audited and their shapes → audit ([#24](https://github.com/Dunky13/wenv/issues/24)); the endpoints and CLI verbs carrying each flow → API & CLI ([#25](https://github.com/Dunky13/wenv/issues/25)); where the auth package sits and how the chokepoint is enforced → architecture ([#22](https://github.com/Dunky13/wenv/issues/22)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

> **Amends the positioning decision ([#3](https://github.com/Dunky13/wenv/issues/3)):** that ticket recorded "SSO max one provider" as a scope-control measure. This ADR ships **multiple simultaneously configured OIDC providers**. The cost #3 was avoiding was account-linking ambiguity, and that cost is paid directly in § *Identity linking* and § *The OIDC transaction* rather than avoided by limiting provider count. Multiple providers do add one genuine failure mode a single provider does not have — **IdP mix-up**, where a response from a weak provider is replayed into a transaction begun at a strong one — and it is closed explicitly below rather than waved away. The scope-control intent of #3 is preserved by the harder limits it did not name: no self-registration, no JIT provisioning by default, instance-scoped provider configuration.

> **Amends the threat model ([threat-model.md § Guarantees](./threat-model.md), [#8](https://github.com/Dunky13/wenv/issues/8)):** that ADR records an explicit residual — *"offline guessing of weak human passwords remains possible against Argon2id verifiers — slowed, not prevented"*. This ADR **closes that residual** by envelope-encrypting the Argon2id verifier under the instance DEK (§ *Credential storage*). Theft of the database or a backup without the root key now yields verifiers an attacker cannot begin to guess against, because they are ciphertext rather than hashes. The headline guarantee becomes true for human passwords without qualification, and #8's residual sentence is superseded. The closure is conditional on the invariants in § *Credential storage* — in particular the compare-and-swap rule, without which re-encryption silently resurrects superseded passwords.

> **Amends the permission ADR ([permission-model.md § Capability atoms](./permission-model.md), [#15](https://github.com/Dunky13/wenv/issues/15)):** that ADR's capability table is closed and contains no credential-administration atom, yet recovery requires one. This ADR **adds `credential-reset`**, valid at **org and instance scope only** (§ *Recovery*). It is not a `manage-members` sub-power: a principal who can reset another's credentials can become them, so confining it to the scopes where #15 already accepts an escalation-capable administrator is what keeps its rule — *project-scoped `manage-members` may grant only capabilities the grantor already holds* — from being walked around through the recovery path.

## Substrate — composed single-purpose libraries, no auth framework

Wenv's backend is **Go, single binary** ([#3](https://github.com/Dunky13/wenv/issues/3)). The standing house rule is that authentication is never hand-rolled, and the house default (Better Auth) is TypeScript — it does not apply here. The Go ecosystem offers no auth framework with a comparable track record, so the rule is satisfied by **composing narrow, widely-deployed, single-purpose libraries in-process**:

| Concern | Library |
|---|---|
| Server-side sessions | `alexedwards/scs` |
| Password hashing | `golang.org/x/crypto/argon2` |
| OIDC relying party | `coreos/go-oidc` + `golang.org/x/oauth2` |
| TOTP | `pquerna/otp` |
| WebAuthn | `go-webauthn/webauthn` |

**Normative invariant: no hand-rolled primitive.** Wenv implements no KDF, no token format, no signature verification, no OIDC discovery/validation logic, no COSE parsing, and no constant-time comparison of its own. What Wenv owns is **flow wiring and relying-party policy** — which factor is demanded when, what a grant change does to a session, what recovery restores. That is the layer where this product's decisions live, and § *The OIDC transaction* and § *WebAuthn relying-party policy* exist because a library supplies neither: choosing `go-oidc` does not choose `state`, `nonce`, PKCE or issuer binding, and choosing `go-webauthn` does not choose RP ID, origin or user-verification policy. **Library selection is not policy selection**, and treating it as such is the specific way "we used a known library" becomes a false assurance.

*Rejected: a Better-Auth-shaped Go framework* (`go-better-auth`, `better-auth-go`, Limen, and siblings). Each is 2025–2026 vintage, effectively single-maintainer, and carries no audit history. "Known library" in the house rule means **proven**, not **conveniently shaped**; adopting an unvetted implementation of the exact thing a secrets manager cannot get wrong inverts the rule's purpose. This is re-evaluable, not permanent: if one acquires a real deployment base and an audit, the composition above is a small surface to migrate.

*Rejected: a hosted identity service* (Clerk, Auth0, WorkOS, Stytch, Firebase Auth). Three locked decisions each independently forbid it. **(1)** The wedge ([#2](https://github.com/Dunky13/wenv/issues/2), [#3](https://github.com/Dunky13/wenv/issues/3)) is "fully open source, no paid gate on any production-required capability" — login is production-required, and a SaaS dependency is a paid gate on it. **(2)** Self-hosting-first is a settled product principle: an air-gapped or LAN-only installation must be able to authenticate, and a hosted IdP makes egress a boot requirement for a product people run *because* they don't want their control plane phoning out. **(3)** The threat model's trust boundary is operator plus own-org admins; a hosted IdP inserts a third party holding every human identity outside that boundary, and the headline data-at-rest guarantee says nothing about a vendor holding the front door. A future hosted Wenv offering could use one — a different product, explicitly out of this map's scope.

*Rejected: requiring an external self-hosted IdP* (Kratos, Zitadel, Authentik, Keycloak) with no local accounts, and *rejected: bundling Kratos as a second process*. The first destroys the persona-A homelab story by making a second stateful service mandatory before Wenv boots; the second breaks the single-binary positioning and doubles the operational surface. Both also collide with § *Lockout and the local floor*.

## Login methods — local accounts and OIDC

**v1 ships local accounts and OIDC relying-party login, with any number of providers configured simultaneously.**

- **LDAP and SAML are out of v1.** SAML costs an XML-signature attack surface with a long history of authentication bypasses, for a population largely reachable through an OIDC-speaking IdP. LDAP is likewise covered by the IdP path. Both recorded as out, not silently absent.
- **No self-registration, ever.** Accounts are created by invitation from a `manage-members` holder ([#15](https://github.com/Dunky13/wenv/issues/15)), or by the bootstrap path below. Open signup on a secrets control plane is not a configuration mistake to be defaulted off; it is a capability that does not exist.
- **Provider configuration is instance-scoped**, under an instance capability. Were it org-scoped, an org admin could add a provider and mint identities authenticating into the instance — a lateral path the tenant model does not intend.
- Each provider carries an **assurance policy** (§ *Assurance*) and an optional `jit_provision` policy (§ *Identity linking*), both defaulting to the weakest-privilege setting.

### Lockout and the local floor

**Local accounts can never be fully disabled.** At minimum, principals holding instance capabilities retain a local credential. The permission ADR refuses to leave an org or instance unadministrable and routes recovery from that state through a local procedure; an installation whose only authentication path is an external IdP has no such floor — an IdP outage or misconfiguration becomes an unrecoverable lockout with no in-product path back. An installation may require OIDC for ordinary users; it may not remove the floor.

## Identity linking

**The identity key is `(issuer, subject)`, canonicalized, under a database uniqueness constraint. Email is never a linking key, at any point, for any provider.** OIDC fixes `sub` as immutable within an issuer; email addresses are reassigned, unverified, spoofed, and in several widely-deployed providers not verified at all.

**Linking is an explicit act by an already-authenticated user, and is an account-security mutation** (§ *Account-security mutations*): it requires fresh proof from a credential that existed before the link.

**An unknown OIDC identity is not a login.** Presenting a valid token for an unrecognized `(issuer, subject)` does not create an account and does not authenticate. It resolves one of three ways: it matches a pending invitation and is claimed by presenting the **invitation token itself**; the provider's `jit_provision` policy admits it; or it is refused.

**Invitation claiming binds to the invitation capability, never to an email comparison.** The single-use invitation token is the authority; a matching address in an ID token is not evidence and never substitutes for it.

**JIT provisioning is off by default, names its evidence, and grants nothing.** Where enabled, the policy MUST name the **issuer-specific claim** it trusts and the accepted values — a domain allowlist evaluated against an unverified `email` claim is precisely the auto-linking mistake this ADR rejects, relocated into provisioning. Providers that do not assert verification for the named claim cannot be used for JIT at all. The created account holds **zero grants**: it can authenticate and see nothing until a `manage-members` holder grants something. Provisioning an identity and authorizing it are separate acts.

**Binding is atomic.** Invitation consumption, identity binding, account creation and any initial grants occur in **one transaction**, under the `(issuer, subject)` uniqueness constraint. Two concurrent callbacks cannot both bind one identity or both consume one invitation; the loser fails closed.

**Unlinking your last remaining credential is refused**, in the same shape as the permission ADR's lockout invariant. **Unlinking invalidates every session authenticated through that identity**, in the same transaction.

*Rejected: auto-linking on verified email.* It requires trusting `email_verified` from every configured provider, so a single lax or misconfigured provider yields takeover of every account whose address it can assert. A per-provider "trust this issuer's email claim" switch makes it survivable, but it is a footgun on the login path, and explicit linking costs the user one deliberate click, once.

*Rejected: matching on `(issuer, subject)` with automatic account creation per provider.* That is not linking; it produces one account per provider per human, and the grant model then has to reconcile several principals that are one person — the account-linking problem with extra steps and worse audit attribution.

## The OIDC transaction

`go-oidc` verifies a token it is given. It does not supply the relying-party transaction, and **every multi-provider takeover path lives in that gap.** The following are normative.

**Authorization-code flow with PKCE `S256`, always** — including for confidential clients, where it defends against code injection rather than public-client interception.

**Every authorization request creates a server-side transaction record**, short-lived and single-use, holding: random `state`, random `nonce`, PKCE verifier, the **exact provider and issuer**, the redirect URI, the initiating session, the intended account where one exists, and the **purpose** — one of `login`, `link`, or `reauth`. A callback is processed only against its own transaction record, which is consumed atomically.

**Purpose is binding.** A response obtained for `login` cannot complete a `link`, and neither can satisfy a `reauth`. Without this, an attacker who can induce any OIDC round-trip can satisfy the reveal gate with it.

**Mix-up defence is explicit**, because this is the failure mode the multi-provider amendment actually introduces: the token exchange is performed **only** at the provider recorded in the transaction, and the callback's issuer is validated either by **RFC 9207 `iss` response parameter** or by **per-provider distinct callback endpoints**. A response from a weak provider presented to a transaction begun at a strong one is refused before any token is inspected.

**ID token validation is complete, not partial**: exact `iss` match against the recorded provider, signature with an algorithm from that provider's allowlist (never `none`, never algorithm-confusion via unvalidated `alg`), `aud` containing this client, `azp` where present, `exp`/`iat` within skew, and `nonce` equal to the transaction's. Failure at any step is a refusal, never a downgrade.

**Login CSRF is closed by the `state`-to-initiating-session binding**, not by cookie attributes alone.

## Sessions and assurance

### The session

**Opaque server-side sessions.** A session is a random ≥256-bit value stored as a **fast-hash verifier** (the threat model's rule for high-entropy artifacts — safe precisely because entropy makes brute force infeasible), with the session row read inside the request's own transaction.

This is forced, not preferred. The permission ADR requires revocation to be **atomic in one transaction** with grant revocation and forbids any cross-request authorization cache, on the stated grounds that a cache is how "revocation is immediate" quietly becomes false. A server-side session satisfies that literally: revocation is a delete in the same transaction.

*Rejected: stateless JWTs, with or without refresh tokens.* A JWT cannot be revoked; the standard remedy is a denylist, which is a session table with extra steps plus a window in which a revoked administrator still works. "Short TTL" does not fix this — it renames the staleness window and calls the rename a mitigation. The permission ADR's no-cache rule forbids the shape, not merely the duration.

**A session value is a replayable bearer credential, and this ADR says so plainly.** `httpOnly`, `Secure`, `SameSite` and `__Host-` constrain *browsers*; they do not constrain an attacker holding the value, who can replay it from any HTTP client. Those attributes reduce the ways a value is *stolen*; they do nothing once it is. Every downstream control here — short lifetimes, immediate revocation, fresh proof for account-security mutations, assurance that a stolen session cannot manufacture — exists because the bearer property is real.

- **Cookie**: `httpOnly`, `Secure`, `SameSite=Lax`, `__Host-` prefixed, path `/`, for browser sessions.
- **CLI sessions are a distinct artifact type** — their own storage, lifetime, audit identity and revocation surface, listed separately in "your active sessions". A browser cookie's attributes protect nothing on a non-browser client, and conflating the two hides which artifact was actually used.
- **Two independent clocks**: idle timeout and absolute lifetime. Values → operations spec.
- **Session rows record** creation time, last-seen time, source IP, user-agent, artifact type, and the assurance record below. Proxy-trust configuration (which forwarded-header sources are believed) is explicit configuration, never inferred — an unauthenticated header is not evidence.
- CSRF tokens on every state-changing browser request, per the threat model's floor.

### Assurance

**Grants belong to principals; credentials belong to accounts; and the thing authorization must consult is neither — it is how *this session* authenticated.** Attaching the MFA rule to the account's credential inventory is an object mismatch that produces two absurdities: an account that owns a passkey but logged in through a weak provider exercises `reveal` anyway, and an account with strong local factors is refused `reveal` because one of its linked providers is weak.

Every session therefore carries an **assurance record**: the authentication method (`local-password`, `local-passkey`, `oidc:<issuer>`), the set of factor classes actually presented, `authenticated_at`, the identifier of the factor ceremony, and for OIDC the `acr`/`amr` values and `auth_time` the provider asserted.

**Authorization of any MFA-mandatory capability requires adequate assurance *in the current session*** — evaluated at the same chokepoint as `authorize()`, in the same transaction, uncached. What the account *could* have presented is irrelevant.

**MFA-mandatory capabilities are `reveal`, `reveal-history`, `manage-members`, `credential-reset`, and every instance capability.** A `viewer` on a development environment is not forced to enrol.

**Provider assurance policy is not a boolean.** Each provider records the **accepted `acr` values and/or the required `amr` combinations**; a session authenticated through that provider gains multi-factor assurance only when the ID token carries them. `acr`/`amr` are context-specific by specification, so a global "this IdP does MFA" flag asserts something the protocol does not define. A provider with no assurance policy configured yields single-factor assurance — sufficient to log in, insufficient to reveal.

### Invalidation

**Rotation is not invalidation, and rotation alone cannot reach an idle session.** Regenerating the acting session's token leaves a stolen second session untouched, because that client is never told. The rules are therefore stated as deletions:

**Each principal carries a session generation counter. Advancing it invalidates every session of that principal**, atomically and without needing to reach the client — which server-side token rotation cannot do, because an idle or stolen session is never told.

**The generation advances, in the same transaction as the triggering change**, on: grant revocation or principal removal (the permission ADR's atomic-deprovisioning requirement), **grant addition or widening**, password change or reset, factor enrolment or removal, passkey enrolment or removal, recovery-code consumption, and credential reset by an administrator.

**Privilege *increase* invalidates as surely as privilege loss.** A session that authenticated before a promotion carries the assurance it had then, and the chokepoint would otherwise combine that stale assurance with the new grant the instant it lands — so a session stolen before promotion inherits the promotion. The permission ADR requires rotation on privilege change; rotation is necessary and not sufficient, because it reaches only the acting session. The new authority becomes exercisable on the principal's **next authenticated session**, which is a login, not a refresh. The cost is that being granted anything logs you out; on a secrets control plane that is the correct trade, and it is stated here so it is not discovered as a bug.

**Sessions authenticated through a given provider are deleted** when that provider is disabled, removed, or has its assurance policy changed, and when the identity linking them is unlinked.

**The acting session may be reissued after such a change only on fresh proof, and it never inherits prior reauthentication windows.**

**Rotation still applies where the session survives** — a new random value, same session identity, old verifier deleted in the same transaction — on login, **privilege change** (#15's explicit requirement), and every reauthentication.

## Factors — WebAuthn, TOTP, recovery codes

**All three ship in v1.**

- **WebAuthn** (`go-webauthn/webauthn`) — the only phishing-resistant option, and the only one that can bind a ceremony to a specific operation (§ *Reauthentication*).
- **TOTP** (`pquerna/otp`) — seeds envelope-encrypted under the instance DEK, as #14 specifies. **Codes are single-use per `(account, time step)`**, consumed transactionally.
- **Recovery codes** — single-use, ≥128-bit each (#8's floor), hashed, the set envelope-encrypted, regenerable as a batch (regeneration invalidates the previous batch atomically).

**Factor enrolment binds to the account, not to a provider identity.** A user who authenticates via two providers and a password has one factor set. What varies per login is the *assurance* that session carries.

*Rejected: TOTP only, WebAuthn deferred.* It ships the reveal gate's *procedure* without its *strength*, and retrofitting a phishing-resistant factor into an already-shipped reauthentication flow is exactly the migration a v1 should avoid. *Rejected: SMS or email as a factor.* Neither is available in an install with no guaranteed mail server, and both are weaker than what is already shipping.

### WebAuthn relying-party policy

Choosing the library chooses none of this; each item below is a normative Wenv decision.

- **RP ID and expected origins are explicit instance configuration, immutable at runtime, never derived from `Host` or a forwarded header.** In a self-hosted reverse-proxy deployment — the normal case here — request-derived values either break every credential when the proxy changes or accept an origin the operator did not intend.
- **Exact origin matching.** No suffix or wildcard matching.
- **`userVerification: required`**, with the **UP and UV bits verified server-side** on every assertion. A credential described as "user-verifying" is not one unless the server checks.
- **Challenges are random, single-use, expiring, and bound** to session, account, and purpose — and, for reauthentication, to the specific operation (§ *Reauthentication*).
- **Opaque random user handles**, never an email or account id.
- **Discoverable (resident) credentials required** for passkey login; sign-count regression is treated as a security event.

## Passkey login

**A passkey may serve as a primary credential, not only a second factor.** A user-verifying discoverable credential authenticates in one gesture, yields multi-factor assurance, and is strictly stronger than password-plus-TOTP.

**Normative precondition for dropping the password:** an account may become passkey-only **only** when it holds a current set of recovery codes **and** at least **two enrolled authenticators**. A passkey-only account with one authenticator and no codes is one lost laptop away from an administrative recovery incident, in a product whose recovery path deliberately does not depend on email. Enforced when the password is removed, and re-checked on de-enrolment: removing the second-to-last authenticator from a passkey-only account is refused until a password is set or another authenticator is enrolled.

## Account-security mutations

**A new credential may never authorize its own enrolment.** Session theft otherwise converts into permanent account takeover in one step: the attacker enrols a factor, regenerates recovery codes, removes the victim's factors, and thereafter passes every reveal gate legitimately.

The following are **account-security mutations**: password set, change or removal; factor enrolment or removal; passkey enrolment or removal; recovery-code regeneration; identity link or unlink.

Each requires, in this order:

1. **Fresh proof from a credential that existed before the mutation began** — a possession factor where the account has one, the password where it does not yet, and never the credential being added. Proof is purpose-bound (`account-security`) and recent; a reveal-window reauthentication does not satisfy it, and it does not open a reveal window.
2. **Execution in one transaction** with the credential change.
3. **Deletion of every session of the principal** (§ *Invalidation*), the acting session reissued only on the fresh proof above, carrying no inherited windows.
4. An audit event naming the mutation and the credential class that authorized it.

### Credential-establishment authority

The rule above assumes a prior credential exists. Three cases have none by construction — a freshly initialized instance, an account being reset by an administrator, and an identity re-established after a credential-epoch bump — so without an explicit mechanism an implementer must either brick bootstrap and reset or weaken the rule case by case, which is how the rule dies.

A **credential-establishment authority** is the named exception, and the only one:

- It is **target-bound** (names exactly one principal), **purpose-bound** (`establish-credential`, satisfying nothing else), **single-use**, expiring, ≥128-bit, hashed at rest, and issued only by the bootstrap path, `credential-reset`, or local break-glass.
- Consuming it **establishes exactly one initial credential, atomically**, and nothing more.
- It **creates no session, carries no assurance, and opens no reauthentication window.** The holder authenticates afterwards with the credential they just set, like anyone else.
- Every subsequent account-security mutation runs under the ordinary rule, using that credential as the prior one.

**Recovery-code consumption is the second exception**, and a different shape: it *is* the fallback for a locked-out account that still has a prior credential set. Correspondingly loud, single-use, and generation-advancing.

Nothing else may establish a credential without one of these two, and neither ever yields an authenticated session as a side effect.

## Reauthentication

The permission ADR fixed the *gate*: a sliding window configured per environment under `project-settings`, `0` meaning every disclosure, the window gating the **prompt** and never the **check**, and the protected-environment flag **capping** the window. This ADR supplies the primitive underneath it — and states honestly what each factor can actually deliver.

**Reauthentication re-presents a possession factor — WebAuthn or TOTP. Never a password, and never a recovery code.**

- **Never a password.** Reauthentication proves the person at the keyboard is still the account holder *now*. A password re-entry proves nothing a stolen session does not already imply: the same keylogger, the same saved credential, the same shoulder. It is the common pattern and it is the weak one.
- **Never a recovery code.** A recovery code restores *access*; it must not authorize *disclosure*. Were codes accepted here, a single stolen sheet would equal production secret disclosure. Normative invariant, not a default.

**The protected unit is one authorization decision over an explicitly enumerated set of keys in one environment.** A bulk reveal or a `values export` is *one* unit whose enumeration is fixed before the ceremony and cannot grow after it; #15's per-key audit rule is unchanged — one ceremony, one unit, still one audit event per key.

**What each factor delivers, stated plainly:**

- **WebAuthn** can bind its challenge to the enumerated unit, so it delivers a genuine **per-operation** gate. `0` means what it says.
- **TOTP** cannot. A code is valid for its time step; single-use consumption prevents a captured code being replayed, but it also means a legitimate user's second disclosure waits for the next step. TOTP therefore delivers a **per-step** gate, not a per-operation one.

**Consequently, an environment whose *effective* window is `0` requires WebAuthn.** The condition is the effective window, not the protected flag: the permission ADR caps a protected environment's window at the protected default and **recommends** `0` without mandating it, with the concrete value owned by the operations spec. An installation running a protected environment at a small non-zero window is conforming, and TOTP remains sufficient there.

This is narrower than a general "WebAuthn-only for reveal" policy, which was rejected for locking TOTP-only users out of `reveal` entirely: TOTP remains sufficient everywhere a non-zero window is configured. It is the honest reading of `0` — an operator who sets it is asking for a per-disclosure gate, and TOTP cannot supply one.

**The requirement is a property of the environment, not of the grant, so it must be enforced on transition and not only at grant time.** Lowering an environment's window to `0` (directly, or by marking it protected where the cap is `0`) would otherwise strand every TOTP-only principal already holding `reveal` there. On that transition, in one transaction:

- every open reauthentication window on that environment is invalidated;
- **grants are retained** — no capability is silently revoked by a settings change, which would make `project-settings` a grant-removal power it is not;
- the affected principals (holding `reveal`/`reveal-history` there without an enrolled WebAuthn authenticator) are **enumerated and surfaced to the actor before the change commits**;
- disclosure for those principals **fails closed** until they enrol, with an error naming the reason and the remedy;
- **factor enrolment stays reachable** — it is an account-security mutation authorized by a pre-existing credential, never by the reveal gate, so a stranded principal can always self-remedy without an administrator.

**Reauthentication is scoped to the environment**, matching the window it opens. Reauthenticating for `dev` opens no window on `prod`. Without this, the protected-environment cap is bypassable by revealing somewhere permissive first and riding a global window into production.

**The sliding window has an absolute cap.** A window refreshed by each disclosure has no maximum age, so one ceremony plus a stolen session keeps production unlocked until the far longer session lifetime expires. The server stores, per environment, `(factor ceremony id, authenticated_at, hard_expires_at)`; `hard_expires_at` is measured from the ceremony and is **not** extended by activity. The cap's value → operations spec.

**Every open window is invalidated** by any account-security mutation, any change to the principal's grants, any provider assurance-policy change, and session deletion.

**Every reauthentication rotates the session token and writes an audit event.**

**OIDC identities reauthenticate by re-running the OIDC transaction** with purpose `reauth`, `prompt=login` and `max_age=0`, and the result is accepted only when the returned token carries the **same `(issuer, subject)`**, an `auth_time` within the freshness bound, and `acr`/`amr` satisfying the provider's assurance policy. `prompt=login` alone proves neither freshness nor multi-factor — a provider may honour it with a single-factor re-login, or with none at all.

**Machine identities do not reauthenticate**, as #15 fixed: the token *is* the credential and there is no second factor to re-present.

*Rejected: WebAuthn-only for all reveal-class reauthentication.* Strictly stronger, but it locks TOTP-only users out of `reveal` everywhere, which in a homelab install means "your phone is not a security key, so you may not read your own production database password." The `0`-window rule above buys the same protection exactly where the operator asked for it. *Rejected: a per-project knob choosing between the two.* `project-settings` is architecturally the right home — it is the capability #15 split out precisely to be the restraining hand — but the window knob already expresses the intent, and a second branch on the most security-sensitive path is not free.

## Recovery

Self-hosted installations frequently have no SMTP. **Email is never on the critical path of any recovery flow**; where configured, it is an alternative transport for an artifact that already exists, never a different mechanism.

Three tiers, in order:

1. **Self-service.** A lost authenticator or forgotten password is recovered by consuming a recovery code. No administrator, no mail server.
2. **Administrator-issued reset**, under the new **`credential-reset`** capability (org and instance scope only — see the amendment above). The holder mints a single-use, ≥128-bit, hashed, expiring token, **displayed once**, transmitted out of band. If SMTP is configured it may be mailed instead — same token, different transport.
3. **Break-glass CLI.** The permission ADR's local procedure: host access (server stopped, or a root-owned local socket) plus the root key, no network route and no HTTP endpoint, naming target principal and capability explicitly, writing a durable recovery audit record.

Four rules make this safe, each stated rather than implied:

**`credential-reset` never belongs to project scope.** A project-scoped `manage-members` holder resetting an account-global credential would become a principal holding authority in *other* projects — walking around #15's rule that project-scoped granting is confined to capabilities already held. The escalation is not specific to MFA reset: a *password* reset reaches the same account. Both are `credential-reset`.

**`credential-reset` at org scope reaches only org-bounded principals.** It applies to a target whose grants lie entirely within that org and who holds no instance capability. A target with grants spanning orgs, or any instance capability, is reachable only at instance scope or by break-glass. Without this, a single-org administrator resets a cross-org principal — and, because reset advances the session generation, can also inflict a cross-scope denial of service on an account they have no authority over.

**The org-bounded test is evaluated and acted upon in one serializable transaction with the target's grant set.** A predicate checked and then acted on separately is a time-of-check race: the administrator reads a target bounded to their org, a concurrent grant lands giving that target instance authority or a foothold in another org, and the reset commits against a principal who is no longer in reach. Grant mutations on the target must conflict with an in-flight reset on that target, and the loser retries or fails closed. The same serialization applies to break-glass, which is the only path permitted to proceed regardless of the predicate.

**Instance-capability holders have no network credential-reset path at all** — break-glass CLI only, for password and factor alike. Otherwise a compromised org administrator escalates to operator through the recovery path, and the instance/org boundary is bypassed from below.

**Reset issues a credential-establishment authority, not a login.** The minted token is exactly the artifact defined in § *Credential-establishment authority*: consuming it lets the holder *set* one credential, never logs them in, carries no assurance, and advances the target's session generation in the same transaction.

Every step of all three tiers is an audit event, **including failures** — a burst of failed recovery-code attempts is the clearest available signal of an account under attack. Failure *responses*, however, are uniform (§ *Admission control and enumeration*): the audit trail is where detail belongs, not the HTTP response.

## Restore

The threat model requires that **every** pre-restore authentication artifact be invalidated and that restored password verifiers are "never trusted as-is". A restored database necessarily still contains verifiers, links and invitations, so "they are invalidated" needs a mechanism, not an assertion.

**The instance carries a credential epoch. Restore increments it.** Every human authentication artifact records the epoch it was created under, and an artifact from an earlier epoch is **inert**: it cannot authenticate, cannot be reauthenticated against, and cannot be reset with a pre-restore token. This covers password verifiers, MFA seeds, recovery codes, sessions, invitations, reset tokens, bootstrap tokens, and OIDC identity links.

**Recovery from the epoch bump runs under local authority**, alongside the permission ADR's inert-grants reconciliation: the operator, under break-glass authority, issues fresh short-lived credential-establishment claims per identity. **OIDC identity links are re-validated, not trusted** — a restored link is inert until the operator confirms it, because a restore can resurrect a link removed precisely because the provider account was compromised. Local-only users establish credentials through the operator-issued claim; there is no self-service path out of an epoch bump, and that is intended.

Recovery mode exits only when the operator commits the reconciled set — the same gate #15 already defines for grants.

## First-administrator bootstrap

**Ordering is fixed by the encryption ADR:** the root key must be present and the instance initialized before any principal exists. No administrator predates the crypto that protects them.

**A one-time bootstrap token is minted at instance initialization and delivered only to local authority** — ≥128-bit, hashed at rest, expiring, single-use. It is a **credential-establishment authority** (§ *Account-security mutations*), which is what resolves the otherwise-circular requirement that a credential predate every enrolment: it establishes the first administrator's initial credential and nothing else, granting no session and no assurance. The administrator then authenticates with that credential and enrols factors under the ordinary rule.

**Delivery is never ordinary stdout.** Stdout is not the console: under Docker, Kubernetes, systemd, a NAS application manager or any log shipper, it is retained and readable by principals holding neither host access nor the root key — so `kubectl logs` would hand a remote reader the first administrator account and its seeded `reveal` grants. The token is written to a **newly created root-owned file** with restrictive permissions, or printed **only when stdout is an interactive TTY**; a non-TTY, non-file delivery is refused rather than downgraded. It never appears in structured logs.

- The first administrator is created by applying the **`admin` template** — #15's explicit requirement — so `reveal` and `reveal-history` land as separate, visible, individually revocable grant rows rather than an implicit bundle.
- The web bootstrap endpoint binds to **loopback or a local socket by default**, with a short expiry; exposing it on a routable interface is a deliberate, documented act.
- **The bootstrap token expires and is single-use.** If it lapses, a new one is minted from the CLI on the host. It is never re-displayed.
- **The first administrator must complete factor enrolment before the session may do anything beyond enrolling** — they hold `reveal` by template, and the assurance rule makes adequate assurance a precondition of using it.
- `wenv admin create` on the host remains available as a permanent alternative — the **same** local-authority mechanism as break-glass, not a second one.
- Mint, delivery mode, consumption, expiry and failed presentation are all audit events.

*Rejected: an open setup page until claimed (trust-on-first-use).* Whoever reaches the port first owns the instance. On a LAN hosting a secrets manager, that is a race with a catastrophic loser. *Rejected: seeding administrator credentials from environment variables.* A plaintext seed account by construction — it lands in shell history, Compose files, `docker inspect` output and process listings, and violates the standing no-plaintext-seed rule. *Rejected: CLI-only creation with no web path.* Safest, but it forces every user through a terminal before first login and duplicates a mechanism that already exists.

## Credential storage

**Passwords are Argon2id verifiers, envelope-encrypted under the instance DEK.**

The hash remains a hash — a root-key holder still cannot reverse it, preserving the encryption ADR's distinction between hashed verifiers and ciphertext. Encryption is an **outer layer**, and it is what closes #8's offline-guessing residual: a stolen database or backup without the root key yields ciphertext, so the attacker cannot mount the guessing attack at all, rather than mounting it slowly. The cost is that password verification requires the instance DEK — always live on a running server — and that verifiers join the `reencrypt` set the encryption ADR defines.

**Compare-and-swap is load-bearing, not hygiene.** The encryption ADR specifies `reencrypt` as resumable, per-row transactional, and explicitly **without a global lock**. A verifier row is also rewritten by password reset, by credential establishment, and by KDF-parameter upgrade on successful login. Read-decrypt-reseal-write across a concurrent reset therefore writes the *stale* verifier back under the new DEK version — **silently resurrecting a superseded password**, which is exactly the failure the residual-closure amendment claims to prevent. Therefore:

- Every credential row carries a **version counter**; `reencrypt` reads it, and its write is a **compare-and-swap** that aborts and retries when the row changed underneath.
- Password reset, credential establishment and KDF upgrade update **verifier, parameters, DEK version, credential epoch and version counter in one transaction**, with session deletion.
- A `reencrypt` pass that cannot converge on a row after bounded retries **fails loudly** rather than skipping it.

**Argon2id parameters (delegated here by #14):** `m=64 MiB`, `t=3`, `p=2`, 32-byte output, 16-byte random salt per verifier. Parameters are recorded per verifier so they can be raised without invalidating existing credentials (re-derivation on next successful login, under the CAS rule above). They are **tunable downward for constrained hardware** — the encryption ADR's Raspberry Pi 4 target is comfortable at these values for this product's user envelope — but a **hard floor is verified at boot** and the server **refuses to start** below it, rather than degrading quietly. Fail loud, no silent fallback.

**Password policy: a length floor of 12, no composition rules, no forced rotation** (NIST SP 800-63B shape), with rejection against a bundled common-password list. Composition rules produce `Password1!` and a false sense of entropy; forced rotation produces `Password2!`. List contents and update policy → operations spec.

## Admission control and enumeration

The threat model's availability baseline is explicit: per-source-IP **and instance-wide** admission limits on pre-authentication paths "so identity rotation cannot exhaust Argon2id, audit storage, or global concurrency". Per-account and per-IP backoff alone does not satisfy it — a distributed attempt spread across many usernames and many source IPs never trips either bucket, while each accepted attempt consumes 64 MiB and a durable audit write.

- **A bounded instance-wide semaphore governs Argon2id execution**, with a bounded queue and an overload response that performs **no unbounded work**. The same admission budget covers OIDC callbacks, WebAuthn ceremonies, recovery-code attempts, invitation and reset-token presentation, and bootstrap presentation.
- **Per-account and per-IP exponential backoff** remains, with an audit event on threshold crossing.
- **Audit writes under failure floods are bounded by aggregation**, never dropped silently — the threat model forbids both unbounded growth and silence.
- **Permanent lockout is refused.** Locking out the last administrator is a self-inflicted denial of service, and the permission ADR already refuses unadministrable states.

**No pre-authentication path distinguishes an existing account from a missing one.** An unknown account traverses a **bounded dummy-verifier path** with fixed Argon2id parameters so timing is comparable; responses and status codes are uniform; recovery and invitation initiation reveal neither account existence nor which factors are configured; and throttle buckets are keyed so that the presence or absence of a real per-account bucket is not observable. This mirrors the permission ADR's unauthorized-is-indistinguishable-from-nonexistent rule, one layer earlier.

## Reconciliation with upstream ADRs

- **Threat model ([#8](https://github.com/Dunky13/wenv/issues/8))** — the browser/session floor is adopted (§ *Sessions*), with the honest correction that cookie attributes do not stop replay. Argon2id, ≥128-bit hashed expiring single-use tokens, and envelope-encrypted MFA seeds and recovery codes are satisfied. The pre-authentication admission-limit requirement is satisfied in § *Admission control*. The offline-password-guessing residual is **closed** by the amendment above, conditional on the CAS rule. Restore semantics are satisfied by the **credential epoch** (§ *Restore*), which is the mechanism behind "never trusted as-is".
- **Permission model ([#15](https://github.com/Dunky13/wenv/issues/15))** — the reauthentication primitive satisfies the sliding-window gate including `0`-window, is environment-scoped so the protected cap cannot be bypassed, and now carries an absolute age cap. Session rotation on privilege change is implemented and **strengthened**: rotation reaches only the acting session, so a principal session generation invalidates the rest, on privilege *increase* as well as loss. Atomic deprovisioning, `admin`-template bootstrap and the break-glass identity proof are implemented as required. The protected-environment cap is read as that ADR writes it — a cap whose recommended value is `0`, not a mandated `0` — and the WebAuthn requirement keys off the effective window rather than the flag. The MFA-mandatory rule is evaluated as **session assurance** at the same chokepoint, so it cannot diverge from the grant table. `credential-reset` is added by amendment rather than smuggled in as a `manage-members` sub-power.
- **Encryption ([#14](https://github.com/Dunky13/wenv/issues/14))** — MFA seeds, recovery codes and now password verifiers sit under the **instance DEK**, which that ADR reserves for sensitive rows belonging to no project. Session tokens remain hashed verifiers, not ciphertext. KDF parameters, delegated here, are fixed in § *Credential storage*, and the CAS rule is the condition under which `reencrypt`'s lock-free design stays safe for credential rows.
- **Positioning ([#3](https://github.com/Dunky13/wenv/issues/3))** — single-binary Go is why no external IdP or hosted service is acceptable; the one-provider SSO limit is amended above, with the mix-up failure mode it was implicitly avoiding closed explicitly.
- **Source of truth ([#13](https://github.com/Dunky13/wenv/issues/13))** — the "human applier" default for `apply` rests on a human session that has actually reauthenticated where a disclosure is involved; this ADR supplies that factor and the assurance it must carry.

## Propagations (binding on downstream tickets)

- **Machine identities ([#17](https://github.com/Dunky13/wenv/issues/17))** — MUST NOT reuse the human session mechanism; machine credentials are bearer artifacts on their own path with their own type and revocation surface. MUST keep human/machine principal distinction visible in audit attribution. MUST carry the credential epoch so restore invalidates machine credentials by the same mechanism.
- **Architecture ([#22](https://github.com/Dunky13/wenv/issues/22))** — MUST site the auth package so session resolution and the **session-assurance check** run inside the same chokepoint as `authorize()`, in-transaction, uncached. MUST accommodate the five named libraries and the no-hand-rolled-primitive invariant. MUST provide the boot-time Argon2id floor check as a startup failure, the instance-wide admission semaphore, and the immutable RP ID / origin configuration.
- **Tenant isolation ([#23](https://github.com/Dunky13/wenv/issues/23))** — MUST treat OIDC provider configuration as instance-scoped state; MUST ensure `(issuer, subject)` lookup cannot resolve across an org boundary; MUST enforce the org-bounded-target test on `credential-reset`.
- **Audit ([#24](https://github.com/Dunky13/wenv/issues/24))** — MUST emit events for: login success and failure (by method and assurance), logout, session creation/rotation/generation-advance (with cause), credential-establishment-authority mint and consumption, effective-window transitions to `0` with the stranded-principal list, factor enrolment and removal, passkey add/remove, recovery-code generation and **consumption**, every account-security mutation with the credential class that authorized it, credential reset issued and consumed, bootstrap-token mint/delivery-mode/consume/expire/failed-presentation, identity link and unlink, JIT provisioning, provider configuration and assurance-policy change, OIDC transaction failures **by cause** (mix-up refusal, nonce mismatch, purpose mismatch), reauthentication success and failure, credential-epoch bumps, and admission/throttle threshold crossings. Failures matter as much as successes, and MUST be aggregable under flood without silent loss.
- **API & CLI ([#25](https://github.com/Dunky13/wenv/issues/25))** — MUST NOT expose `credential-reset` against instance-capability holders over the network, MUST NOT expose break-glass over the network (already #15's rule), MUST keep `wenv admin create` local-only. CLI sessions are a **distinct artifact type** with their own lifetime and revocation verb — the CLI holds a session artifact, never a password.
- **Prototypes ([#20](https://github.com/Dunky13/wenv/issues/20), [#21](https://github.com/Dunky13/wenv/issues/21))** — MUST render: the reauthentication prompt with window state **and remaining hard-cap age**, the enumerated key set a ceremony is about to authorize, factor enrolment including the passkey-only precondition and the WebAuthn requirement for protected environments, step-up prompts on account-security mutations, the recovery-code display-once screen, the administrator reset flow with its display-once token, the identity-linking screen, and active sessions distinguishing browser from CLI artifacts.
- **MVP boundary ([#26](https://github.com/Dunky13/wenv/issues/26))** — SAML, LDAP, per-project reauthentication-factor policy, and general WebAuthn-only reveal enforcement are recorded here as deliberate exclusions needing explicit in/out confirmation.
- **Operations spec (fog)** — session idle and absolute lifetimes, per artifact type; the reauthentication **hard cap**; bootstrap, invitation and reset token expiry; recovery-code batch size; instance-wide admission budget, queue depth and overload response; the throttle curve; the common-password list source and update policy; Argon2id tuning guidance and the hard floor's concrete values; proxy-trust configuration; RP ID and origin configuration guidance for reverse-proxy deployments.
