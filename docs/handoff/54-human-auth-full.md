# Handoff: #54 Human auth, full — OIDC, WebAuthn, TOTP, recovery, sessions, assurance

Issue: https://github.com/Dunky13/hikyo/issues/54 (parent #41). Governing spec:
`docs/adr/human-auth.md` (on `wayfinder-docs`:
`git show wayfinder-docs:docs/adr/human-auth.md`), acceptance row A1 in
`docs/adr/mvp-boundary.md`. Extends the #47 first slice
(`docs/handoff/47-first-slice.md`).

This ticket is one of the largest in the project: full multi-provider OIDC,
WebAuthn, TOTP, recovery codes, session generations, per-provider assurance
policy, reauthentication windows, break-glass and `credential-reset`, all
dual-engine (sqlite + postgres) behind the repo's lint analyzers, sqlc
codegen, closed audit registry and E2E fixture families. It is being landed as
**dependency-ordered, individually-green increments**, not one monolithic drop
— a half-authored tree that breaks the analyzers is worse than a clean
foundation plus a rigorous blueprint.

## State of this branch

**Landed and verified (this increment):**

- **Two Opus 5 adversarial security investigations** of the pre-implementation
  design (the two the ticket command requested). 45 findings — 1 CRITICAL,
  12 HIGH, plus MEDIUM/LOW. **All accepted and folded into the blueprint
  below.** These are the load-bearing output; the implementation slices below
  must honour every resolution.
- **Migration `00006_factors.sql`** (both engines, verified applying + `Check`
  clean on sqlite): `totp_credentials`, `totp_challenges`, `recovery_codes`,
  `reauth_windows`, `sessions.csrf_verifier`, and a `credential_authorities`
  rebuild admitting the `recovery` issuer + `established_credential_kind`
  (recovery may only ever establish a password — closes the CRITICAL).
- **Dependencies** added and behind the import boundary: `coreos/go-oidc/v3`,
  `golang.org/x/oauth2`, `pquerna/otp`, `go-webauthn/webauthn`, test-only
  `descope/virtualwebauthn`.
- **`internal/oidctest`** — a test-only OpenID Provider (discovery, JWKS,
  RS256 ID tokens, PKCE-verifying token endpoint, mix-up/issuer-case knobs) so
  the OIDC fixture families run against a real wire flow. `crypto/rsa` is
  unrestricted by the boundary test; the package is `_test`-only.
- **New bearer artifact types** (`internal/crypto/bearer.go`):
  `br` (browser session), `rc` (recovery code), `st` (OIDC state), `ob` (OIDC
  browser-binding cookie), `cs` (CSRF token) — all covered by the audit
  redaction filter for free.
- **apigen path trap fixed**: the stray root-level `apigen/apigen.gen.go`
  (imported by nothing, byte-identical to the live package, written by the
  documented regen command) is removed, and `api/oapi-codegen.yaml`'s `output`
  is now repo-root-relative so regeneration targets the live package.

**Also landed since (commits on this branch):**

- **Store + crypto for TOTP and recovery codes.** `internal/crypto/totp.go`
  (pquerna/otp wrapper: 160-bit seed, constant-time code comparison returning
  the matched step for single-use tracking) and `recovery.go` (bearer-artifact
  codes, constant-time set match). sqlc queries + enumerated resolution-surface
  writers for `totp_credentials`, `totp_challenges`, `recovery_codes`, plus
  step-up session rotation and the outstanding-authority sweep (B12). Nine new
  writers in `lint.ResolutionSurfaceWriters`; `annotated_queries.json`
  regenerated. Dual-engine.
- **Assurance gate plumbed (dormant).** `authz.Authorize` now takes the
  caller's `Identity` instead of a bare principal and consults
  `assuranceInadequate` AFTER the grant check (so only a capability-holder
  learns a step-up is required); session-less local host authority is exempt.
  `authz.AdequateAssurance` is the rule (two distinct factor classes, or
  WebAuthn). `Actor.resolve` returns the full `Identity`. **`AssuranceEnforced`
  stays `false`** — the gate is wired but dormant until the factor endpoints
  land in the same PR.

**LANDED (the atomic factor vertical, commit `e97a461`):** TOTP
enrol/confirm/remove + step-up, recovery generate/consume, the
account-security-mutation reissue, `establish` stays password-only; the five
factor audit events registered and **`AssuranceEnforced` flipped to true** (the
chokepoint now refuses MFA-mandatory ops from inadequate session-backed
callers); six wire endpoints + regen + classify; CLI factor verbs with rotated
tokens persisted; demo E2E enrols + steps up before `org create`;
`factors_e2e_test.go` carries the A1 fixtures. Full suite green on sqlite,
built by an Opus 5 subagent, reviewed on the main thread.

**Blocking Codex cross-model pass: COMPLETE, verdict CLEAN (R3 of the 3-round
cap).** R1 returned 5 HIGH / 2 MEDIUM / 1 LOW; the substantive HIGHs were real
and are fixed: (a) every TOTP-code and Argon2-password ceremony now rides the
admission budget with per-account backoff keyed on the canonical account id +
the throttle-crossing event (closed an authenticated online brute-force of the
6-digit code and an unthrottled Argon2 oracle/DoS from a stolen session); (b)
confirm/remove/recovery-gen re-authenticate the presented token inside the
write tx (a revoked session can no longer win the phase gap and reissue
itself); (c) the CAS consumes the row whose seed was verified in phase 1, not a
re-read row, and the pending-enrolment expiry is re-checked inside the write tx
(future-stamped rows refused). R1 MEDIUM/LOW also fixed: recovery negative-path
timing equalised via a cached dummy envelope open, the missing
`auth.credential_authority_minted` event emitted on the recovery mint
(delivery=response) and declared in wireEvents, and all decrypted recovery
plaintext / verifier buffers zeroed. R2 verified the HIGHs held and caught five
completeness gaps (throttle-event audit declaration, write-tx expiry recheck,
unreadable-path timing, residual zeroing); all folded. R3 confirmed every item
CLOSED with no new regression → CLEAN. Commits: `e97a461` (vertical), `e877a1a`
(R1 fixes), `825730b` (R2 fixes). Review artifacts in `.xreview/54-factors-r*`.

**OIDC vertical: DONE** (commits `53b94b5` impl, `5a6d305` R1 fixes, `0e1ad56`
R2 fixes, `c3a44fe` R3 blocker). Migration 00007, `internal/oidcrp`,
`internal/service/oidc*.go`, provider admin, dual-engine fixtures on
`internal/oidctest`. Built by an Opus 5 subagent (synchronous), reviewed on the
main thread. Blocking Codex cross-model pass ran the full 3-round cap:
- R1 (two focused passes): 5 HIGH (reauth possession/epoch/provider-rebind/
  downgrade + phase-C provider TOCTOU) + 2 MED + 3 LOW. Core transaction
  invariants (mix-up, binding, single-use, link, SSRF) verified sound.
- R2: reauth HIGHs held; 4 residuals folded (possession-`mfa` dropped,
  provider-race made serializable via `GuardProviderForMint` row lock, start
  timing uniform, callback default → 401).
- R3: 3 closed, 1 HIGH surfaced (provider-DELETE mint race) — closed with a
  `sessions.provider_id` ON DELETE CASCADE FK + lock-then-sweep ordering.
Deferred, named: browser CSRF token delivery + per-purpose check ride #56 (the
`csrf_verifier` is minted and the anti-fixation tx-binding ships); reauth-window
CONSUMPTION at disclosure is vertical #7 (this vertical only OPENS/refuses).

**WebAuthn vertical: DONE** (commit `0ae37c5` impl, `eaec02c` R1 fixes,
`64d7b84` R2 fixes). Migration 00008, `internal/webauthnrp`,
`internal/service/webauthn.go`, passkey login/enrol/step-up/reauth/remove,
sign-count/clone (B9), passkey-only post-state invariant (B4/B13), fixtures on
`descope/virtualwebauthn`. Cross-model 3-round cap: R1 (two passes) 2 HIGH
(credential-delete IDOR, browser session token in JSON body) + 4 MED; R2 4 held
/ 2 residual (login backoff keyed on attacker handle, ceremony binding
revalidation); R3 CLEAN. Disposition items: passwordless accounts can't yet
passkey-prove a mutation; the "drop password" B4 arm has no endpoint (invariant
enforced, reached by SQL in tests); `AccountByWebAuthnUserHandle` now unused
(remove in a codegen pass).

**Reauth/reset vertical: DONE** (uncommitted, main-thread review pending). No
new migration — reauth_windows, consumed_at/single_decision, and the
credential-reset/break-glass issuers all pre-exist in 00006. What landed:

- **Reauth-window CONSUMPTION** (`service.ConsumeReauthWindow(az, session, env,
  keyIDs, now)`): a disclosure on env E requires a live window for (session, E) —
  `now < hard_expires_at AND now < window_expires_at` at the current epoch; the
  sliding clock slides per disclosure capped at the hard cap; a `single_decision`
  window (0-window WebAuthn, unit-bound) is consumed exactly once via the
  consumed_at NULL guard and matched byte-exact to the ceremony's
  operation_binding. Ships as the library #50/#58's reveal path calls; no reveal
  op exists yet, so fixtures exercise it directly.
- **`service.ReauthTOTP`** (library, no HTTP endpoint): the TOTP analog of OIDC
  reauth — refuses at a 0 effective window naming the WebAuthn remedy, opens a
  sliding window above 0. Direct code presentation like the landed `StepUpTOTP`;
  `totp_challenges` is dormant codebase-wide (no writer), so B8's purpose wall is
  unexercised and the single-use step CAS is the operative control (stated
  deviation).
- **`LowerEffectiveWindow(az, envID, newValue, now) -> (stranded, invalidated)`**
  (B6): the five ADR items in one tx — invalidate the env's open windows, RETAIN
  grants, enumerate the stranded reveal/reveal-history holders (no WebAuthn
  authenticator), disclosure fails closed for them, factor enrolment stays
  reachable — plus the `auth.effective_window_lowered` event carrying the
  stranded list. Stranded computed only at `newValue <= 0`. #55's project-settings
  knob is the arriving caller.
- **`credential-reset`** (network): `POST /accounts/{principal}/credential-reset`,
  two registered ops (`credential-reset.org` tenant@org, `credential-reset.instance`)
  the service dispatches between by the target's grant classification —
  org-bounded (one org, no instance cap) → org op (an org-scoped OR inherited
  instance-scoped grant covers it); multi-org/zero-grant → instance op;
  instance-capability target → refused by name (break-glass only). The
  classification + mint run under a `principals` row lock every grant writer also
  takes (B14), making the org-bounded test serializable. Failures audited by
  cause (`instance-capability-target`, `unknown-target`), wire uniform (401/403).
- **Break-glass** (`hikyo admin reset-credential --principal ID`): host-local, root
  key required, reaches any target incl instance-cap holders, no network route
  (contract test asserts exactly one credential-reset HTTP path, the network one).
  Mirrors `hikyo admin create`'s local-authority mechanism; no SystemProof (rides
  the resolution surface like `BootstrapAdmin`).
- **Grant-lock analyzer** (`lint.CheckGrantLock`, B14): pins that every grant-table
  writer takes `LockPrincipalRow`; the lock is folded into `Resolver.CreateGrant`;
  negative fixture `testdata/badgrant`. #55's general grant surface inherits the
  obligation.
- CLI: `hikyo account reset-credential <principal>` (network) + `hikyo admin
  reset-credential` (host-local). Audit events `auth.credential_reset_issued`,
  `auth.effective_window_lowered` registered.

**Disposition items surfaced by this vertical (for the human):**

1. **A single-decision (0-window) reauth window has ZERO life unless
   `ReauthHardCap > 0`** — with both `ReauthWindow` and `ReauthHardCap` at 0 the
   window's `hard_expires_at == authenticated_at`, so consumption fails closed
   immediately. #55 / the ops-spec MUST set a non-zero hard cap before any
   `reveal` ships, or 0-window WebAuthn reauth is unusable. Low-stakes today (no
   reveal exercisable). The consumption library enforces the cap correctly.
2. **ADR issuer-list amendment still owed.** `issued_by='credential-reset'` and
   `'break-glass'` are in the ADR's list already; no amendment needed for those.
   Disposition 2 above (the `'recovery'` issuer) remains the outstanding
   wayfinder-docs edit — the implementer cannot commit to that repo, so the main
   thread owns landing the ADR amendment.
3. **Serializability is lock+analyzer-argued, not race-fixtured** (the task's
   stated option, mirroring the OIDC provider-race argument): sqlite serializes on
   its single writer; postgres holds `FOR UPDATE`; the analyzer proves every grant
   writer takes the same row lock the reset takes.
4. **credential-reset audits via `RecordAuthEvent`** (resolution surface,
   TrailInstance) though it authorizes through a chokepoint operation — a hybrid
   (recovery audits proof-free; provider-admin audits proof-bound). The event
   commits in the same tx as the reset, so durability holds; the minted proof is
   the authorization gate only (the writes are all resolution-surface).

**Delegation note (reliability):** in-process subagents and long background
shell jobs get reaped at main-process boundaries between turns. Mitigation:
run implementer/fix subagents SYNCHRONOUSLY (one uninterrupted process
lifetime), and run Codex reviews as small focused passes (foreground for tiny
diffs, bounded background for larger) so each finishes inside the window.

**Known follow-up:** the `internal/service/audit.go` query/export paths take a
bare principal (not a session `Identity`), so they are wrapped as session-less
(MFA-exempt) at their `Authorize` call. This is safe today — audit ops use
`CapAuditRead`, which is NOT MFA-mandatory, and they are not yet wired to HTTP —
but when audit read is exposed over the network it must thread the session
`Identity` like the demonstration services do, or a `reveal-history`-class read
would bypass the assurance gate. Noted so it is closed by name, not omission.

## Disposition items for the human (surface before the freeze)

1. **Default effective reauth window = 0 (fail-closed).** **DECIDED (human,
   2026-08-08): keep 0, fail-closed.** Until #55's `project-settings` knob
   lands, an unset window defaults to 0, requiring WebAuthn for a
   `reveal`-class disclosure and refusing TOTP there — reproducing the
   "WebAuthn-only for reveal" state the ADR *explicitly rejected*, but
   low-stakes because no `reveal` operation is exercisable until #50/#58 land.
   The window-store library still ships `LowerEffectiveWindow` (finding B6)
   for #55 to call when it introduces a settable window.
2. **`issued_by='recovery'` is a fourth credential-authority issuer** beyond
   the ADR's closed list (bootstrap, credential-reset, break-glass).
   **DECIDED (human, 2026-08-08): accept, amend the ADR's issuer list when
   the vertical lands** (do not introduce a separate `recovery_grants`
   table). The A1 fixture ("reveal attempted mid-reset") *requires* the
   intermediate session-less artifact to exist, so a direct-consume recovery
   cannot satisfy acceptance. The recovery issuer is constrained by CHECK to
   establish only a password, so it inherits none of the authority's future
   factor-establishing power. Same disposition shape as #47 deviation 1.
3. **`account establish-credential` spelling** (#47 deviation 2) is confirmed,
   not renamed, by this ticket.
4. **`scs` not adopted** — session resolution must run inside the request
   transaction at the chokepoint (permission ADR no-cache rule); scs's
   middleware model is that forbidden cache. The ADR substrate table gets the
   handoff note #47 already flagged.

## Scope partition (named exclusions)

- **SPA pages + Playwright UI ceremonies → #56.** The ticket says "once the
  shell exists"; the server surface here is complete so #56 is purely
  frontend. The CLI `login` (loopback handoff) and `login --device` transports
  keep their #47 refuse-by-name behaviour (both need the browser login page).
- **Member invitations → #55.** No `invitations` table exists. An unknown OIDC
  identity resolves: JIT policy admits, else uniform refusal. The
  invitation-claim path is a named seam (`ErrNoInvitationPath`).
- **Restore / epoch-bump reconciliation → #76.** Epoch checks on all new
  artifacts land here; the bump writer + operator reconciliation is #76's.
- **`project-settings` window values + protected-env cap knob → #55.** This
  ticket ships the window store, evaluation, hard cap, invalidation, the
  effective-window-0→WebAuthn rule, and `LowerEffectiveWindow(tx, envID,
  newValue)` as the library #55's knob must call.
- **SAML/SCIM → #72/#73; LDAP out of v1.** The identity key already carries
  the `kind` discriminator (`kind='oidc'` here).

---

## Blueprint — the reviewed design the remaining slices implement

Every item tagged **[A#]/[B#]** traces to an accepted investigation finding.

### Schema (landed in 00006; OIDC/WebAuthn get their own later migrations)

`totp_credentials` — surrogate `id` PK; `UNIQUE(account_id) WHERE confirmed_at
IS NOT NULL` so a pending enrolment cannot displace a confirmed factor **[B2]**;
`seed` envelope-encrypted (InstanceFieldAAD, owner `totp_credentials`);
`last_step` single-use guard floored at `created_step` so re-enrolment with a
kept seed cannot rewind it **[B19]**; `dek_version`/`row_version` for the
reencrypt CAS obligation.

`totp_challenges` — purpose-bound single-use challenge for a TOTP code
presentation, so a code authorizes exactly one operation **[B8]**. CHECKs:
reauth ⇒ `operation_binding` non-null; account-security ⇒ `session_id` non-null
**[B21]**.

`recovery_codes` — `account_id` PK, `batch` envelope-encrypted JSON array of
SHA-256 hashes of `rc`-grammar ≥128-bit codes; `row_version` CAS on
consume/regenerate **[B22]**.

`reauth_windows` — keyed by `session_id` only (never principal — a dead
session's window must never answer for a fresh one) **[B10]**; `ON DELETE
CASCADE` from sessions; `single_decision` + `consumed_at` NULL-guard so a
0-window WebAuthn ceremony authorizes exactly one enumerated unit **[B11]**;
two clocks (`window_expires_at` slides, `hard_expires_at` never extends).

`credential_authorities` rebuilt — `established_credential_kind` +
`CHECK(issued_by <> 'recovery' OR established_credential_kind = 'password')`
**[B1/B17]**.

**OIDC migration (next):** `oidc_providers` (issuer **immutable** after create
**[A3]**, `UNIQUE(kind,issuer) WHERE enabled`, client_secret envelope-encrypted,
nullable `jit_policy`/`assurance_policy`, `row_version`); `external_identities`
(`UNIQUE(kind,issuer,subject)` byte-exact, `provider_id` provenance NOT in the
key **[A3]**, no email column ever); `oidc_transactions` (`binding_kind` NOT
NULL discriminator with no default callback branch **[A2]**, per-provider
`redirect_uri`, `ceremony_id` for link **[A6]**, `provider_id` `ON DELETE
CASCADE` **[A14]**, `nonce` hashed / `pkce_verifier` raw **[A19]**);
`sessions.provider_id` (federated-session sweep key **[A4]**).

**WebAuthn migration (next):** `webauthn_credentials` (opaque random
`user_handle`, `disabled_at`, `discoverable`, `backup_eligible`/`backup_state`
consulted for the sign-count skip **[B9]**, sign-count CAS); `webauthn_ceremonies`
(purpose-conditional nullability CHECKs **[B21]**, `operation_binding` for
reauth + account-security **[A6]**); `accounts.webauthn_user_handle` UNIQUE.

### OIDC transaction (service)

PKCE S256 always; server-side single-use transaction row; token exchange only
at the recorded provider **[sound]**; mix-up refused before token inspection
via per-provider **distinct callback path** (`.../oidc/{slug}/callback`, the
redirect URI is per-provider not a fixed path **[A1]**) + RFC 9207 `iss` when
advertised; complete ID-token validation (exact iss, alg allowlist, aud, azp,
exp/iat skew, nonce); purpose wall (`login`/`link`/`reauth` cannot substitute);
byte-exact `(kind,issuer,subject)` (no trimming/case-fold/normalize); empty
`sub` refused **[A15]**; three-state resolution `live`/`epoch-inert`/`unknown`
where epoch-inert is terminal, never JIT input **[A8]**; discovery refresh
reconstructs via go-oidc (re-asserts byte-exact issuer) **[A20]**; IdP `error=`
consumes+audits the tx **[A18]**; no caller-supplied return target **[A17]**.

Anonymous-login CSRF/fixation: `binding_kind` discriminator, `session` or
`browser-cookie` (`__Host-hikyo-oidc-tx`, `SameSite=Lax`, per-tx-suffixed name),
hash on the tx row, byte-matched before consume, no default branch **[A2/A16/A22]**.

OIDC reauth: refused when the provider's `assurance_policy` is NULL or the
satisfied `amr` carries no possession factor **[A5/B5]**; absent `auth_time` is
a refusal not a downgrade **[A7]**; must re-present the identity/credential
class the session authenticated with, or one at least as strong **[B15]**;
opens a window only where the effective window > 0 (only WebAuthn opens a
0-window gate).

### Sessions / assurance

Browser session under `crypto.ArtifactBrowserSession` ("br"); cookie leg
accepts only "br", header leg only "cli"; a request carrying both is refused;
CSRF requirement decided in transport, never inferred from the row **[A10]**.
CSRF token delivered via authenticated `GET /auth/whoami` after the redirect
lands, regenerated on rotation **[A9]**. `Authenticate` must accept both
artifact types (today hard-pins cli).

Assurance enforcement flips to `true` (the tripwire test demands it once any
factor event registers). MFA-mandatory ⇒ session factors carry ≥2 distinct
classes, or `webauthn` (UV = inherent 2FA), or `oidc:<issuer>` whose recorded
acr/amr satisfied the provider policy *at login*, evaluated in the mint tx with
the provider `row_version` recorded **[A12]**; provider-change sweep by
`provider_id` deletes stale-assurance sessions **[A4]**. Reissued acting session
assurance is built **solely from the proof ceremony**, never copied from the
prior session **[B3]**; a factor class with no live backing credential is
treated as absent **[B3]**.

Generation counter advances (same tx as the trigger) on: grant
revoke/add/widen, password change/reset, factor/passkey enrol/remove,
recovery-code consume, admin reset, unlink, provider change. Every
generation-advancing path also deletes the principal's session rows **[B10]**.
New audit events: `auth.session_rotated` (cause), `auth.generation_advanced`
(closed cause enum).

### Factors

**TOTP** (`pquerna/otp`, HMAC → the code lives behind `internal/crypto`):
`enrol/start` requires the account-security proof up front and binds the seed
to that ceremony **[B2]**; `confirmed_at IS NOT NULL AND created<ceremony` is
the *one* predicate all code paths call **[B2/B7]**; `enrol/confirm` consumes a
step through the same single consumption function **[B20]**; single-use per
`(account, step)` floored at `created_step` **[B19]**.

**WebAuthn** (`go-webauthn`): RP ID + expected origins are immutable instance
config, required to enable any WebAuthn route, exact-origin match, UV required
and verified, opaque user handle, discoverable required for login; sign-count
check skipped when `backup_eligible=1` or both counters 0, and a real
regression disables the credential + deletes its sessions/windows + advances
generation in one tx before refusing **[B9]**. Passkey-only precondition is a
**post-state invariant** `assertPasskeyOnlyInvariant(tx, accountID)` run in
every tx touching credentials/recovery/epoch; *current batch* = live-epoch row
with ≥1 unconsumed hash; the ≥2 count is over `discoverable=1` only, absent
`credProps` ⇒ discoverable=0 fail-closed **[B4/B13]**.

**Recovery codes**: batch generate (display-once), single-use consume (CAS +
mint authority in one tx, losing CAS discards the authority **[B22]**);
consumption on a passwordless account is a named terminal state blocking
further account-security mutations until regenerate **[B4]**.

### Account-security mutations (one helper)

`requireAccountSecurityProof(tx, account, ceremonyID, excluded)` — accepts a
ceremony id (so the synchronous and deferred OIDC-link paths are ONE
implementation **[A6]**), evaluates over `{credentials confirmed/created
strictly < ceremony.created_at} \ excluded`; "no possession factor" computed
over that same filtered set **[B7]**. Then in ONE tx: mutation +
`AdvanceGeneration` + delete all sessions + reissue acting session from the
proof (no inherited windows, assurance from the ceremony only) + audit naming
the mutation and authorizing credential class. `establish` is **password-only**
**[B1]**. Minting an authority for a principal marks every outstanding
unconsumed authority for that principal consumed in the same tx **[B12]**.

### Reauth windows / credential-reset / break-glass

`LowerEffectiveWindow(tx, envID, newValue) → (stranded, invalidated)` performs
the five ADR items + the stranded-principal audit event; #55 calls it **[B6]**.
`credential-reset` (org|instance scope): org-bounded target test evaluated in
the same tx as the mint, made serializable by a `SELECT ... FOR UPDATE` on the
target `principals` row that every grant-mutation tx must also take — enforced
by a new lint analyzer, obligation documented for #55/#44 **[B14]**;
instance-capability targets refused over the network by name. Break-glass:
`hikyo admin reset-credential` host-local only, root key required, no network
route (contract test asserts no such path).

### Wire + admission + audit + fixtures

Endpoints per §3 of the blueprint; every pre-auth path enters the existing
admission budget (`AccountDelay` before `Enter`), uniform refusals, dummy work
on unknown subject. New audit events registered (registering any factor event
forces the `AssuranceEnforced` flip in the same PR — budget for updating the
demo/bootstrap E2E flows, since the first admin's instance caps become
refusable until factors are enrolled). CSRF on `/auth/oidc/{p}/start` is
per-purpose (login pre-auth exempt; link/reauth require the token) **[A23]**.

**Fixture families (mvp-boundary A1), dual-engine:** every login path; IdP
mix-up (both directions) **[A13]**; byte-exact linking incl. issuer-case and
subject-case; recovery single-use + credential-establishment-as-complete-flow
with a mid-reset reveal attempt refused; break-glass on-host only; grant
add/widen/revoke each invalidate sessions; boot refused below the Argon2id
floor; credential epoch inert; account-security mutation cannot self-authorize;
assurance step-up; 0-window (TOTP refused, WebAuthn unit-bound passes, wrong-unit
refused, double-spend refused **[B11]**); CSRF cookie-mutation-without-header
refused; purpose walls; auth_time absent/stale; policy-less reauth refused;
policy-change kills federated sessions; issuer-change vs existing links. [CI]
pre-auth admission invariant extended to enumerate every new pre-auth route.

## Mechanical build-breakers (from the two codebase explorers — do not relearn)

- ASCII-only sqlc query-file comments (multibyte shifts sqlite statement
  offsets and silently truncates — hit twice already).
- Add every new table to the postgres isolation harness `DROP TABLE` list,
  **before `principals`**.
- Every new proof-free writer in `internal/store/authn` → name it in
  `lint.ResolutionSurfaceWriters`.
- Re-pin `annotated_queries.json`, `operation_formulas.json`,
  `audited_exemptions.json`; CLI golden fixtures (`go test ./internal/cli
  -update`, read the diff).
- Registering any of the seven factor audit events while
  `authz.AssuranceEnforced == false` fails the build — flip it in the same PR.
- `AccountDelay` before `Enter` on every new pre-auth path.
- No `domain.OrgID`/`ProjectID`/`EnvID` typed values in store-method
  signatures **or struct fields** (proofsig analyzer); environment ids are
  plain `string` at the store boundary.
- New endpoint → all five `x-hikyo-*` extensions + regen + `wireRegistry` +
  `wireRoutes`/`wireEvents`; four invariants fail until all done.
- New table → `-- hikyo:table <name> class=authn chain=-` in BOTH dialects.
- New sensitive/material-holding type → embed `crypto.redactor` + pin in
  `lint.SensitiveTypes`.

## Continuation order

1. Store: sqlc queries + `internal/store/authn` writers for 00006's tables +
   repos wiring + lint re-pins. (Shared dependency — do first, alone.)
2. TOTP + recovery + account-security-mutation helper + credential-establishment
   (password-only) service; flip `AssuranceEnforced`; update demo/bootstrap E2E
   to enrol a factor; the A1 recovery fixture. (Smallest complete vertical.)
3. OIDC migration + `internal/oidcrp` + service + provider admin + wire +
   mix-up/issuer-case/purpose-wall fixtures.
4. WebAuthn migration + `internal/webauthnrp` + service + wire + passkey-only
   + sign-count fixtures.
5. Reauth windows + `LowerEffectiveWindow` + credential-reset + break-glass +
   the grant-lock analyzer.
6. Full dual-engine suite green → `/code-review` → blocking Codex cross-model
   pass (3-round cap) → land.

---

## FINAL STATUS (2026-08-08): #54 complete — all four verticals cross-model CLEAN

| Vertical | Impl commit(s) | Cross-model | Result |
|---|---|---|---|
| Factors: TOTP, recovery, account-security, assurance flip | e97a461 (+e877a1a, 825730b) | 3-round | CLEAN |
| OIDC multi-provider: transactions, linking, provider admin | 53b94b5 (+5a6d305, 0e1ad56, c3a44fe) | 3-round + R3 blocker | CLEAN |
| WebAuthn / passkeys | 0ae37c5 (+eaec02c, 64d7b84) | 3-round | CLEAN |
| Reauth windows / credential-reset / break-glass | 4a3e1af (+389005c, 2213b03) | 3-round | CLEAN |

Migrations 00006–00008 (dual-engine). Uncached `go test ./...` green on sqlite;
`go vet` + `gofmt` clean; dialects structurally identical (CI runs postgres).
Each vertical: implemented by an Opus 5 subagent (synchronous), independently
re-verified on the main thread, then a blocking Codex `gpt-5.6-sol` high-effort
cross-model pass to a CLEAN verdict within the 3-round cap; all findings folded
by delegated Opus 5 fix subagents. Review artifacts in `.xreview/54-*`.

Cross-model caught and closed, among others: recovery-sheet→MFA (CRITICAL,
factor design), unthrottled TOTP brute-force + Argon2 oracle, OIDC reauth
possession/epoch/provider-rebind/downgrade + phase-C provider TOCTOU +
provider-delete mint race, WebAuthn credential-delete IDOR + browser-token-in-body
+ ceremony-binding revalidation, and the reauth effective-window-seam
consistency (slide/clamp).

### Corrections to the per-vertical sections above (superseded by review fixes)
- credential-reset instance-capability-target refusal is now the UNIFORM refusal
  (no distinct 403 grant-shape oracle); the cause lives only in the audit trail.
- The reauth-window slide and the WebAuthn open both go through the single
  `effectiveReauthWindow(env)` seam and clamp to the hard cap (a tripwire test
  pins the global window to one read site).

### Deferred, each named to its ticket (scoped out, not gaps here)
- Browser CSRF token delivery + per-purpose check → **#56** (SPA); `csrf_verifier`
  minted, anti-fixation tx-binding ships, browser session tokens are cookie-only.
- Per-env reauth-window values behind `effectiveReauthWindow` → **#55**
  (project-settings); `LowerEffectiveWindow` is the library it calls; default 0.
- `reveal`/`reveal-history` that CONSUME a window → **#50/#58** (consumption is a
  tested library; no live reveal endpoint yet).
- Member invitations → **#55**; restore/epoch-bump reconciliation → **#76**;
  UI Playwright ceremonies → **#56**; common-password full list → #47 follow-up.
- `issued_by='recovery'` ADR amendment on wayfinder-docs → owed (human's).
- Passwordless passkey-proof mutations; the "drop password" B4 arm has no
  endpoint (invariant enforced, SQL-reached in tests); `AccountByWebAuthnUserHandle`
  now unused — remove in a codegen-capable pass.

### Human-merge gate
CI green + cross-model CLEAN across all four verticals. NOT merged — awaiting the
human one-click merge decision (branch t3code/review-auth-assurance-flows).
