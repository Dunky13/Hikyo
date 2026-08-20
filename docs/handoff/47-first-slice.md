# Handoff: #47 first slice — OpenAPI 3.1 API, CLI skeleton, bootstrap admin, local login

Issue: https://github.com/Hikyo-Org/Hikyo/issues/47 (parent #41). Specs, all on
`wayfinder-docs`: `docs/adr/api-cli-surface.md`, `docs/spec/api-cli-spellings.md`,
`docs/adr/human-auth.md` (bootstrap + local floor slice), `docs/adr/mvp-boundary.md`
rows S1/S2/A1, and the operative 2026-08-07 OpenAPI 3.1 amendment banner in
`docs/adr/system-architecture.md`.

## Scope decisions taken with the human, before building

**Login transports — local floor only.** #54 ("Human auth, full") says in its
own body that it *"extends the bootstrap/local slice already landed"* and is
blocked by this ticket, so the partition was already the ticket authors'. The
loopback handoff and the device-code flow both need the instance's own
browser login page plus the `__Host-` cookie session surface, and the SPA is
explicitly out of this slice (#56). Building throwaway HTML for both would
have been ~2–3× this auth slice and most of it deleted when the SPA lands.

`login` and `login --device` therefore **refuse by name** (exit 4) rather than
falling back to `--local` — a silent fallback would skip a ceremony the
operator asked for. The transport dispatch seam is built, so adding them is
additive. **S2's "each login transport" is carried forward to #54.**

**Assurance — recorded now, enforced with the factors.** Every session carries
the full assurance record (method, factor classes presented, `authenticated_at`,
ceremony id) from day one, so no migration is needed when the check turns on.
The chokepoint's *enforcement* is off (`authz.AssuranceEnforced == false`) and
visibly so: no factor exists to satisfy it, and enforcing now would leave a
freshly bootstrapped administrator unable to perform the very operations that
administer the instance, with no in-product path to enrol out of it.
`isolation.TestAssuranceEnforcementCannotBeForgotten` is the guard.

## What exists

### The contract (`api/`)

`api/openapi.yaml` is the single source of truth and is **embedded in the
binary**, so the running server validates traffic against exactly the bytes CI
diffed. The `api` package is a real Go package at the ADR's fixed path for
that reason — `go:embed` cannot reach outside its own directory.

- OpenAPI **3.1** per the amendment banner. `/api/v1/meta`, the
  identity-protocol endpoints (`auth/credential/establish`, `auth/local/login`,
  `auth/logout`, `auth/whoami`), and the org surface as the first audited
  mutating domain endpoint.
- **oapi-codegen v2.8.0** strict-server + models → `api/apigen`. The pin is
  asserted by a test that names the amendment obligation, so the generator
  cannot move on a dependency bump.
- **kin-openapi v0.146** for both duties the banner separates: runtime request
  validation in the server, and wire-response validation in the contract
  tests. Both demonstrated against the 3.1 document (see *Toolchain* below).
- **Hikyo extensions**, cross-checked against the Go registries in CI:
  `x-hikyo-class`, `x-hikyo-operation`, `x-hikyo-formula`, `x-hikyo-artifacts`,
  `x-hikyo-min-revision`, and `x-extensible-enum` for open enums.
- `CheckProfile` enforces the bound 3.1 semantic profile — `nullable`
  prohibited, `jsonSchemaDialect` pinned, top-level `webhooks` prohibited,
  open enums forbidden from also carrying `enum` — with a refusal test per
  prohibited construct.
- `CheckFreeze` is the oasdiff gate: every check down to INFO, fail-closed
  over `PermittedChanges`. oasdiff's own severity taxonomy is deliberately not
  the policy.

### Transport (`internal/server`)

The router **partitions** health probes from the contract: a liveness probe
refusable by the admission budget would turn a login flood into a restart
loop. Everything under `/api/v1` is contract-validated before a handler sees
it; anything else is a 404 in the contract's own error shape.

One error writer, **fixed message per code**. `detail` exists only on
`bad_request`, which is decided before any tenant resolution. Wire metadata is
attached per request (the audit ADR's inherited obligation), with forwarded
headers believed only from a configured trusted proxy. The bearer is carried
**raw** into the handler and resolved only at the chokepoint.

### Authentication (`internal/authz`, `internal/service`, `internal/store/authn`)

Session resolution sits on the transaction's authorizer, not in middleware —
the human-auth ADR requires it in the same chokepoint as `authorize()`, in the
same transaction, uncached, and a middleware deciding "authenticated" before a
transaction exists is the cross-request cache the permission model forbids.

- Migration `00005` (both engines): `accounts`, `password_credentials`
  (envelope-encrypted Argon2id verifier + a `row_version` CAS target),
  `sessions` (verifier hash, artifact, assurance record, generation, two
  clocks), `credential_authorities`, `auth_instance_state` (credential epoch).
  `principals` gains `session_generation`.
- Liveness is evaluated in one place: grammar → row → idle clock → absolute
  clock → session generation → credential epoch. Every failure answers
  `domain.ErrUnauthenticated` and nothing else.
- `internal/crypto` gains Argon2id (the `x/crypto` import boundary is why it
  lives there) with the `m=64MiB, t=3, p=2` **boot floor**. Raising is allowed;
  lowering refuses to start. `VerifyPassword` deliberately does *not* enforce
  the floor, or raising it would lock out every existing account.
- Bearer artifacts adopt the locked `hik_` grammar with the type list's
  existing `cli` and `bs` entries, so the audit package's redaction filter
  covers them for free and no second unfiltered grammar exists.
- `internal/admission`: derived concurrency
  `clamp(floor((budget−16MiB)/m), 1, 8)`, queue depth 16, per-IP sliding
  window, per-account exponential backoff with **no hard lockout**. Buckets are
  keyed on the *presented* identifier, so an unknown account gets one exactly
  like a real one.
- Local login burns a dummy verification on every non-verifying path
  (unknown account, no credential, stale epoch), so all of them cost what a
  wrong password costs.

### CLI (`internal/cli`, `internal/disclose`)

- **Trust store.** Two establishment acts only: an interactive ceremony
  displaying origin + leaf public-key fingerprint, or a provisioned bundle.
  An unestablished reference is exit 4 naming the missing provisioning step —
  never a prompt-to-trust mid-command.
- The pin is checked **leaf-only** and replaces chain verification (self-hosters
  run their own CA). Redirects are never followed with a credential; plaintext
  http to anything but loopback is refused outright.
- **Context resolution** is per dimension, first hit wins, with no persistent
  active context. The resolved target is echoed to stderr with the precedence
  level that supplied each dimension.
- **The print triad** (`internal/disclose`): controlling terminal /
  dirfd-checked `O_EXCL` 0600 file / `--dangerously-print`. Ordinary stdout is
  refused even when stdout is a TTY.
- Passwords are read from `/dev/tty` with echo off. There is no `--password`
  flag and no stdin fallback.
- `hikyo admin create` mints the first administrator on the server's own host
  with the `admin` template expanded into one grant row per capability.

### TypeScript (`clients/ts`)

`@hey-api/openapi-ts` + Zod from the same 3.1 document. Machinery only, no
SPA. Its own fixtures prove the semantics survive the second generator: an
open enum accepts an unknown value, a closed one refuses a typo, and nullable
members keep absent / null / value distinct.

## Acceptance criteria → evidence

| Criterion | Where |
|---|---|
| [CI] oasdiff fail-closed gate + negative fixtures | `api.TestFreezeGateFixtures` (9 pairs), `api.TestAllowlistNamesThePromisedAdditions` |
| [CI] 3.1 negative-fixture set (nullable, dialect, webhooks, downgrade) | `api.TestBoundProfileRefusals`, freeze fixtures |
| [CI] HTTP contract tests validate real wire responses | `internal/server/contract_test.go` — every call validates the response against the document |
| [E2E] golden snapshots per shipped verb | `internal/cli/testdata/{help.txt,exit-codes.txt,context-list-empty.json}` |
| [E2E] trust-store establishment | `cli.TestAnUnestablishedReferenceIsRefusedNotPrompted`, `TestPinFileCanDirectButNeverIntroducesAnOrigin`, demo E2E (interactive), manual (provisioned) |
| [E2E] each login transport | **local only**; handoff + device refuse by name. Carried to #54. |
| [CI] parity harness with closed exemption list | `internal/isolation/contract_test.go` + `testdata/audited_exemptions.json` |
| [E2E] bootstrap first-admin end to end | `isolation.TestDemoFlow{SQLite,Postgres}`, `human_authentication_flow` |
| [E2E] local login | same |
| [E2E] boot refused below the Argon2id floor | `crypto.TestBootFloorRefusesEachShortParameter`, `app.AuthComponents` |
| [E2E] non-TTY stdout refused | `disclose.TestNonTTYWithNoFlagIsRefused`, `TestPreflightRefusesBeforeAnythingIsMinted`, verified with the real binary |
| Demo on both engines | `isolation.TestDemoFlow{SQLite,Postgres}` |

## Verified empirically (real binary, sqlite)

- `admin create` without a root key: refuses, names the fix.
- `admin create --output-file`: 0600 file holding `hik_1_bs_…` and nothing else.
- A second `admin create`: refused — first administrator only.
- `/api/v1/meta`: exactly the three allowlisted members.
- Absent vs garbage bearer: byte-identical 401 bodies.
- Establish → replay refused (single use) → login → wrong password and unknown
  user byte-identical → authenticated `POST /orgs` → 201.
- Audit trail after the flow: `credential_authority_minted`,
  `credential_established`, `credential_authority_refused`, `login` (success),
  `session_created`, `login` (failure ×2), `settings.org_created`.
- Dump grep: session token, password and authority all absent from the database.
- Non-TTY establishment and non-TTY delivery both refuse, and the delivery
  refusal now happens **before** anything is created.
- State directory `0700`, files `0600`.

Full suite green on sqlite **and** postgres 18 (local container).

## Deviations from the ADR letter — stated, for human disposition

1. **The resolution surface has more than one write path.** The audit-model
   ADR's amendment part 4 pinned `WriteDenial` as the single proof-free writer.
   Human authentication is the same circularity from the other side: resolving,
   minting and revoking the artifact that decides *who* a caller is cannot run
   under a proof, because the proof is what that answer produces, and
   credential establishment deliberately produces no session at all.
   `internal/lint.ResolutionSurfaceWriters` is now a **pinned enumerated
   list** — every proof-free writer named in one place, with a build failure
   behind anything unlisted. The property the "exactly one" protected is
   preserved; the wording is not.

   **Disposition (human, 2026-08-07): accept as-is; amend the ADR later.**
   The property the "exactly one" protected — every proof-free write named in
   one place behind a build-failing analyzer — is preserved and now
   mechanically *stronger* than a count. The old check was fail-open: "exactly
   one" was enforced only by there happening to be one, and a second writer
   would have slipped in silently (which is precisely the round-2 finding).
   Auth is irreducibly more than one bootstrap write — create-first-admin,
   establish-credential, session lifecycle — so "exactly one" cannot be met
   without hiding thirteen operations behind a single name, which makes review
   worse, not better. audit-model.md's "single write path" clause gets an
   amendment naming the human-auth authority when #54 lands; nothing in #54 is
   blocked by the wording.

2. **`hikyo account establish-credential` is a spelling this ticket adds.** The
   ADR fixes the `account` family as `session`/`factor`/`recovery-codes`. The
   bootstrap path needs a terminal way to consume the authority `admin create`
   mints, and the browser path that would otherwise carry it is #54's. It joins
   the **existing** family under the existing grammar — no new verb family, no
   new output class. #54 confirms or renames it before the freeze.

3. **The `admin` template expands at instance scope.** A fresh instance has no
   org for an org-scoped template to attach to, and the first administrator's
   job is to create one. The full template catalogue with org-scoped
   application is #55's.

4. **The per-account throttle is in memory, not in the database.** v1's locked
   deployment envelope is a single node with no HA, so process-local state is
   the whole instance's state; a durable throttle would add a write per failed
   attempt, amplifying exactly the flood it bounds. A multi-node build must
   replace it — the constraint is written at the top of `internal/admission`.

5. **The common-password list is a mechanism without its data.** The ops spec
   names an embedded top-100k SecLists/HIBP-derived list, pinned and
   hash-checked in CI. The whole mechanism is implemented — length floor,
   no composition rules, no forced rotation, set-time-only checking, and the
   embedded-list lookup — but **the bundled list is a ~90-entry starter set**,
   because sourcing the real one needs a network fetch and a licence review
   this ticket did not do. `service.TestCommonListIsAKnownPlaceholder` fails
   the day the file grows past the placeholder bound, so the two cannot be
   confused, and its failure message names what else to update. This is the
   one acceptance-adjacent item this slice leaves short. **Disposition
   (human): follow-up ticket, not this PR** — the full list needs sourcing
   and a licence review; the starter set ships here behind the placeholder
   guard.

6. **The freeze gate is fixture-proven, not yet armed.** No freeze tag exists,
   so there is no immutable base to diff the live contract against. The
   machinery is exercised entirely by synthetic base/revised pairs.

7. **`--dangerously-print` on Windows has a weaker file leg.** The
   dirfd-relative create and the owner-only DACL have no direct equivalent;
   Windows is a client platform, so the bootstrap path (server host, unix) is
   unaffected. Stated in `internal/disclose/file_windows.go`.

## Defects found and fixed while building

Recorded because each was found by a check rather than by reading:

- **Refusal events were rolled back with their own refusal.** Login failures
  and authority refusals returned their sentinel from inside `tx.Write`, so
  every failure event was discarded. Found by the audit emitter invariant.
- **sqlc's sqlite engine truncated two statements.** Multibyte characters in
  query-file comments shift its statement offsets; `DeleteSessionsForPrincipal`
  had been generated as `DELETE FROM sessions WHERE principal_id =`. All query
  comments are now ASCII (this is the second time the repo has hit it — see
  handoff 44).
- **Leaf-only pinning.** The TLS pin check scanned every presented certificate,
  so an attacker could satisfy it by including the legitimate certificate as an
  intermediate under a leaf whose key they held.
- **`hikyo login <url> --local` refused itself.** Go's `flag` stops at the first
  positional, so the spelling the help advertises was parsed as three
  positionals.
- **A trust-store refusal exited 1, not 4.**
- **Argon2id ran inside a write transaction.** sqlite has one write
  connection, so four concurrent logins — exactly the admission budget —
  would have stalled every write on the instance for the length of a
  derivation each. Login is now read / verify / write, with the write phase
  re-reading the credential so a password changed mid-login cannot mint a
  session.
- **The idle-clock touch opened a write transaction for any bearer**,
  including a fabricated one, so the same contention was reachable by anyone
  sending a noise Authorization header.
- **`/meta` had no rate limit** despite being the endpoint `login` calls
  before every authentication.
- **`admin create` created the administrator before checking it could deliver
  the authority** — leaving an instance bootstrapped with a value nobody saw
  and a command that refuses to run again. `disclose.Preflight` now runs first.

## Cross-model review (Codex `gpt-5.6-sol`, high effort)

Standing rule: Claude-authored code gets a blocking pass by the other
vendor's model. Round 1 was run twice — the first attempt died with context
exhausted on a 445 KB diff, which is CODEX.md's documented failure mode — and
then split into two focused passes over the actual files. Both reports are in
`.xreview/`.

**Round 1: 4 blockers, 11 highs, 6 mediums, 2 lows across the two passes.**
All fixed in this branch; none deferred. The two that mattered most:

1. **Identity was resolved in a different transaction from the operation it
   authorized.** Both reviewers found it independently. The transport
   resolved the session, then handed a bare principal id to a service that
   opened its own transaction — so a session revoked in between still
   authorized the operation. A principal id crossing a transaction boundary
   IS the cross-request authorization cache the permission model forbids; it
   just looks like an argument. `service.Actor` now carries the raw artifact
   and the service resolves it at the chokepoint, with a lint check refusing
   `internal/server` the right to name the bypass constructor.

2. **The proof-free-writer analyzer was fail-open.** It guessed "does this
   mutate?" from a name-prefix list, and `ConsumeCredentialAuthority`,
   `TouchSession` and `AdvancePrincipalGeneration` match no listed prefix —
   so three real writers bypassed the enforcement that exists to catch
   exactly them. Classification now comes from sqlc's own command
   annotation, with an unrecognised command treated as mutating.

Also fixed: `EstablishCredential` derived Argon2id inside a write
transaction; the malformed-authority audit event was rolled back with the
refusal it recorded (a previous pass claimed to have fixed this and had not —
the reviewer read the code, not the claim); an unreadable verifier answered
500 while a missing account answered 401, an account-existence oracle;
session liveness returned early so the query count told you why an artifact
was dead; the KDF upgrade existed only in a comment; per-account backoff slept
while holding an expensive-work slot; stored KDF parameters were unbounded
before Argon2id allocated; `ParseArtifact` accepted arbitrary bytes;
`X-Forwarded-For` was read leftmost, which is the client-controlled end; the
freeze allowlist permitted closed-enum growth and optionality relaxation;
a failed disclosure left its file behind; an explicit instance URL was not
compared against the trust entry it resolved to; the limiter's maps were
unbounded.

**Round 2** verified the fixes: 10 HOLDS, 5 PARTIAL, 0 new criticals. All five
partials closed in the follow-up commit — the Actor pattern extended to the
Projects/Environments demonstration services; login/authority refusal audit
failures made loud rather than swallowed with `_ =`; the proof-free-writer
analyzer broadened to catch a mutating query taken as a method value; the
artifact grammar tightened to a canonical decode so the accepted set equals
the emittable set; and an oldest-live fallback added to account eviction so
the limiter maps cannot grow past their bound.

**Round 3 (the cap): CLEAN.** All five round-2 partials verified closed, no
blocking items, no new scope. The adversarial loop is complete.

### Known-open, for disposition

- **State-directory hardening.** Existing state files are not checked for
  ownership, mode, symlink status or regular-file-ness, and the temporary
  files used for atomic replacement have fixed names. A pre-existing
  writable or symlinked state directory is therefore a session-disclosure
  path. The disclosure path (`internal/disclose`) IS hardened; the CLI's own
  state directory is not. Bounded work, not done here.
- **A hostile pin file can still select among ALREADY-TRUSTED instances.**
  Origin binding now covers the case where the operator names a URL
  explicitly. A `.hikyo.json` that names a bare reference can still direct a
  command at a different established instance the box already trusts — which
  is the residual the ADR itself states ("bounded to retargeting within
  origins this box already trusts"), but the reviewer's point that
  `--context` should outrank a repository file is a fair reading and is not
  implemented.
- **Username is not re-resolved between the read and write phases of login.**
  No rename verb exists, so the race is currently unreachable; it becomes
  reachable the day one lands.
- **The freeze gate is not armed against a baseline in CI.** By design —
  pre-freeze the spec may change freely, and there is no freeze tag to diff
  against. The gate is fixture-proven and the CI wiring is the freeze
  ticket's.

## Pickup notes

- Adding an endpoint: describe it in `api/openapi.yaml` with all five
  `x-hikyo-*` extensions, regenerate (`go tool oapi-codegen --config
  api/oapi-codegen.yaml api/openapi.yaml`), classify the route in
  `authz.wireRegistry`, and map it in `wireRoutes` (domain) or `wireEvents`
  (authentication). Four invariants fail until all of that is done.
- Adding a proof-free writer to `internal/store/authn`: name it in
  `lint.ResolutionSurfaceWriters`. That diff is the review artifact.
- Re-pin on change: `annotated_queries.json` (58 entries now),
  `audited_exemptions.json`, `operation_formulas.json`, and the CLI golden
  fixtures (`go test ./internal/cli -update`, then read the diff).
- Postgres locally: any 17/18 scratch database. The isolation and conformance
  harnesses drop the authentication tables before `principals` — sessions and
  accounts reference it.
- TypeScript: `corepack pnpm install && pnpm run verify` in `clients/ts`,
  Node from `.nvmrc`.
- The `api` package is importable by anything, deliberately: it is the
  published contract. `internal/server` must **not** import `internal/authz`
  (boundary test), which is why `service.Identity` exists beside
  `authz.Identity`.
