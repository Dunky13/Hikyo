# Handoff: #58 Reveal / copy / publish-into-protected ceremonies

Parent #41. Binds [permission-model.md](https://github.com/Hikyo-Org/hikyo/blob/wayfinder-docs/docs/adr/permission-model.md)
§ *The reveal guard* and § *Disclosure by proxy*, [audit-model.md](https://github.com/Hikyo-Org/hikyo/blob/wayfinder-docs/docs/adr/audit-model.md)
(one disclosure event per key), [human-auth.md](https://github.com/Hikyo-Org/hikyo/blob/wayfinder-docs/docs/adr/human-auth.md)
(the reauthentication primitive), mvp-boundary rows **A5** and **S3**, and the
frozen prototype `prototype/reveal-edit/` — **approach a, the ceremony modal**
(locked 2026-08-02; the inline popover, hold-to-reveal and session drawer were
rejected).

## The division of labour with #50

#50 gave the value surface its **capability** half: `read(E) ∧ reveal(E)` at
the chokepoint, and one `disclosure.value_revealed` per key. It deliberately
did not build the gate in front of that — `internal/service/reauth.go` says so
in its own header ("There is no `reveal` operation to call ConsumeReauthWindow
yet (it lands with #50/#58)").

#58 is that gate, plus the browser. **Almost nothing here is new machinery**:
`Auth.ConsumeReauthWindow`, `Auth.ReauthTOTP`, `effectiveReauthWindow` and the
WebAuthn reauth ceremony all landed with #54/#55. This ticket is the seam that
calls them at the value surface, the two endpoints that were waiting on it, and
the UI.

## What landed — server

**The ceremony seam (`internal/service/ceremony.go`).** One function,
`requireCeremony`, and a `ceremonyGate` closure the value paths hand down.
Three ADR invariants are load-bearing:

1. **The window gates the PROMPT, never the check.** Every gate call runs
   *after* `authorize()` has produced a proof, inside the disclosure's own
   transaction. A revoked `reveal` therefore stops revealing on the next cell
   even inside an open window — the capability check ran first and failed
   first.
2. **The gate covers every route in the formula table**, not only the matrix
   cell: cell reveal, bulk reveal, diff reveal, and **both ends of a copy** —
   gated differently, and the difference is the ADR's. The **source** is a
   disclosure and always takes the ceremony. The **destination** takes one when
   it is **protected**, which is where the ADR puts protected-environment
   confirmation and where the locked prototype puts the publish-into-protected
   ceremony. A non-protected destination stays capability-only: its `reveal`
   conjunct is checked at the chokepoint like any other, and inventing a prompt
   there would train people to click through the one that matters.
3. **Machines never reauthenticate** ("the token IS the credential"). The
   exemption is structural, not a flag: `authz.Identity.SessionID` is empty for
   a machine identity, and `skipsCeremony` reads exactly that. It mirrors the
   existing MFA-mandatory exemption for local host authority, which sits on the
   same field.

**Where the gate fires (`internal/service/values.go`).** `readCells` gained a
`discloseGate` callback, invoked **after** the catalogue and value rows are
resolved (so the enumerated unit is known exactly) and **before** the first
ciphertext is opened (so a refusal discloses nothing and writes no disclosure
event). `openSourceMaterial` gained the same, between the plan and the open, on
every caller of the pair — copy and clone alike.

The unit is `(environment, sorted key ids)` where the key ids are the `secret`
keys that are `set` — which is exactly the set that will emit disclosure
events, and exactly the set the modal lists. Three things that must not drift,
derived from one place. A single-decision (0-window) window matches it
byte-exact against the ceremony's pinned `operation_binding`.

**The protected destination is a ceremony, not a boolean.** #50 gave a copy
into a protected environment an explicit `confirm_protected` field — right for a
machine principal, which the ADR says gets "an explicit field in the immutable
plan… never an interactive prompt". For a human that field alone would let the
UI *delete* the protection by hardcoding `true`. So `authorizeDestination` now
consumes a window over the **destination** when it is protected, on the secret
leg only (a config-only copy enumerates nothing to decide over). Protected ⇒
effective window 0 ⇒ the only thing that satisfies it is a single-decision
passkey ceremony bound to exactly `(destination, keys)`.

It is consumed **in the preflight and nowhere else**: a protected window
authorises one decision, so a second consumption on the write path would be a
double-spend. Preflight placement also preserves the ordering property the
source gate already has — a refusal lands before any source ciphertext is
opened.

The hole this closes is worth stating, because it is invisible from the happy
path: without it, revealing anything in development opened a five-minute
sliding window, and a publish into protected production consulted *that* window,
found it live, and ran with **no ceremony at all**. Regression fixture:
`TestCopySourceTakesTheCeremony*` asserts the copy is refused under a live
*source*-only window and succeeds after the destination's own ceremony; the
browser flow asserts the same shape end to end
(`a live source window does not stand in for the protected destination`).

**Two endpoints that were waiting on this ticket.**

- `POST /api/v1/auth/reauth/totp` — `Auth.ReauthTOTP` had no HTTP route because
  there was no disclosure for a TOTP window to gate. `ErrReauthWindowClosed`
  maps to **409**, not 401: at a 0 effective window it is the *environment's*
  state refusing the factor, and answering 401 would tell a human their code
  was wrong and send them to re-enrol an authenticator that was never the
  problem.
- `GET .../environments/{environment}/reveal-window` (`internal/server/reveal.go`,
  `service.Reveal`) — the guard's state: effective window, protected flag,
  `totp_offered`, and whether a window is live with its expiry. Its formula is
  **`read` alone** and it is `auditedNone`: the browser must know whether the
  next disclosure will prompt and with which factor *before* it holds any
  disclosure, and the answer is project settings plus the caller's own session
  state — never material.

**Write-only editing is capability-driven, not display state.** The guard
carries `can_reveal` — whether this principal satisfies `read ∧ reveal` here —
computed through `authz.HoldsFormula`, which reads the same grant table through
the same predicate `Authorize()` uses but mints no proof and no denial event.
It is an AFFORDANCE, never a decision: the chokepoint still judges every
disclosure. It exists because `edit` without `reveal` is a supported grant shape
the permission model refuses to reject, so the editor has to say "replace
without seeing the current value" to someone who genuinely cannot read it.
Deriving that from whether a cell happens to be revealed on screen would make
the microcopy a function of what the human last clicked.

**The ceremony refusals classify as `forbidden` (403).** They are decided after
`authorize()` has already succeeded, so they disclose nothing beyond the
caller's own capability — which they can read off their own grants — and they
must not be 500s: a missing ceremony is a routine, actionable state, not a
fault. They are deliberately **not** distinguishable from one another on the
wire (absent, lapsed, spent, wrong unit): the client's correct move is the same
in every case, and the error enum is closed.

**No new `ErrorCode`.** The enum is documented "closed set — never grows", so
there is no `reauthentication_required` on the wire. This is not a gap, it is
the locked design read correctly: the window gates the prompt, so the *client*
asks the guard first and prompts accordingly. A refusal from a disclosure route
is a plain uniform refusal and the surface treats it as "remask and say so",
never as "re-prompt" — which is also the honest handling of the case that
actually produces it, a grant revoked under an open window.

## Findings from the adversarial review (R1), and what they changed

Eight, all verified against the code before being fixed. Four are security
properties that were claimed but not enforced; they are worth stating because
each was invisible from the happy path.

1. **A protected destination could be satisfied by a caller-supplied boolean.**
   The ceremony hung on the SECRET leg, so a config-only copy into a protected
   environment went through on `confirm_protected: true` alone — a value the UI
   supplies, which means the UI could delete the guard by sending a constant.
   The decision is now made ONCE per destination, over **every** key the copy
   names (`config` included, because that is what the human is agreeing to
   deliver), and the flag is the machine plan field the ADR always meant it to
   be. `withDestination` no longer decides protection at all; the write path
   re-decides nothing, which is safe because the project row is locked for the
   whole transaction.
2. **Consumption read a captured clock.** `Copy` took `time.Now()` before the
   destination locks and preflight, then judged every later gate against it —
   so a window that lapsed while the transaction waited on a lock would still
   be spent. The clock is now read inside `requireCeremony`, at the moment of
   consumption, and it is `Auth.now()` rather than the wall clock so a fixture
   can move it.
3. **"Purpose-bound" was only in the modal.** The signed binding was
   `(environment, sorted key ids)`, so an assertion the human gave to
   `reveal · production` was spendable on `publish into · production` over the
   same keys — the same unit, a different decision. `ReauthPurpose` (a closed
   set: reveal, copy, publish, mint) is now part of the canonical binding the
   authenticator signs, the binding stored with the ceremony, and the tuple
   consumption matches byte-exact. No migration: the binding was already an
   opaque string column, so widening what it contains changes both sides at
   once. Sliding windows are deliberately not purpose-scoped — a sliding window
   authorizes a PERIOD by design, which is the ADR's model; only the
   single-decision window is a decision, and only it matches a binding.
4. **The TOTP route was a protected-environment oracle.** It inspected the
   environment's reauthentication policy with no tenant authorization at all,
   so a signed-in principal could tell a protected environment (409) from an
   unreachable or nonexistent one (401) by presenting nonsense. It now resolves
   the chain from the environment id and requires `read(E)` before it will
   discuss policy, and the policy check moved ahead of the caller's factor
   lookup so a `0`-window environment answers the same whether or not the
   caller has an authenticator enrolled.
5. **`HoldsFormula` was broader than its safety claim** — any principal id, and
   grants only. It is now `CallerHolds`, takes the resolved `Identity`, and
   applies the same MFA-mandatory floor the chokepoint does, so a password-only
   session is never told it may reveal while authorization is about to refuse.
6. **Delete-then-insert is not a supersede under concurrency.** Two tabs
   finishing ceremonies at once can both miss the other's not-yet-visible row on
   postgres, and the loser's insert then hits the unique constraint — an
   intermittent failure of exactly the passkey-per-disclosure flow the
   supersede exists for. It is one `ON CONFLICT … DO UPDATE` statement now, on
   both engines.
7. **Revealed plaintext survived environment navigation.** React Router reuses
   the surface when only route parameters change, and `disclosed` was keyed by
   key NAME — so development's `DB_PASSWORD` could render in production's row
   inside the remask window. State is cleared on the org/project/environment
   tuple changing, and disclosures are keyed by `(environment, key id)`.
8. **Four tests did not prove their property**: a zero-window TOTP assertion
   that passed on `nil`, "sliding" tests that never advanced past the original
   expiry, a machine test using `LocalPrincipal` (the local-authority path,
   exempt for a different reason) instead of a minted bearer credential, and a
   write-only browser test that fired a mutation and never read it back. Each is
   now an exact sentinel, an injected clock beyond the original expiry (plus a
   hard-cap refusal), a real minted credential, and an awaited write followed by
   an authorized readback.

### R2: what the second round found

Four of the eight were confirmed fixed. Five items came back, and two of them
were defects rather than weak tests:

- **The clipboard ceremony signed the wrong operation.** It displayed and
  signed `copy`, then took the REVEAL route — so in a protected environment the
  binding never matched and clipboard copy failed every time with
  `ErrReauthUnitMismatch`. Sliding environments concealed it completely,
  because a sliding window is deliberately not purpose-scoped. The honest
  reading is the ADR's own: clipboard copy *is* a reveal ("gated and audited
  exactly like reveal — including copy without display"), same route, same
  audit surface, so it SIGNS `reveal`. What the human is told and what the
  assertion commits to are now two things: `CeremonyPurpose` carries the
  sentence (`copy to clipboard · production`) and `SIGNED_OPERATION` maps it to
  the route it takes. `copy` remains the source leg of moving material into
  another environment, which is a different route and a different decision.
  Regression: the protected-environment flow now copies to the clipboard
  through a passkey ceremony and asserts the server-side disclosure row —
  reverting the map to `copy` fails it.
- **The passkey reauth route kept the oracle the TOTP route lost.**
  `ReauthPasskeyStart` accepted any environment id, and `finish` derives the
  window's shape from that environment's policy, so an authenticated principal
  could distinguish unreachable from missing and protected from open by
  starting ceremonies. The authorization now sits in `beginAccountCeremony`,
  the one place both reauth legs pass through, and applies whenever a ceremony
  names an environment (enrol and step-up name none). Test:
  `TestThePasskeyRouteIsNotAnEnvironmentOracle*`, which also asserts a refused
  start writes no ceremony row — an oracle in durable form is still an oracle.

The three weak tests were rewritten to fail against the implementations they
were supposed to exclude:

- **Expiry during a copy** now uses a clock that lapses *mid-flight*: valid on
  its first read, expired afterwards, with a protected destination so the copy
  consumes two windows. An implementation capturing the clock at copy entry
  reads it once and never notices; the test also asserts the read count, so
  both halves have to hold.
- **The sliding proof** now outlives the ORIGINAL expiry: a five-minute window
  opened at T0, disclosures at T0+4m (which slides it to T0+9m) and T0+7m —
  past what the ceremony alone bought, so a fixed window fails.
- **Concurrent supersede** is now two barrier-synced goroutines opening a
  window for the same `(session, environment)` in separate transactions,
  asserting no unique violation and exactly one fresh row. On sqlite the store
  serialises writers, so that leg proves the statement; postgres is where the
  arbitration actually happens.

One consequence worth knowing: the reauth routes now require `read(E)`, so
every fixture that reauthenticates needs it. It is granted at INSTANCE scope in
the bootstrap helpers — org scope would put org A in every bootstrap
administrator's rail and break the fixtures that assert an instance-scoped
principal sees no organisations.

## The bug this ticket found: one window *ever* per (session, environment)

`reauth_windows` carries `UNIQUE (session_id, environment_id)`, and
`InsertReauthWindow` was a bare INSERT. That turned "at most one window per
pair" into "**one window ever** per pair", which breaks the ADR's headline
case: a protected environment is capped at 0, so its disclosures are *a passkey
ceremony per disclosure* — ceremony, disclose, ceremony again — and the second
ceremony collided with the first window's spent row.

Fixed at the shared writer, not at a caller: a new
`DeleteReauthWindowForSession` query (both engines) runs inside
`store/authn.CreateReauthWindow`, in the caller's transaction, so a fresh
ceremony **supersedes** the pair's window. The uniqueness invariant is
unchanged; a concurrent disclosure sees the old window or the new one, never
neither. It is also the honest behaviour for a sliding window: someone who
reauthenticates mid-window has just proved possession again, so the window
restarts rather than refuses. A DELETE rather than an upsert because the two
engines' upsert dialects differ and a window id is bound to nothing outside
that table.

Covered by `TestZeroWindowForcesAPasskeyPerDisclosure{SQLite,Postgres}`, which
fails without it.

## The TOTP success path is exercised, not only its refusals

Every ceremony fixture drives the modal with a passkey, and every TOTP
assertion in the suite was a REFUSAL — so a code path that opened a window
nothing could spend would have shipped green. Two fixtures close that:
`TestTOTPOpensARevealWindow{SQLite,Postgres}` presents a real code on a
non-protected environment, discloses through the window it opened, and
discloses again without a second ceremony; and the browser flow answers a
non-protected ceremony with the code form and asserts the sliding countdown
that follows.

## What landed — web

`src/routes/Values.tsx` (the surface), `src/routes/Ceremony.tsx` (the modal),
`src/api/values.ts` (Zod-parsed client + the WebAuthn legs). Surface `values`
is registered in `app/navigation.ts` with `section: null` — it addresses one
environment of one project, so it is reached by deep link, never from a static
sidebar entry that could not know which environment to mean.

The decided set from the prototype, and where each lives:

| Locked decision | Where |
|---|---|
| Purpose-bound modal, enumerated key set, disclosure-vs-step-up distinction | `Ceremony.tsx` |
| Sliding window with visible countdown chip | `windowChip` in `Values.tsx`, fed by the reveal-window route |
| Protected ⇒ window 0 ⇒ passkey only, TOTP option **absent** (not disabled) | `Ceremony.tsx`, gated on `totp_offered` |
| Short auto-remask with visible countdown | `REMASK_MS`, derived from a deadline rather than a per-cell timer |
| Clipboard = audited disclosure incl. copy-without-display; non-secret copy free | `doCopy` / `writeClipboard` |
| Honest clipboard microcopy, verbatim | `writeClipboard` |
| Row editor, empty field = unchanged, no per-row clear | `RowEditor` |
| Write-only replacement placeholders where reveal is missing | `RowEditor`'s `writeOnly`, driven by the guard's `can_reveal` — changes the *placeholder*, never the capability |
| Publish/copy-into-protected run the SAME enumerated-key ceremony | `doPublishInto` — **two** decisions, source then destination |
| One audit line per disclosed key, never "revealed N secrets" | `noteDisclosure` |
| No `confirm()` anywhere | asserted: the flow fails if a native dialog fires |

Two implementation notes worth not re-deriving:

- **A copy asks twice, and that is the honest shape.** `withCeremony` takes a
  LIST of targets — every environment the act needs authority over, in the order
  the server judges them. A reveal names one; a publish names the source it
  discloses from and the destination it delivers into. Each target that is not
  already covered by a live sliding window gets its own decision, and the act
  runs only once every one of them is. A live window on one environment is not
  authority over another, which is exactly what a protected cap exists to say.
- **The modal is a native `<dialog>` opened with `showModal()`.** That is the
  whole accessibility story, not a starting point: the platform supplies a real
  focus trap (Tab cannot leave), inert content behind it, Escape and the top
  layer. A ceremony a keyboard user can Tab out of while it is "modal" is one
  they can answer without seeing what they are answering about. `role="dialog"`
  and `aria-modal` are left implicit — the element already exposes both, and a
  restated role is one more thing that can drift from what the element is.

  One consequence reached into the shared fixture: `interactiveElements` now
  scopes to an open modal when there is one. An inert element is not an
  interactive element — focusing it is impossible by design — so asserting a
  focus ring on the page behind a modal fails for a reason that is the platform
  working correctly.
- **The modal title names the environment, not its id** (`reveal · production`).
  The purpose-bound title is the modal's headline feature, and an opaque id
  would defeat it; the name is resolved from the environment list the surface
  already loads, falling back to the id only until that resolves.
- **Remasking is derived from a deadline, not scheduled.** A tab backgrounded
  past the deadline comes back masked; a `setTimeout` per cell does not
  guarantee that.
- **The live region is the audit `<ul>`, not each `<li>`.** An explicit role on
  an `li` *replaces* its implicit `listitem` role, which would leave the list
  with no items as far as assistive technology is concerned. This was caught by
  the flow, not by review.

## What landed — the flow, and four things the harness had to learn

`e2e/flows/reveal.spec.ts` (registered as flow `reveal`, surface `values`),
`e2e/fixtures/seed.ts`, and a substantially rewritten `e2e/fixtures/instance.ts`.

The fixture tenant is seeded through the **real API** with a real session — a
value is a sealed envelope bound to its own row, so a fixture that inserted
bytes would produce cells nothing can open. Break-glass grants (`hikyo admin
grant`) supply the value authority, because the bootstrap administrator holds
`operator` at instance scope and deliberately **no** disclosure capability.

Four constraints the product imposed on the harness. Each looked like
flakiness and was not:

1. **`HOST` is `localhost`, not `127.0.0.1`.** A WebAuthn relying-party id must
   be a registrable domain; an IP literal is not one, so a passkey ceremony
   against a loopback *address* is refused by the browser before the server
   sees it. `--dev` derives the external origin from the listen address, so the
   two move together.
2. **Grants at INSTANCE scope, not org scope.** `listMyOrgs` projects the orgs
   a caller's own grants *name*, so org-scoped grants would put the fixture org
   in the bootstrap admin's rail and silently delete the shell flow's
   zero-organisation state — a locked surface state with nothing to do with
   this ticket. Instance scope reaches the same environments by ordinary
   downward inheritance.
3. **The passkey is enrolled exactly once, in global setup, and its signature
   counter is persisted between Playwright projects.** Enrolment is an
   account-security mutation: it advances the principal's session generation
   and deletes every other session that principal holds, so a flow that
   enrolled would invalidate the shared storage state the rest of the suite
   runs on. And a counter that goes backwards is how a *cloned* authenticator
   is detected — a fresh authenticator per project replays a stale counter, the
   server disables the credential, and every later test fails for a reason that
   has nothing to do with the ceremony.
4. **Global setup must stay SHORT.** The instance is a child of the setup
   process and does not survive a setup that sits waiting for minutes — which
   is what a fixture presenting one TOTP code per time step turns into. The
   seeding therefore does its two MFA-mandatory acts (create the org, grant
   `reveal`) on ONE stepped-up session, does everything else on a plain one,
   and only ever waits when the step it needs is outside the server's ±1 skew.
   A stale instance holding the port is now named explicitly at boot rather
   than surfacing later as an inexplicable 401.
5. **Three pieces of shared account state travel through the fixture file**,
   because global setup and the workers are separate processes sharing ONE
   account: the passkey's signature counter, the newest spent TOTP step (every
   code is single-use per `(account, step)`, so the seeding session, the desktop
   project and the mobile project cannot each pick "one step ahead of now"), and
   the instance's sqlite path — which is how a flow asserts SERVER-side audit
   truth rather than the UI's belief about it, through stdlib `node:sqlite`.
6. **One context for the ceremony file, a fresh session per test.** One
   authenticator so the counter only ever goes up (as a real key's does); a
   fresh session because a reauthentication window is a property of the
   *session*, and carrying one over would mean the next test's first disclosure
   quietly skipped the ceremony it exists to assert. Cookies are cleared first:
   the context is shared, and a *live* cookie makes the login itself a
   cookie-authenticated POST, which the server refuses without the synchronizer
   token.

`reveal` is granted through the **API** while the other six capabilities are
break-glass. The grant surface releases only the origins it owns, so a
break-glass `reveal` could not be revoked over the network — and the write-only
flow needs to take it away and give it back, this product having no
second-account path (`admin create` mints the FIRST administrator and refuses a
second). That flow restores the grant and re-mints the shared session in its
teardown, because revoking advances the principal's generation and kills every
session they hold.

The seeding TOTP is RFC 6238 computed in ~15 lines of `node:crypto`. It is
fixture-grade and deliberately so: the product's own TOTP lives in
`internal/crypto/totp.go` and is not reachable from Node, there is no TypeScript
equivalent in this repo to reuse, and a dependency for a dozen lines is a
dependency to audit and pin forever. It is checked against the RFC's own
vectors and authenticates nothing in production. Every fixture response crosses
a Zod schema before anything reads it, as the SPA's own client does. Two subtleties are
commented at the call sites: a base32 accumulator must drop emitted bits or
JavaScript's 32-bit bitwise operators overflow after the sixth character; and
every code is single-use per `(account, step)` — enrolment's confirming code
included — so a code for the *current* step is refused as a replay.

## Deliberate boundaries

- **`reauth_window_seconds` is set per environment by the fixture, and the
  instance default stays 0.** The ADR delegates the concrete default to the
  operations spec (#77, open); 0 is fail-closed and this ticket does not invent
  a value. Consequence worth knowing: out of the box every environment takes a
  ceremony per disclosure until someone configures a window.
- **"Publish into protected" is a copy into a protected destination**, because
  #51 (revisions & publish) has not landed and there is no publish to gate. The
  ceremony, the enumerated unit and the component are the ones #51 will reuse;
  only the verb behind them changes.
- **Copy-into-protected is browser-only for humans**, as reveal-in-protected
  already was: a protected environment admits only a WebAuthn ceremony, and a
  CLI session cannot run one. A machine principal is unaffected — it never
  reauthenticates and keeps the explicit `confirm_protected` plan field the ADR
  gives it.
- **The row editor is one key in one environment**, not one key across all
  environments. The cross-environment row editor is #57's matrix surface, which
  this surface's components are built to be lifted into.
- Diff-reveal is gated in the service but has no UI here; the history drawer
  and restore are #59's.

## Verification

| Check | Result |
|---|---|
| `go vet ./...` | clean |
| `go test ./...` (sqlite) | 1179 passed, 34 packages |
| `go test` isolation + conformance + store + server with `HIKYO_TEST_POSTGRES_DSN` set | 1237 passed, 11 packages |
| The ceremony fixtures, both engines | 30/30 pass |
| `pnpm --dir web typecheck` | clean |
| `pnpm --dir web test` (vitest) | 20 passed |
| `pnpm --dir web exec playwright test` (unfiltered, both projects) | 64 passed; global teardown's run-log check clean |

The Postgres leg needs `HIKYO_TEST_POSTGRES_DSN` pointing at any reachable
Postgres; it is unset by default and the isolation harness fails loudly rather
than skipping when `CI` is set.
