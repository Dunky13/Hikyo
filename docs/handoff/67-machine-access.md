# Handoff: #67 Machine access UI

Parent #41. Binds the frozen prototype `prototype/machine-access/` —
**iteration 3, locked** (Marc, 2026-08-05, ticket #31: tabbed inventory, row
expansion leading with credentials and bindings, journey full-width **below**)
— plus [machine-identities.md](https://github.com/Hikyo-Org/hikyo/blob/wayfinder-docs/docs/adr/machine-identities.md)
(#17), the Compose (#18) and Kubernetes (#19) ADRs, and mvp-boundary row **S3**
(`machine access: all three tabs + row expansion + display-once mint`, desktop
and mobile, pinned assertion set).

Blockers #56 (UI shell) and #62 (OIDC federation + conditional-fetch cursor)
were merged before this landed.

## What shipped

**A project surface at `/orgs/:org/projects/:project/machine-access`**, added to
the router's own surface table (`web/src/app/navigation.ts`) — the closed flow
registry reads that table, so the route could not exist without a flow.
`section: null` for the same reason `values` is: it addresses ONE project and a
static sidebar entry cannot know which. The project-scoped navigation the
prototype draws around it is the shell's ticket, not this one.

- **Tabbed inventory** — Service accounts / Federation / Kubernetes targets,
  with a live count in each tab label.
- **Policy strip** above the table: the per-project machine-reveal opt-in,
  **stated, not offered** (see gaps).
- **Write-only credential rows**: prefix hint, kind, expiry in words, last used
  — never a value. There is no route that returns one after the mint, so there
  is nothing the row could render.
- **Row expansion**: credentials and federated bindings on the left, delivery
  targets and the three actions on the right, the five-step setup journey
  full-width underneath — iteration 3's resolution exactly.
- **Display-once mint**: a step-up naming the post-state formula and the
  environments it ranges over, then the value **exactly once**, with a
  stored-confirmation checkbox gating dismissal — including Escape, which must
  not be a way to lose a value nothing can return. Rotation is the same flow
  with the "the prior value is never returned, the predecessor keeps working
  until you revoke it" sentence added.
- **Grant-mutation warning**: names the live-credential count (the server's own
  `live_credentials`, which applies revocation, the credential epoch and
  expiry — a client filtering on `revoked_at` would count credentials that
  stopped authenticating weeks ago), states the formula, and enumerates exactly
  what becomes reachable. It is **fail-closed**: until the key catalogue has
  actually loaded, the grant button stays disabled and says why, because
  "nothing becomes reachable" is the one answer a pending or failed read does
  not have and the one that makes the grant look harmless. The catalogue comes
  from `listKeys`, not `listValues`, on purpose (PR review, aikido): a value
  listing is authorized for the human reading it and carries **config
  plaintext** this dialog never renders, and a fetch is a copy the query cache
  keeps — `listKeys` answers the only question asked (name, classification)
  with no value member anywhere in its schema.
- **Federation form**: three presets carrying the per-platform pin rules the
  server enforces at creation (Kubernetes' `/kubernetes.io/serviceaccount/uid`,
  Forgejo's `repository` + `event_name`, GitHub Actions' `repository_id` +
  `repository_owner_id` + `event_name`), a **binding lifetime** (instance
  default / 30 / 90 days, with `indefinite` present-and-disabled naming the
  instance opt-in that admits it — renewal is a mint, never an edit), a
  mandatory audience refused before the request rather than as a 400, and the
  **pull-request refusal**: pinning `pull_request` or `pull_request_target`
  raises a `role="alert"` refusal and is held back until a deliberate
  acknowledgement is ticked. Submission runs the same reauthentication leg as
  the credential mint (PR review, aikido): a binding **is** a mint (#62), so
  one passkey ceremony per post-state environment precedes
  `createFederatedBinding` — vacuous today exactly like the mint's, but the
  form will not start failing with a bare 403 when the reveal opt-in lands.
- **Every write on this surface is commit-aware, not just the mint** (PR
  review, aikido round 2). Binding and grant submissions track the same
  `issued` line the mint draws: an in-flight write blocks Escape, Back and
  unload (`useNavigationGuard(busy)` + the dialog cancel gate), and a failure
  after the request left refreshes the rows / scope column and says the act
  *may still have landed* (`bindingFailureText` / `grantFailureText`) rather
  than reporting "nothing happened" over a committed external login path or a
  committed widening.
- **Typed claim pins are parsed, not coerced.** A numeric pin takes digits only,
  non-empty, inside the range JSON carries exactly. `Number()` would turn an
  empty field into repository id **0**, accept `1e3` and `4242.7`, and round
  anything past 2^53 to a *neighbouring* repository id — each of which binds a
  production service account to a repository nobody chose, while looking like it
  worked.
- **Restore quarantine**: a binding carrying `reactivated_at` renders the
  permanent iat-floor refusal in words. It is real state, not a simulation.

## Three properties of the mint that are not obvious from the screen

1. **The plaintext exists in exactly one place.** The mint is deliberately NOT a
   `useMutation`: TanStack keeps a mutation's result in a global cache until
   garbage collection, so a mint run through it would leave the credential
   reachable from the query client long after the dialog closed — a second copy
   of a value whose whole contract is that there is one. It is a plain async
   call, and only `MintDialog`'s own state holds the result.
2. **The response is parsed down to what may be kept.** `zMintCredentialResult`
   is `.pick`ed to `{ value, clamped }` rather than parsed whole, so a drift in
   the nested credential metadata cannot throw away the one member nothing can
   ever return again. The row metadata is re-read from the listing instead.
3. **A mint that was ISSUED and then failed is reported as such.** Once the
   request leaves, a failure says nothing about whether the server committed —
   so that path invalidates the credential list and says *a credential may still
   have been minted; check the rows and revoke anything you did not expect*,
   rather than the guess ("the mint failed") that leaves a live credential
   nobody is looking for. And **dismissal is refused entirely while the mint is
   in flight**: Escape reaches a native `<dialog>` even when Cancel is disabled,
   and unmounting mid-flight loses a committed value as thoroughly as never
   minting it (`dismissDecision`, unit-tested, plus a flow test that delays the
   real mint and presses Escape). Navigation gets the same treatment
   (`useNavigationGuard`): `beforeunload` guards reload/close while a mint is
   in flight or a value is unstored, and a history sentinel turns the Back
   button into a dismissal attempt routed through the same gate — the route
   never pops out from under the dialog (flow test: Back mid-flight and Back
   with the value on screen).

## The one backend change, and why it is here

**`listMachineCredentials` dropped every binding member.** The wire schema has
always said an `oidc-federation` row "carries the binding members instead" of a
prefix hint; the generated Zod schema has `issuer`, `subject`, `audience`,
`required_claims` and `reactivated_at`; the store layer already returned all of
them on `MachineCredential.Binding`; and `server.wireCredential` rendered none.
Since a binding **is** a credential row and is listed only through that route
(#62's own decision), an operator could see that a binding existed and not
which external identity it admitted — and the quarantine field was invisible
for the same reason.

That is a server failing its published contract rather than a feature that does
not exist yet, so it is fixed here rather than worked around. **The change is
read-path only and three files:**

- `internal/service/identities.go` — `CredentialView` gains the binding
  members; `ListCredentials` populates them for `oidc-federation` rows,
  resolving the byte-exact issuer STRING once per distinct configuration (not
  once per row) via `az.FederationIssuerByID`, and decoding the pins through
  the existing `DecodeClaimPins`.
- `internal/server/identities.go` — `wireCredential` renders them, reusing
  `wireClaimPins`. All zero for a bearer credential, so `optional` renders them
  absent. The mint path goes through the same function with zero values and is
  unchanged.
- `internal/isolation/federation_e2e_test.go` —
  `TestFederationBindingIsListedWithItsIdentity{SQLite,Postgres}` pins it in
  both directions through the SERVICE: a listed binding carries
  issuer/subject/audience byte-exact plus its `event_name` pin and no prefix
  hint, and a bearer row on the same account carries no binding members at all.
- `internal/server/identities_wire_test.go` — and the same two directions
  through the RENDER, which is where the defect actually was: a service-level
  test passes with the wire still empty. It asserts the pins' scalar **values**
  (not merely their presence — `event_name` is the whole CI rule) and that the
  discriminated scalar is not folded, that `reactivated_at` round-trips, and
  that a bearer row renders every binding member *absent* rather than as an
  empty string, which a client cannot tell from "unset".

Nothing on the authentication or verifier path was touched. **Flagged for the
reviewer as its own item**: it is separable from the UI work and revertible on
its own, at the cost of the Federation tab.

A second, smaller backend change followed from the first during PR review
(aikido): now that the credential listing carries the issuer string byte-exact
to project-level `manage-identities`, an issuer configured as
`https://user:secret@host` would disclose those embedded credentials on a
lower-privileged surface. `checkIssuerRequest`
(`internal/service/federation.go`) therefore enforces the OIDC issuer grammar
at creation — https, a host, and no userinfo, query or fragment — refused
before a row exists, because byte-exact matching forbids sanitising later.
Pinned by `TestFederationIssuerGrammarRefusesNonIssuerURLs`.

## What a `read` grant actually reaches — the decision behind the warning

Read off `internal/service/delivery.go` (`deliveryRows`) and the `fetchDelivery`
contract rather than assumed. A machine holding `read` on an environment gets
**the whole key catalogue for that environment** — every key's name, its
classification and its declared presence rule — and **no value of any
classification, config included**: `DeliveredKey` has no value member at all.

So the grant warning enumerates *every* key with its classification, not only
`classification === 'secret' && set`. The narrower filter would have understated
the blast radius twice over: it hid the config keys, and it hid the secret keys
that are declared but unset — whose presence state is itself delivered, and
whose names are exactly what an attacker with a stolen credential would want.

## Gaps: where the prototype is ahead of the server

Each of these renders the state that exists and says what is missing. None of
them mocks a data path.

| Prototype surface | Server today | What ships |
|---|---|---|
| Per-project machine-reveal opt-in, as a toggle with a ceremony both ways | No opt-in exists. #55's machine allowlist admits `read` and **nothing else** on a workload principal (`internal/domain/permission.go`), so `reveal` on a machine is refused by the grant API | A `role="status"` policy strip stating the opt-in is off in this build and why. A toggle would be a control whose only outcome is a refusal; the repo's own precedent is the ceremony's TOTP cap — absent with the reason given, never disabled. **Ships with #17/#18.** |
| Journey step 5, "Grant `reveal`" | Same refusal | Step renders `not in this build`, naming the allowlist. No button. |
| Journey step 3's verbatim delivery refusal (`hikyo run` / `UndeliverableKeys`) | Delivery never refuses: it delivers config and secret **presence**, with no plaintext path at all (`fetchDelivery`) | Step 3 says delivery succeeds as configuration and secret presence. **Rendering the refusal would fabricate a state the server does not produce.** |
| Kubernetes delivery targets and the four CR conditions in both voices | No operator (#64), no target state, no condition rows | Empty state saying nothing is reporting and that an empty list here is **not** "everything is healthy". The condition vocabulary is deliberately NOT rendered as a static reference: it is documentation with no data source and would drift the day #64 lands. |
| Restore reconciliation: recovery banner, per-SA re-activation, no bulk-accept | No recovery-mode signal and no per-SA re-activation route. `Federation.Reactivate` exists as the write #76's ceremony will call, and `reactivated_at` is on the wire | The quarantine badge and its permanent-floor sentence render from the real field. The banner and the re-activation ceremony are **not** built. |
| Scenario simulator (normal / expiring / post-restore) | — | Not built. It is a prototype affordance for showing states, not a product surface. |
| Mint step-up's passkey leg | Reachable, but never exercised: the disclosure conjunct ranges over environments the account can decrypt, and no machine can hold `reveal` today, so the post-state reach is always empty and the server asks for no reauthentication (ratified, #61 handoff item 5) | The code path is there and correct — one `reauthPasskeyStart({operation: 'mint', …})` per reachable environment, mirroring `RequireDisclosureAuthority` — but it cannot be exercised end to end until the opt-in lands. The panel says in words that the conjunct is vacuous rather than performing a ceremony that authorises nothing. **Covered by a unit test (`postStateReach`), not by the flow.** |
| Grant-mutation step-up's passkey leg | Same, one level along: `checkMachineWidening` gates a grant on the same conjunct, but over the **delta** rather than the whole post-state — and a `read` grant on a principal that cannot hold `reveal` widens nothing | Same treatment as the mint's, deliberately: the dialog states the formula, runs one ceremony per newly-decryptable environment, and says *this grant newly decrypts nothing, so the disclosure conjunct is vacuous* when — as today — the delta is empty. The delta is computed by `grantWideningReach`, which is unit-tested against the non-vacuous case the server will one day produce. |

**Partial reads are not rendered as zeroes.** Every act on this surface is
gated on all four of its inputs — accounts, grants, environments and
credentials — having actually loaded: each dialog's warning is an assertion
about that state, and a query that failed answers "how many credentials does
this re-scope" with a confident 0. A failed listing therefore shows the tab
count as `—` rather than `(0)`, the scope column as `unknown` rather than
`no environment`, and holds the mint, bind and grant actions back with the
reason stated.

Also noted, not a gap in this ticket: the shell's breadcrumb resolves a
parameterised path to "Not found" (pre-existing; `values` has it too), and the
teardown's `--grep` escape hatch does not actually trigger for a CLI `--grep` in
the pinned Playwright version, so a filtered run still fails the execution
check. Neither was touched — `e2e/global-teardown.ts` is #56's locked harness.

## Files

| File | |
|---|---|
| `web/src/api/identities.ts` | new — Zod-parsed hooks plus every derivation as a pure function |
| `web/src/api/identities.test.ts` | new — unit tests over those derivations, including the three whose failure modes are invisible on screen: `parseClaimNumber`, `grantWideningReach` and `dismissDecision` |
| `web/src/routes/MachineAccess.tsx` | new — the surface and its three native `<dialog>` ceremonies |
| `web/src/app/navigation.ts`, `web/src/app/App.tsx` | the surface entry and its element |
| `web/src/api/values.ts` | `PasskeyCeremonyInput.operation` widened with `mint` (the contract already has it) |
| `web/src/styles/app.css` | tabs, inventory, expansion, journey, binding card, token box, checkbox |
| `web/e2e/registry.ts`, `web/e2e/registry.test.ts` | the flow, and the closure test's counts derived rather than restated |
| `web/e2e/fixtures/seed.ts`, `web/e2e/fixtures/instance.ts` | the machine fixture |
| `web/e2e/flows/machine-access.spec.ts` | new — 10 tests × 2 viewport projects |
| `internal/service/identities.go`, `internal/server/identities.go` | the contract-conformance fix above |
| `internal/isolation/federation_e2e_test.go`, `internal/server/identities_wire_test.go` | its two tests, at the service and at the render |

## Endpoints each surface consumes

| Surface | Route |
|---|---|
| Inventory rows | `listServiceAccounts` (`manage-identities@project`) |
| Read scope column, journey, grant dialog's grantable set | `listProjectGrants` (`manage-members@project` — a **separate** authority; its absence renders an honest "no scope is shown", not a blank column) |
| Environment names | `listEnvironments` |
| Credential rows, binding cards, tab counts | `listMachineCredentials`, one query per account |
| Display-once mint | `reauthPasskeyStart`/`finish` with `operation: mint`, per reachable environment, then `mintMachineCredential` |
| Revoke | `revokeMachineCredential` |
| Federated binding | `createFederatedBinding` |
| Environment grant | `createEnvGrant` |
| Grant warning's newly-reachable key set | `listValues` for the chosen environment (presence only — the surface never asks for plaintext) |

## The e2e fixture

`seedTenant` now also creates, **inside the stepped-up TOTP session** (because
`instance-config` and `manage-members` are MFA-mandatory and the `reveal` grant
at the end kills that session):

- a federation issuer, `kubernetes` type, static JWKS, with the API server's own
  audience in `refused_audiences`;
- three service accounts — `web-api` (workload, `read` on development, one
  federated binding), `nightly-export` (automation, no journey), `batch-worker`
  (workload, no grants, the one the mint tests mint on);
- `manage-identities` added to the break-glass grant list.

The binding's service account reaches no plaintext, so its own mint formula's
disclosure conjunct is vacuous and seeding needs no reauthentication.

**Each minting test revokes what it minted.** The instance caps live
credentials per account at five and this file mints three times per viewport
project; without the revoke the sixth mint is refused by the cap and reads as a
broken mint rather than as a test that littered.

## How to verify

```bash
pnpm --dir web typecheck
pnpm --dir web test                     # 37 unit tests, incl. the closed-registry checks
pnpm --dir web build                    # the flows run against the EMBEDDED bundle
pnpm --dir web e2e                      # unfiltered: a filtered run fails the execution check
go build ./... && go vet ./...
go test ./internal/service/... ./internal/server/... ./internal/isolation/ ./internal/conformance/
```

Last run on this branch: `pnpm e2e` **84 passed** across both viewport
projects with the registry's execution check satisfied; `vitest` 48 passed;
`go build`/`go vet` clean and 722 passed across `internal/server` and
`internal/isolation` (sqlite only — set `HIKYO_TEST_POSTGRES_DSN` for the
Postgres leg of `TestFederationBindingIsListedWithItsIdentityPostgres`, which
has never executed here).
