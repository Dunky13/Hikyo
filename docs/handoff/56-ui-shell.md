# Handoff: #56 UI shell — embedded SPA, app-chrome skeleton, Playwright flow registry

Parent #41. Binds the system-architecture ADR § Frontend (embedded serving
rules), the ui-spec, root `DESIGN.md`, mvp-boundary row S3, and the frozen
`prototype/app-chrome/` iteration 15 (+ sidebar treatment e from iteration 18).

## What landed

**Embedded serving (`internal/server/spa.go`, `internal/webui/`).** The ADR's
rules are implemented and asserted: reserved prefixes (`/api/`, `/metrics`,
`/healthz`, `/readyz`, `/assets/`) never fall back to the document; a missing
hashed asset 404s as a build error; hashed assets `immutable`, `index.html`
`no-cache`; the v1 security baseline (CSP self-only, no inline script,
`frame-ancestors 'none'`, `nosniff`, referrer policy) on every response.
Root-only base path.

Two rules are narrower than they look and are stated so nobody widens them by
accident:

- **Fallback needs an explicit `text/html` (or `text/*`) range with a positive
  q-value.** `Accept: text/html;q=0, application/json` is a client refusing
  HTML, and `*/*` — what `fetch` and curl send — is not a navigation. Handing
  either a document is how a mistyped API call fails at `JSON.parse` twenty
  frames from the mistake instead of at its status code.
  A weight is validated against RFC 9110 §12.4.2's grammar exactly (0..1, at
  most three decimals). An ABSENT q means 1, which is the RFC's default; a
  PRESENT but malformed or out-of-range one (`q=2`, `q=.5`, `q=0.5000`,
  `q=abc`) means the range does **not** qualify. That last part is a decision,
  not a reading: the RFC gives no default for a malformed weight, and a client
  that sent one has told us something is wrong with it — serving a document on
  the strength of a guess is exactly what this predicate exists to avoid.
- **Only ROOT files are served by name.** `fs.ValidPath` accepts
  `some/dir/file`, so a build that later emits a sourcemap or manifest into a
  subdirectory would become publicly readable without anyone deciding that.
  Hashed assets have their own reserved prefix; everything else the browser
  fetches by name sits at the root.

`server.New` now takes an `fs.FS`. Nil means an API-only binary, which is what
a plain `go build` produces — the embed sits behind the `ui` build tag in
`internal/webui`, so `go build ./...` and `go test ./...` stay green for
someone who has never run pnpm. `go build -tags ui` embeds
`internal/webui/dist`, which `pnpm --dir web build` writes.

**Browser session + CSRF (`internal/server/browser.go`, `internal/service/auth.go`).**
`localLogin` gained an optional `artifact` member (`cli` default, `browser`).
A browser login mints a `br` artifact with the browser clocks and a CSRF
verifier, delivered as `__Host-hikyo` (HttpOnly) plus `__Host-hikyo-csrf`
(readable), and never in the body. The transport requires `X-Hikyo-CSRF` on any
non-safe method that authenticated on the cookie leg, verifies it against the
session row's verifier (`Auth.VerifyBrowserCSRF`) and then against the
companion cookie in constant time. A bearer caller has no cookie leg and
therefore no CSRF contract (#54 A10). Every existing browser-session mint
(OIDC callback, passkey login/enrol/step-up/reauth) now emits the CSRF cookie
alongside the session cookie; logout clears both.

**"Authenticated on the cookie leg" means the cookie resolves to a LIVE
session, not that a cookie is present.** An expired or revoked browser session
leaves its cookie in the browser and the human's next act is to sign in again —
a POST that carries the dead cookie. Keying on presence refuses that login 401
before the handler and locks the account out of its own login page. So
`VerifyBrowserCSRF` answers with two distinguishable errors:
`domain.ErrUnauthenticated` (no live session — not a cookie leg, let the
request through and let the chokepoint judge it) and `service.ErrCSRFMismatch`
(live session, wrong or absent token — the refusal the gate exists for). Both
are the same uniform 401 on the wire. Regression fixtures:
`TestAStaleSessionCookieDoesNotBlockANewLogin`,
`TestAStaleSessionCookieLeavesTheRefusalToTheChokepoint`.

Session artifact kinds are a type, not a bare string: `service.Artifact` with
`ArtifactCLI`/`ArtifactBrowser`, `Valid()`, and the three things that differ
between them (`idle()`, `absolute()`, `bearerKind()`) hanging off it, so the
closed set carries its own rules instead of a validating switch and three
parallel `if artifact == …` ladders.

**Every reissue preserves the ACTING artifact.** TOTP enrol-confirm, TOTP
remove, TOTP step-up, recovery-code regeneration, identity link and identity
unlink all reissue or rotate the acting session, and all of them hard-coded
`ArtifactCLI`. Before #56 that was invisible; with a browser artifact in play
it meant a browser that enrolled a factor was simultaneously **logged out**
(its cookie now pointed at a rotated verifier) and handed a **long-lived CLI
token in a script-readable body**. Each site now reads the artifact off the
session it re-authenticates inside its own write transaction — `completeLink`
gained that re-authentication, which it was missing anyway — and the transport
delivers on the matching channel through one `sessionResponse`
(`internal/server/browser.go`): cookies for a browser result, body token for a
CLI one, never both. Step-up rotates in place and leaves `csrf_verifier`
untouched, so it re-delivers only the session cookie; clearing a still-valid
synchronizer token would break the very next mutation. Covered at both levels:
`TestEveryReissuingOperationDeliversOnTheActingChannel` (transport, five
operations × browser/CLI), `TestAccountSecurityMutationsPreserveTheBrowserArtifact*`
(datastore, both engines: TOTP enrol/step-up/remove and recovery regeneration)
and `TestBrowserFederationPreservesTheArtifact*` (datastore, both engines:
OIDC `completeLink` and unlink). The federation legs exist separately because
the pre-existing OIDC lifecycle tests drive link and unlink with a CLI
session, so a regression there would otherwise be invisible.

**SPA (`web/`).** React 19 + TypeScript + Vite, pnpm, strict TS; no `as` type
assertions anywhere (the `as const` uses are literal narrowing, not casts).
Consumes the generated `clients/ts` client and Zod schemas through Vite/tsconfig
aliases (`@hikyo/client`, `@hikyo/zod`, `@hikyo/runtime`); every response with a
body is `schema.parse`d at the boundary — including login, whose body is
contract-bearing even though the session itself arrives on cookies. `ok()` is
restricted to bodyless 204s and throws if it ever sees a body, so "the caller
did not need it" cannot become "nobody checked it". Login failures are mapped
honestly: **only** a 401 is a credential refusal; 429 is a throttle; a 500, a
network outage or a schema violation says so, because presenting those as
"wrong password" sends the human to reset a credential that was never the
problem and hides a server regression behind the one message nobody
investigates (`loginFailureText`, unit-tested). TanStack Query for server state. Login page
(local password only), app-chrome skeleton — org rail, sidebar sections with
the locked treatment-e geometry, breadcrumb, account entry, theme control —
dual theme dark-default via CSS alone, mobile-first collapse below 800px.

**Flow registry (`web/e2e/registry.ts`).** Closure has three legs, because a
declaration is not a check:

1. **The router is generated from the table.** `src/app/navigation.ts` is the
   closed surface list; `App.tsx` holds a `Record<SurfaceId, ReactElement>`, so
   a surface without an element does not compile and an element without a
   surface cannot exist, and the routes are a `.map` over the table. A unit
   test reads `App.tsx` and refuses any `path=` that is neither the catch-all
   nor reads `.path` off a Surface record — so `path={someVariable}` is caught
   as well as `path="/x"`.
2. **The declarative check** rejects a surface with no flow, a flow naming an
   unknown surface, a missing spec file, or a flow covering nothing.
3. **The execution check** rejects a claim nothing ran. `surfacesForFlow(id)`
   is what a flow ITERATES — the shell flow's matrix is derived, not re-listed,
   so claiming a fourth surface is the same act as asserting it — and the
   pinned-set fixture appends `flow⇥surface⇥theme` to a run log that global
   teardown compares against every claim. A surface that was claimed and never
   reached fails the run with a non-zero exit even when every test passed. The
   check is skipped under `--grep` and only there: a filtered run is
   deliberately partial, and failing it would make the gate something people
   work around. CI runs unfiltered.

Each flow runs the pinned set on **every surface it claims**, in both themes; the registry maps flows to surfaces and the closure check fails
on a surface with no flow, a flow naming an unknown surface, a missing spec
file, or a flow covering nothing. Four negative fixtures in
`e2e/registry.test.ts` prove the check can fail. It runs in `pnpm test` and
again at Playwright global setup, before a browser starts.

**Pinned assertion set (`web/e2e/fixtures/assertions.ts`).** One entry point,
`expectPinnedAssertionSet`, so a new flow cannot pick up half of it:

- axe serious/critical = 0;
- state announced by text + ARIA, asserted under `forced-colors`;
- **a visible** focus indicator, ≥ 4.5:1 contrast and the 44px touch floor over
  **every visible interactive element the page offers** — discovered from the
  native-focusable set (including `summary`, editable regions and media
  controls) rather than listed by the flow author, so coverage is structural
  and a new control is asserted the day it renders. (It found one immediately:
  the skip link was a 39px target on a phone.)
  "Visible" is asserted, not assumed: `outline: 2px solid transparent` and a
  ring the same colour as what it sits on both satisfy "the computed style
  changed", so the ring's colour is sampled, required to be opaque, and
  required to clear WCAG 2.2's 3:1 non-text contrast against the surface
  behind it — then re-checked under `forced-colors`, where an author-coloured
  ring disappears and the user who most needs it is looking;
- contrast and palette sampled through a 1×1 canvas, because the palette is
  OKLCH and `getComputedStyle` cannot be parsed as RGB;
- DESIGN.md conformance the flow declares by name: radius roles, typefaces,
  **palette tokens** (`--tx`, `--tx-dim`, `--bg-raise`, `--line`, `--accent`,
  `--on-accent`) in both themes where a flow exercises them, 1px hairlines, and
  density against `--touch`/`--row`;
- a sweep that fails any stray 999px pill.

Focus needs one non-obvious step: Chrome only matches `:focus-visible` on a
scripted focus when the last interaction was a key press, so the fixture
presses Tab first. Without it the assertion measures the wrong state.

## Decisions worth not re-deriving

1. **CSRF delivery is a cookie, not `whoami` — recorded deviation from #54's
   A9 line.** The verifier is a one-way SHA-256, so `whoami` could only deliver
   a token by minting a new one: a write on a GET, and a token a second tab's
   boot silently invalidates. `__Host-hikyo-csrf` reaches the same origin under
   the same restrictions, survives a reload, needs no write, and is still a
   true synchronizer token because the row verifier settles it. **The ADR's A9
   wording is owed an amendment** (wayfinder-docs; the implementer cannot commit
   there).
2. **`web/` is a standalone pnpm package, not a workspace member.** A root
   `pnpm-workspace.yaml` relocates the lockfile and breaks the `client` job's
   frozen-lockfile install. The generated client is consumed as source through
   aliases instead.
3. **Vite output goes to `internal/webui/dist`, gitignored.** `go:embed` cannot
   traverse `..`, and a committed minified bundle is unreviewable and ships
   stale silently.
4. **Chromium only, two viewport projects.** `forced-colors` emulation and
   axe's colour sampling are reliable there; cross-browser rendering is a
   different question from accessibility and token conformance.
5. **The flow suite reuses one session.** `admission.PerIPPerMinute` is 10, so
   a suite that drove the login form per test would measure the throttle.
   Global setup mints a browser session over HTTP (same endpoint, same
   `artifact: browser` request) into a Playwright storage state; the login flow
   and the sign-out flow still authenticate for real.

   **Correction to an earlier note in this document: cross-run 429 is
   impossible.** `admission.Limiter` keeps `ipHits` in a plain in-memory map
   built at boot, and the harness spawns a fresh binary in a fresh temp
   directory per run and kills it at teardown — no throttle state survives a
   run. The risk was only ever within a single run, where a full suite spent
   about 7 of the 10 allowed attempts.

   That headroom is now bought properly rather than by rationing tests:
   `HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE` raises the per-source allowance, the
   harness sets it to 500 on the server it spawns, and the key is fail-closed
   twice — a non-`--dev` process **refuses to start** when it is set at all,
   and a malformed or non-positive value is an error rather than a silent
   fallback to the default. The precedent for a configurable admission value is
   `HIKYO_ADMISSION_BUDGET_MIB`, already in `knownEnv`; the ADR routes admission
   values to the ops spec. The alternative was deleting or merging flow tests to
   fit under a security constant, which is measuring the throttle instead of the
   UI.
6. **`exactOptionalPropertyTypes` is off** in `web/tsconfig.json`: the
   generated hey-api client does not satisfy it, and `clients/ts` does not set
   it either.
7. **`extractBearer`'s dual-presentation refusal is left alone.** A request
   carrying both `Authorization: Bearer` and a session cookie is refused 401
   before anything resolves — #54 A10, deliberately, because accepting both
   would let a caller choose which CSRF contract applies. Making it tolerate a
   DEAD cookie beside a live bearer would mean resolving the cookie in
   middleware on every request, which is the pre-chokepoint authorization read
   the architecture forbids. The stale-cookie case converges instead: the next
   successful login overwrites both cookies, and browser session cookies do not
   survive the browser anyway.

## The navigation surface: `GET /api/v1/me/orgs`

The rail cannot be built on `listOrgs`. That operation is `ClassInstance` with
`Formula{instance-config@none}`, and `instance-config` is MFA-mandatory — it is
the *operator's* enumeration of every organisation on the instance, and putting
it behind a sidebar meant a password-only session saw an empty rail with a "you
need a second factor" notice. That notice was the UI apologising for asking the
wrong question.

`listMyOrgs` asks the right one: **the organisations the caller's own grants
name**, at org scope or below. Decisions, each argued rather than assumed:

- **No new authz registry operation, deliberately.** The registry's `opSpec`
  offers `events` or `auditedNone`, and `auditedNone` is default-deny —
  permitted only for tenant-class, bare-`read`, non-mutating operations. This
  addresses no tenant object, so it is not tenant-class; and there is no
  capability to require, because *holding a grant is the predicate* and
  demanding one would be circular. It is a resolution-surface read, exactly
  like `GET /auth/identities` ("the caller's own linked identities"), and it is
  classified the same way: `ClassUnauthenticated` in the wire registry, no
  `x-wenv-operation`/`x-wenv-formula` pair. **The registry entry that was not
  created is itself the decision** — recorded here so the next reader does not
  re-derive it.
- **Not audited, pinned as a reviewed deviation** in
  `testdata/audited_exemptions.json` beside `whoami` and the identity list. The
  audit model's default-deny governs registry operations; this is not one. Its
  subjects are already recorded when grants are created or revoked, and its
  result set can contain nothing the caller does not already hold — so an event
  would record "a principal looked at their own sidebar" once per page load,
  which no investigation could act on.
- **A grant BELOW org depth still names its org.** `covers()` in
  `authorize.go` only matches downward, so a project- or env-scoped grant does
  *not* satisfy `read@org` — filtering the rail through `org.get` would have
  emptied it for exactly the persona the permission ADR says drives the
  product. The projection reads the grant rows directly instead.
- **An instance-scoped principal gets an EMPTY list, and that is correct.**
  Instance scope inherits downward, so expanding it here would silently
  reproduce `listOrgs` on a surface without its gate. The bootstrap
  administrator is in this state (the admin template expands at instance scope
  and `org.create` seeds its creator nothing), so the rail's zero state —
  prototype iteration 14, text + ARIA, no step-up wall — is what a fresh
  instance shows. The Playwright shell flow asserts exactly that; the datastore
  e2e (`TestListMineProjectsOnlyTheCallersOwnOrgs*`,
  `TestListMineNeedsNoSecondFactor*`, both engines) carries member-sees-own-org,
  cross-org-invisible, depth-below-org, and MFA-not-required.
- **Identity only.** `MyOrg` is `{id, name}`. `metadata` and `active` are
  operator-set state read through `getOrg`, which authorizes; returning them to
  a member who could not call `getOrg` would be a genuine over-disclosure.
- Store side: no new grants query — `ListGrantsForPrincipal` already exists and
  is already pinned, so the annotated-query fixture is untouched. One new
  `GetOrgIdentity` on `orgs`, which needs no annotation because `orgs` is
  `class=org chain=id` and `WHERE id` is that chain as a top-level conjunct.

## Release wiring

`.goreleaser.yaml`'s build carries `-tags=ui`, so a released binary serves the
SPA. Both pipelines that invoke GoReleaser build the frontend first —
`release.yml`'s `build-unsigned-draft` and `ci.yml`'s `supply-chain-fixtures`
(which runs the snapshot) each gain Node from `.nvmrc`, `corepack enable`, and
`pnpm --dir web install --frozen-lockfile && pnpm --dir web build` before the
GoReleaser step. `Dockerfile.release` needs no change: it copies the binary,
and the binary carries the assets. `packageManager` is pinned in both
`web/package.json` and `clients/ts/package.json` so corepack resolves the same
pnpm the lockfiles were written by.

## Deferred, by name

- **TanStack Virtual is installed and unused.** The ticket names it as wired-in
  for the matrix; the skeleton has no list long enough to justify virtualising,
  and forcing it would be theatre.
- **OIDC / passkey / TOTP / recovery UI.** #54 shipped the endpoints; each
  surface is its own ticket.
- **Multi-org rail interaction.** The rail renders and marks the active org but
  switching is not wired: there is no second org to switch to until org
  creation has a surface.

## Running it

```bash
pnpm --dir web install --frozen-lockfile
pnpm --dir web typecheck        # strict TS over src/ and e2e/
pnpm --dir web test             # vitest: registry closure + its negative fixtures
pnpm --dir web build            # -> internal/webui/dist
go build ./... && go test ./... # untagged: no UI needed
go build -tags ui ./...         # embeds the bundle
pnpm --dir web exec playwright install chromium
pnpm --dir web e2e              # boots a real --dev instance, desktop + mobile
```

CI runs exactly that order in the `web` job.

---

## Files created / modified (this run)

Created:
- `internal/server/spa.go`, `internal/server/spa_test.go`
- `internal/server/browser.go`, `internal/server/browser_test.go`
- `internal/webui/webui.go`, `internal/webui/absent.go`, `internal/webui/embedded.go`
- `internal/isolation/browser_session_e2e_test.go`
- `web/**`
- `docs/handoff/56-ui-shell.md`

Modified (highlights):
- `api/openapi.yaml` — optional `artifact` on LocalLoginRequest; `GET /api/v1/me/orgs`
  (`listMyOrgs`) + `MyOrg`/`MyOrgList`; regenerated Go + TS clients
- `internal/authz/` — `Identity.CSRFVerifier`; `TxAuthorizer.OrgsForPrincipal`;
  wire classification for the new route
- `internal/store/authn/` — `csrf_verifier` read-back; `OrgsForPrincipal`,
  `GetOrgIdentity`
- `internal/service/` — `type Artifact`; `VerifyBrowserCSRF` + `ErrCSRFMismatch`;
  artifact-preserving reissue on every account-security mutation; `Orgs.ListMine`
- `internal/server/` — `New(…, fs.FS)`, security headers, SPA leg, CSRF gate,
  shared cookie-bearing responses, `ListMyOrgs`
- `internal/admission/`, `internal/config/`, `internal/app/` —
  `PerIPPerMinute` override, dev-gated fail-closed
- `internal/isolation/testdata/{annotated_queries,audited_exemptions}.json` —
  reviewed pins
- `.github/workflows/{ci,release}.yml`, `.goreleaser.yaml` — frontend build
  before GoReleaser, `-tags=ui`
- `.gitignore`, `clients/ts/package.json` (`packageManager`)

Campsite fixes: `SlideIdleClock` slid a BROWSER session by the CLI idle window;
the skip link was a 39px touch
target on a phone; `completeLink` reissued a session without re-authenticating
the acting one.
