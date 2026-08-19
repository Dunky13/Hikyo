# Handoff: #60 chrome surfaces — members, settings, account & security, instance administration

Parent #41. Binds mvp-boundary row S3 (the chrome clause), the permission ADR
(#55), the retention API (#53), the human-auth endpoints (#54), the UI shell
and flow registry (#56), root `DESIGN.md`, and the frozen prototype
`prototype/app-chrome/` iteration 15 (+ the retention panels from iteration 16
and the sidebar treatment from 18).

Base implementation: **Claude Opus 5** via the Agent tool (the ticket's label says
Opus 4.8; the tool's `opus` resolves to Opus 5 — recorded, not chosen). Fix
rounds: **GPT-5.6-sol via `codex exec`** (three parallel passes, an integration
pass, and an R2 pass). Orchestration and final verification: Claude Fable 5.

## What landed

Four new locked surfaces, one rewritten one, and four new Playwright flows.

| Surface | Path | Flow |
|---|---|---|
| `members` | `/orgs/:org/members` | `members` |
| `org-settings` | `/orgs/:org/settings` | `chrome-settings` |
| `project-settings` | `/orgs/:org/projects/:project/settings` | `chrome-settings` |
| `instance-admin` | `/instance` | `instance-admin` |
| `settings` (rewritten) | `/settings` — now **Account & security** | `account` |

**Members & grants** (`web/src/routes/Members.tsx`, `web/src/api/access.ts`).
The membership listing grouped one row per (principal, scope) with each
capability still its own line, its **origin chips** and its own one-click
revoke; a "who can…?" inspection that counts grants ABOVE the scope asked
about; and the NEW GRANT modal — capability checklist with the permission
ADR's own "Covers" wording behind a `(?)` toggle per atom, a role-template
shortcut that calls `applyTemplate` (server-side expansion), a scope select
ordered narrow→wide, and the **org-scope blast warning** enumerating the
checked capabilities and every project × environment in the organisation plus
the "any project created later" line, with *back, change scope* preserving the
composition. Post-action feedback is persistent `role=status` text.

**Org settings** (`web/src/routes/OrgSettings.tsx`): identity (rename, plus the
stated consequence that renaming is instance-operator work), the org retention
cap in the API's real two dimensions, a members entry card, and a danger zone
whose delete is gated on the typed organisation name, inline.

**Project settings** (`web/src/routes/ProjectSettings.tsx`): identity (rename),
per-environment policy (protected flag + reveal reauthentication window, with
the window fixed at 0 and *stated* while protected), the project retention
override with the cap refusal named per dimension before the request, an access
entry card, and the typed-name delete.

**Account & security** (`web/src/routes/AccountSecurity.tsx`,
`web/src/api/account.ts`): profile, sign-in factors (passkey list, enrol and
remove; TOTP enrol start/confirm/remove), recovery codes (regenerate with the
display-once presentation behind an acknowledgement), **active sessions —
absorbed from #71's standalone `Sessions.tsx`, which is deleted**, linked
identities (list, authenticated link redirect, unlink, and an honest successful-empty
"no provider configured" state), and
preferences (theme). One `ProofDialog` asks for the pre-existing credential, so
"a new credential never authorises its own enrolment" is stated once.

**Instance administration** (`web/src/routes/InstanceAdmin.tsx`): organisations
(list + create + link into each one's settings, where deletion lives), instance
grants with visible origin subjects plus create/template/revoke, credential-policy
read/edit, honestly separated retention-health states, and the change-token-key
rotation behind a warned-consequence dialog. The SystemProof local set is
stated as absent rather than drawn as disabled controls.

**Chrome** (`web/src/routes/Shell.tsx`, `web/src/app/navigation.ts`): org-scoped
sidebar entries are generated from the active organisation and are ABSENT while
there is none; the rail switches organisation and carries the address with it;
the breadcrumb's organisation is derived from the ROUTE when the route names
one.

## Decisions worth not re-deriving

1. **One members surface for the whole organisation, not one per depth.**
   `listOrgGrants` answers org-, project- AND environment-scoped lines in one
   read, and #55 deliberately shipped no `grant.list-env` because "who can
   reach this environment" must include the lines above it. A per-project
   members page would therefore either re-ask the same question or ask a
   narrower one while looking complete. Project settings' Access panel links
   here; there is exactly one permission editor.
2. **The grant modal posts one create per checked capability, sequentially, and
   stops at the first refusal.** Each create advances the target's session
   generation in its own transaction and the writers serialize on the target's
   principal row anyway, so concurrency would buy nothing; stopping and
   reporting how far it got is the same honest partial-failure shape #55 gave
   `access member remove`.
3. **The scope select's default is the first CONFIRMED-unprotected environment
   named `staging` (case-insensitive), otherwise the first confirmed-unprotected
   environment, and empty when there is none.** `getEnvironmentSettings` is
   `read@environment`, which a member manager need not hold — so protection is
   a tri-state (`true` / `false` / unreadable), and an unreadable flag is never
   treated as "fine". When nothing qualifies, nothing is preselected and the
   human chooses explicitly. The staging preference is intentionally
   hard-coded by name; it is not inferred from display order. Unit-tested in
   `web/src/api/access.test.ts`.
4. **The server is authoritative for retention-cap refusal, and its detail is
   safe to show.** `validateProjectRetention` returns `invalidDetail`, whose
   `SafeDetail` is extracted by `writeHandlerError`; `errorBody` honours that
   detail for `bad_request`, and the SPA's `parsed()` keeps it on `ApiError`.
   The project editor therefore validates only input shape (positive exact
   integers), sends the requested bounds, and renders the server's named cap
   detail. It does not duplicate the cap rule client-side.
5. **A 403 on a grant route is read as the second-factor refusal.** Not a
   guess: `isolation.TestTenantRoutesDeclareForbiddenOnlyForMFA` pins that a
   tenant route declares 403 iff its formula is MFA-mandatory, and
   `manage-members` is. A 404 stays the uniform nonexistent shape and the copy
   says so rather than inventing the oracle the server closed.
6. **The org rail's two-organisation state is stubbed in the flow; everything
   behind it is real.** The fixture creates a SECOND real organisation, and the
   rail test intercepts `GET /api/v1/me/orgs` to return both. The projection
   itself is #56's operation, proven on both engines by
   `isolation.TestListMineProjectsOnlyTheCallersOwnOrgs*`,
   `TestListMineNeedsNoSecondFactor*` and their siblings; what #60 owns is the
   INTERACTION (a circle changes the active organisation, the breadcrumb and
   the org-scoped destinations), and both organisations behind the switch load
   real data from the real server. The alternative — granting the bootstrap
   administrator into an organisation — would delete the shell flow's locked
   zero-organisation state for the whole suite, because `listMyOrgs` projects
   the organisations a caller's grants NAME and every fixture grant is
   instance-scoped precisely to keep that state reachable. Precedent for
   intercepting a read to reach a presentational state: the shell flow's own
   retention-health tests.
7. **`settings` moved from the shell flow to the account flow.** A surface with
   six panels is not a navigation destination the chrome flow can cover in
   passing. `shell.spec.ts`'s deep-link test now loads `/projects`.
8. **Every destructive drill happens to objects the flow creates.** The seeded
   tenant is the reveal, matrix and machine-access flows' subject; a settings
   drill that flipped production's protected flag would break three flows from
   a cause several files away. The settings flow creates a throwaway
   organisation and a throwaway project (named per Playwright project, so a run
   that dies halfway cannot collide with the next viewport's) and the members
   flow revokes what it granted in a `finally`.
9. **The account flow enrols and removes one additional passkey near the end.**
   The virtual authenticator preserves the shared credential; the new passkey
   is asserted in the list and removed through the UI. Because each factor
   mutation advances the session generation, `refreshSharedSession()` restores
   the suite before the recovery-code test, which remains last. Full TOTP
   enrolment is not repeated on the already-enrolled administrator.
10. **`browser.newContext()` inherits the describe's `storageState`.** The
    password-only instance-admin test therefore creates its context with an
    explicitly empty jar: a live session cookie on a login POST is refused 401
    by the CSRF gate before the handler, which looks exactly like a wrong
    password. (`machine-access.spec.ts` clears cookies for the same reason;
    this is the same trap one level along.)

## Prototype affordances flagged and skipped, with the reason

Each of these is in the frozen prototype and is NOT built, because no operation
on this branch backs it. None is stubbed.

- **Invite member.** There is no invitation anywhere in the contract: no table,
  no claim flow, no delivery channel, no expiry. #55 cut it explicitly (scope
  cut 1, disposition item 1) and it is still open. The members surface says so
  in a comment beside where the button would be; the UI shows nothing.
- **`definitions_source: db | git`** on project settings. The source-of-truth
  ADR fixes the switch and the read-only consequence, but no column, service or
  endpoint for it exists on this branch — it belongs to mvp-boundary S4. The
  Policy panel states its absence rather than offering a select that could not
  persist: a guard that appears set and is not is worse than a missing one.
- **Project metadata** (description). The `Project` contract carries id, org,
  name and creation time. Nothing to write, nothing to write it with.
- **Organisation and project avatars** — preset hues, the custom-hue slider,
  glyphs, image upload. No operation stores any of them. `Org.metadata` exists
  but is only settable at create, and freighting a display preference into
  operator metadata would be inventing a schema.
- **Profile editing** (display name, email). No update-principal operation
  exists. The fields are rendered as read-only facts.
- **Password change** (the prototype's Profile "change password" control). There
  is no self-service credential-change operation: a credential is established
  once through the bootstrap/reset authority (`establishCredential`), and the
  only re-issue path is an administrator's `resetCredential`. The panel states
  how a reset happens instead of drawing a control that could not persist.
- **TOTP enrolment STATE.** There is no read for "does a code factor stand".
  The panel says so and offers the acts; a second enrolment is refused by the
  server with a named 400 rather than hidden behind a button that guessed.
- **Passkey-only sign-in toggle** and **notification preferences**. No backing
  state or operation; the passwordless floor is enforced server-side at removal
  time, and the ADR's own answer on security alerts is that they are not
  disableable.
- **Instance settings: server URL / RP id and audit retention.** No operation
  exists for those fields. The machine-credential ceiling is built from the
  existing `getCredentialPolicy` / `setCredentialPolicy` operations, including
  affected-credential preview and confirmation.
- **Master-key rotation and re-encryption controls.** Local host authority by
  ADR — `rotateTokenKey` is the only key operation with a network surface, and
  it is bound.
- **The undo toast** on grant and revoke. Replaced by persistent inline
  `role=status` feedback: an eight-second toast is a message a screen-reader
  user can miss and a keyboard user cannot return to, and there is no undo
  behind it — a revoke is a real revocation and re-granting is an ordinary
  audited grant.

Deferred by name, not skipped in passing: **SCIM binding administration and
mapping authoring**, **OIDC and SAML provider configuration**, and the SCIM
**deprovision attention flag**. #73 and #62 shipped no web UI and neither
deferred one to this ticket; the ui-spec assigns provider configuration to "the
existing instance-config surface", which is a surface-sized piece of work per
provider family and is not in S3's chrome clause. The one SCIM UI obligation
that IS in this clause — origin chips per capability line on grant views — is
built. Also out by the ticket's own boundary: connected instances (#71
Remotes, shipped), the history drawer (#59), secret-scanning presentation
(#74), and key-rotation operations beyond `rotateTokenKey` (#75).

Previously omitted contract-backed work is now explicit: linked identities start
`linkIdentity` from the authenticated account proof dialog; instance grants can
be created, templated, and revoked; and project settings expose the per-project
retention read/write surface. None starts from a login-purpose provider flow.

## Human dispositions

- A full successful TOTP enrolment flow needs a second human principal created
  through SCIM plus credential reset. The sole administrator already owns a
  confirmed TOTP factor, so only the already-enrolled refusal is exercised.
- `linkIdentity` is built but not exercised end-to-end because the harness
  configures no identity provider; #62 covers the server-side operation.
- The seeded instance-directory grant's `manual` origin is #71's pre-existing
  fixture and remains unchanged.
- Desktop controls below 44px (`.btn--quiet`, `.explain__toggle`) are
  deliberate. S3 pins the 44px floor on the MOBILE viewport and the pinned set
  asserts it there; desktop density follows DESIGN.md's `--row` token.

## Campsite fixes

- **`e2e/fixtures/instance.ts` wrote a grant id the contract forbids.** The
  `instance-directory` seam inserted `grn_e2e_directory` / `gor_e2e_directory`
  directly into sqlite. The contract's `ID` grammar is
  `^[a-z]{2,8}_[0-9a-fA-F-]{36}$`, and the SPA parses every response against
  the generated schema — so the instance grant listing failed to parse in full,
  loudly and correctly, the moment a surface listed it. The fixture now writes
  conforming ids. Nothing in the product changed; the product was right.
- **The fixture's synchronizer-token read was not scoped to an origin.**
  `browserApi` (new in this ticket) read `context.cookies()` unfiltered, and
  the shared jar carries BOTH instances' cookies (#71 runs two). Picking the
  serving instance's `__Host-hikyo-csrf` produced a 401 from the CSRF gate that
  looked exactly like a dead session — and only sometimes, because it depended
  on jar order. It now reads `context.cookies(BASE_URL)`. Worth knowing before
  writing the next fixture helper that talks to the API from a page.
- **A nested scroll container inside `.ceremony`** made the grant modal's
  checklist unclickable on a phone: `.ceremony` is a scrolling flex column, and
  a second scroller inside one shrinks its siblings into each other while every
  visibility check still passes. The inner `max-height`/`overflow` is gone and
  the dialog scrolls as a whole.

## Files created / modified

Created:
- `web/src/api/access.ts`, `web/src/api/access.test.ts`
- `web/src/api/settings.ts`, `web/src/api/settings.test.ts`
- `web/src/api/account.ts`, `web/src/api/account.test.ts`
- `web/src/routes/Members.tsx`, `OrgSettings.tsx`, `ProjectSettings.tsx`,
  `AccountSecurity.tsx`, `InstanceAdmin.tsx`, `Sections.tsx`,
  `useModalDialog.ts`
- `web/e2e/flows/members.spec.ts`, `settings.spec.ts`, `account.spec.ts`,
  `instance-admin.spec.ts`
- `internal/domain/capability_fixture_test.go`,
  `internal/domain/testdata/capabilities.json`
- `docs/handoff/60-chrome-surfaces.md`

Deleted:
- `web/src/routes/Sessions.tsx` (absorbed into the account surface)

Modified:
- `web/src/app/navigation.ts` — four surfaces, the `settings` label, `needsOrg`
- `web/src/app/App.tsx` — the new elements
- `web/src/routes/Shell.tsx` — org-resolved sidebar entries, rail switching,
  route-derived breadcrumb organisation
- `web/src/routes/Projects.tsx` — a per-project settings entry
- `web/src/routes/MachineAccess.tsx` — shared modal-dialog hook
- `web/src/api/identities.ts`, `web/src/api/matrix.ts` — shared parsed helpers
- `web/src/api/values.ts` — the base64url helpers are exported and shared
- `web/src/styles/app.css` — the chrome-surface components
- `web/e2e/registry.ts`, `web/e2e/registry.test.ts` — four flows, the moved
  `settings` claim
- `web/e2e/global-teardown.ts` — unfiltered run-log closure
- `web/e2e/flows/login.spec.ts`, `reveal.spec.ts`, `shell.spec.ts` — dual-theme
  closure, cast-free fixture narrowing, and the deep link moved to `/projects`
- `web/e2e/fixtures/seed.ts` — a second organisation, exported org names
- `web/e2e/fixtures/instance.ts` — `browserApi`, conforming fixture grant ids,
  the widened seed schema, and session/passkey lifecycle repair
- `internal/server/oidc.go`, `internal/server/contract_test.go` — empty account
  collections encode as contract-valid arrays

No `api/openapi.yaml`, generated client, or dependency changed. The domain Go
additions pin the capability fixture; the server Go change preserves the
existing generated response contract for empty account collections.

## Review record

- **R1** — two-axis review (standards + spec, Claude sub-agents) plus the
  blocking cross-model review (Codex `gpt-5.6-sol`, high effort, five slices:
  api · chrome · members/settings · account/instance · e2e/handoff). Every
  slice BLOCKED; ~60 findings in total, the headline ones: discarded partial
  grant results, environment-settings tri-state collapsed to `null` (Save could
  silently unprotect), typed-name delete armed on `'' === ''`, recovery codes
  escapable before acknowledgement, "Nobody" / "none enabled" / "no
  environments" asserted while unknown, route org not persisted into the rail,
  rail test stubbing `/me/orgs`, the run-log closure ignoring theme, and four
  backed-but-skipped spec items (credential policy, link identity, per-project
  retention list, instance grant create/revoke/template).
- **Fix round** — three parallel GPT-5.6-sol passes in isolated worktrees
  (grants/members · settings/chrome · account/instance/e2e) and one
  integration pass reconciling their seams. Desktop sub-44px controls were
  rejected as a finding (S3 pins the floor on the mobile viewport).
- **R2** — the same five slices plus a spec re-check verified the fixes;
  leftovers (partial-grant rendering, day-editor discrimination, "Nobody" while
  pending, credential-policy preview snapshot, `themeOf` fallback, per-project
  closure, five missing e2e regressions, handoff corrections) went through one
  more GPT-5.6-sol pass; the rail deep-link scenario was moved onto the real
  membership test and the `/me/orgs` stub removed from the shell flow.
- **R3** — final verdict: **CLEAN** (all R2 leftovers verified fixed; no
  casts beyond `as const`; no dead exports).

## Final verification (orchestrator, this tree)

- `pnpm --dir web typecheck` clean; vitest **151/151** (12 files); web build ok.
- `go build ./...`, `go vet ./...`, `go build -tags ui ./...` ok;
  `HIKYO_TEST_POSTGRES_DSN=… go test ./...` **3075 passed, 45 packages**
  (sqlite + postgres).
- Full unfiltered Playwright: **240/240** — 120 desktop + 120 mobile — with the
  run-log closure gate green, ports 45830/45831/45832.

## Stacked on #59 (PR #173)

This branch is rebased onto `t3code/implement-ticket-4` (#59, the history
drawer) and its PR targets that branch, so GitHub shows it as a stack and
retargets it to `main` when #173 merges. Merge conflicts resolved on the
stack: `useModalDialog.ts` (both tickets extracted it — merged to #59's
signature with the optional initial-focus ref, our `useLayoutEffect` + close-on-
unmount, and `useFeedback`), `registry.ts` / `registry.test.ts` /
`global-teardown.ts` (both made the run-log closure theme-aware; ours is the
superset — project × flow × surface × theme — and the filtered-run detection
reads `process.argv` incl. `--grep-invert`), `matrix.ts` imports, `login.spec`
(the pinned set runs in both themes through one helper), and `app.css`
(#59's block first, ours appended; the duplicate `.btn--danger` keeps #59's
richer rule). #59's seed adds a second project (`ledger`: development · staging)
to the fixture org, so the members flow now selects scopes by VALUE and the
safest-default assertions expect `ledger/staging` — which is the rule working
(name-matched staging over position order), not a fixture accident.

## Running it

```bash
eval "$(fnm env)" && fnm use 24
pnpm --dir web install --frozen-lockfile
pnpm --dir clients/ts install --frozen-lockfile   # the aliases resolve to source
pnpm --dir web typecheck
pnpm --dir web test                                # vitest: registry closure + the pure logic
pnpm --dir web build
pnpm --dir web exec playwright install chromium
HIKYO_E2E_PORT=45830 HIKYO_E2E_PORT_B=45831 HIKYO_E2E_PORT_TLS=45832 \
  pnpm --dir web e2e                               # desktop + mobile, unfiltered
```

Unfiltered matters: the run-log closure gate in global teardown only fires when
the run is not filtered by `--grep`, and it is what proves each claimed surface
was actually asserted rather than merely declared.
