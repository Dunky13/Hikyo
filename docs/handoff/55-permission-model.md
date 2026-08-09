# Handoff: #55 permission model, full — grants, role templates, protected environments

Issue: https://github.com/Dunky13/wenv/issues/55 (parent #41, blocked by #48 and
#54 — both merged). Governing spec: `docs/adr/permission-model.md` on
`wayfinder-docs` (locked 2026-07-31, plus the SCIM, flat-model and
multi-instance amendments), acceptance row A2 in `docs/adr/mvp-boundary.md`.

## What exists

### Vocabulary (`internal/domain`)

- **The closed capability atom set, in full** (`domain.go`): the six environment
  atoms, the four project atoms, `manage-members`, `manage-projects`, the seven
  instance operator atoms, plus the amendment atoms `scim-provision` (SCIM
  amendment (c)) and `instance-directory` (multi-instance amendment (a)), plus
  the two atoms earlier tickets added under their own ADR amendments
  (`audit-read` from #45, `credential-reset` from #54).
  `capabilityLevels` maps each atom to the DEEPEST scope it may be granted at —
  so `manage-projects` on one environment is refused rather than stored as a row
  nothing can evaluate. `Capabilities()`/`IsCapability()`/`DeepestLevel()` are
  the closed enumeration the grant API validates against.
- **The eight role templates** (`permission.go`), verbatim from the ADR table,
  with their applicable levels. `admin` carries `manage-projects` in a separate
  `orgOnly` list so the SAME template at project scope does not create it;
  `admin` seeds `reveal` and `reveal-history` as ordinary members of its
  capability list (they become independent rows); `operator` seeds neither.
  `ExpandTemplate(t, level)` is the only place a template name exists —
  expansion happens AT GRANT TIME and what lands is grants.
- **Machine principal classes and the NORMATIVE allowlists** (`permission.go`):
  `workload`, `automation`, `provisioning-connection`, `instance-connection`.
  `MachineMayHold` is consulted by the grant API as a refusal, not documented as
  a convention.
- **Origins**: the closed `OriginKind` enumeration (manual / break-glass / scim
  / structural / lockout-retention) with `IsMintableOrigin` gating what this
  ticket's writers may produce (manual + break-glass only).

### Schema (migration `00012_permission.sql`, both dialects)

- `grant_origins (id, grant_id, kind, subject, created_at)` with
  `UNIQUE(grant_id, kind, subject)` and a **RESTRICT** FK to `grants` — deleting
  a grant row while an origin still holds it is the ADR violation, so the
  database refuses it rather than tidying it away. `subject` is the origin's
  holder identity discriminated by `kind` (granting principal for `manual`, the
  literal `local-host-authority` for `break-glass`, the binding id for
  `scim`/`structural`). It is NOT NULL so `UNIQUE` behaves identically on both
  engines — the same NULL-distinctness divergence that kept `grants` free of a
  triple UNIQUE in the first place.
- **Backfill**: every pre-existing grant row gets `manual(self)`. Unlike 00006's
  tables this is NOT a "no real rows exist" premise — a bootstrapped instance
  legitimately holds grants, and an unfilled row would be a grant no origin
  holds. The fill is the self-grant, which is what the amendment's own wording
  ("every pre-existing grant has exactly `manual(granted_by)`") implies for rows
  that had no granting principal.
- `environments.protected` (NOT NULL, DEFAULT false) and
  `environments.reauth_window_seconds` (NULLABLE). The default on `protected` is
  deliberate and differs from #48's rule for `display_order`: unprotected is the
  real initial state of every environment, so a writer that omits the column
  gets the truth. The window is nullable because NULL means "inherit the
  instance default" — a stored copy of that default would freeze it at creation
  time, and 0 is a legal window value that must never be confused with unset.
- `principals.class` (NULLABLE), backfilled to `automation` for existing machine
  rows. See Deviations for the missing CHECK constraint.

### Store (`internal/store/authn/grants.go`, `internal/store/repos.go`)

Grants live on the **enumerated resolution surface**, following the
credential-reset precedent: `authorize()` reads the grant table to mint a proof,
so a grant write cannot be gated behind one without a cycle. The authorization
gate is the ordinary chokepoint operation the service calls first. New writers
(`AddGrantOrigin`, `ReleaseGrantOrigin`, `DeleteGrantRow`) are named in
`lint.ResolutionSurfaceWriters` and each takes `LockPrincipalRow`.

`lint.CheckGrantLock`'s `grantTable` constant became `grantTables`, gaining
`grant_origins`: releasing the last origin deletes the grant row, so an origin
write is a grant write with one more step and inherits the same serialization
obligation.

The two `project-settings` columns ride the proof-carrying repository surface
(`Environments().Settings` / `SetSettings`), because `environments` is a tenant
table. The reveal guard's READ of the same columns rides the resolution surface
(`EnvironmentReauthSettings`), because it runs beside session resolution before
any operation proof exists.

### Service

- `internal/service/grants.go` — `Create`, `Revoke`, `ApplyTemplate`, `List`,
  `BreakGlassGrant`. Every refusal rule is its own sentinel so a test can assert
  WHICH rule fired.
- `internal/service/settings.go` — `ProjectSettings.GetEnvironment` /
  `SetEnvironment`, `ProtectedWindowCap`, `DefaultReauthHardCap`, and
  `effectiveWindow` — the ONE rule turning stored settings into the window the
  reveal guard enforces, shared by the writer here and the reader in
  `effectiveReauthWindow`.
- `internal/service/reauth.go` — `effectiveReauthWindow` now performs the
  per-environment read #54 left as a seam. The seam test
  (`TestReauthWindowSeamIsSingleSource`) still holds: `s.ReauthWindow` is read
  in exactly one place.
- `internal/service/bootstrap.go` — the first administrator's grants now carry
  their `manual(self)` origins.

### Registry + audit

Sixteen new operations, one per addressed depth per verb (the house pattern from
`audit.query-*` and `credential-reset.*`), plus `environment.settings-read` /
`environment.settings-update`. Nine new audit types: `grant.created`,
`grant.modified`, `grant.revoked`, `grant.template_applied`,
`grant.membership_read`, `settings.reauthentication_window_changed`,
`settings.protected_flag_changed`, `recovery.break_glass_grant` — and
`auth.effective_window_lowered` moved from the closure invariant's hard-coded
exemption list onto `environment.settings-update`, which is the caller #54 was
waiting for.

### CLI

`wenv admin grant --principal ID --capability CAP [--org/--project/--env]` —
host-local, root key required, no network route, naming its target and
capability explicitly, writing a durable recovery record. It mirrors
`wenv admin reset-credential`'s mechanism exactly (local authority through
`adminAuth`, riding the resolution surface, **no `SystemProof`**), following
#54's precedent — so invariant 11's system-site sets are untouched and
`SiteBreakGlass` stays empty.

### Wire surface — HTTP + CLI

**17 operations across 9 paths under the `access` tag**, one per addressed
depth, because the authorization formula differs per depth and the ADR forbids
"the capability for this endpoint" as a statement. Every operation carries all
five `x-wenv-*` extensions, and the formula is documented on the endpoint AND
on the verb:

| Path | Verbs | Operations / formulas |
|---|---|---|
| `/instance/grants` | GET, POST, DELETE | `grant.{list,create,revoke}-instance` = `manage-members@instance` |
| `/instance/grants/template` | POST | `grant.template-instance` = `manage-members@instance` |
| `/orgs/{org}/grants` | GET, POST, DELETE | `grant.{list,create,revoke}-org` = `manage-members@org` |
| `/orgs/{org}/grants/template` | POST | `grant.template-org` = `manage-members@org` |
| `/orgs/{org}/projects/{project}/grants` | GET, POST, DELETE | `grant.{list,create,revoke}-project` = `manage-members@project` |
| `/orgs/{org}/projects/{project}/grants/template` | POST | `grant.template-project` = `manage-members@project` |
| `…/environments/{environment}/grants` | POST, DELETE | `grant.{create,revoke}-env` = `manage-members@project` |
| `…/environments/{environment}/grants/template` | POST | `grant.template-env` = `manage-members@project` |
| `…/environments/{environment}/settings` | GET, PUT | `environment.settings-read` = `read@environment`; `environment.settings-update` = `project-settings@project` |

**The grant's scope IS the addressed path — never a body member.** A
body-supplied scope would let a caller authorized at one depth write a grant at
another: the whole formula defeated by a JSON field. `internal/server/access.go`
builds the scope from path parameters only.

**There is no `grant.list-env`.** "Who can reach this environment" must include
the org- and project-scoped grants that reach it by inheritance, which an
environment-only listing would silently omit. Listing is served at org, project
and instance scope; the CLI refuses an env-addressed `member list` by name
rather than answering a narrower question.

**Revoke is `DELETE` with `?principal=&capability=`** rather than a body on a
DELETE: the triple is an address, and query parameters are the shape every
intermediary handles the same way.

**MFA declarations**: every grant route declares 403, because `manage-members`
is in `authz.MFAMandatory`; the two settings routes do NOT, because
`project-settings` and `read` are not. The iff is asserted against the registry
by `isolation.TestTenantRoutesDeclareForbiddenOnlyForMFA`.

**CLI** (`internal/cli/access.go`): `wenv access grant list|add|remove|template`,
`wenv access member list|remove`, `wenv project-settings get|set`. Scope comes
from the ordinary per-dimension precedence (`--org`/`--project`/`--env`), and
the DEEPEST resolved dimension picks the route — `--instance-scope` is an
explicit opt-in, because "no org resolved" must never silently mean "grant it to
the whole instance". `access member remove` is a client-side loop over the
per-capability revoke (each revocation its own audited event, as the audit ADR
asks); the honest cost is that it is not atomic, and it reports how far it got —
failing in the safe direction, authority removed rather than retained.

**Mechanical chain completed**: oapi-codegen regen (v2.8.0 pin), `wireRegistry`
+ `wireRoutes` + CLI verb classification, `Verbs` list, CLI golden re-pinned
(`go test ./internal/cli -update` — the diff is 10 added help lines and nothing
else), `audited_exemptions.json` grew the two CLI-transport entries, TS client
regenerated (`pnpm run generate` + typecheck + 4/4 contract fixtures on Node 24).
No formula pin change was needed: the operations were registered in the earlier
increment and the wire slice added no formula.

## Invariant → test map

| Property | Test |
|---|---|
| A2: per-formula matrix generated FROM the registry, both engines | `isolation.TestFormulaMatrix{SQLite,Postgres}` (`formula_matrix_test.go`) |
| A2: a formula without a fixture fails CI — **negative test** | `isolation.TestMatrixPlannerRejectsUnfixtured` (synthetic registry with three unfixturable formulas) |
| A2: every proof-minting operation is covered | `isolation.TestMatrixCoversEveryProofMintingOperation` |
| A2: revocation immediate, no cache | `isolation.TestRevocationIsImmediateSQLite` |
| **The acceptance demo**: grant a template role → watch it expand into independent grants → revoke one → the session dies | `isolation.TestRevokeKillsSession{SQLite,Postgres}` (`runRevokeKillsSession`, one principal, three numbered steps) |
| A2/A3: unauthorized ≡ nonexistent for the grant surface, incl. counts | matrix deny cases assert `ErrNotFound` (tenant) / `ErrUnauthorized` (instance); `runMembershipListing` asserts a refused listing is the uniform 404, never an empty list |
| A3: structural timing control (1 query on a miss at any level) | unchanged `isolation.query_count` subtests (#44) |
| Grant-authority rules (org/instance may grant unheld; project may not) | `isolation.TestGrantAuthority{SQLite,Postgres}` |
| Dedup is the API's job; second grantor = second origin, same row | `isolation.TestGrantDedup{SQLite,Postgres}` |
| Origin release; row dies only with its last origin | `isolation.TestGrantRevokeReleasesOneOrigin{SQLite,Postgres}` |
| Lockout invariant (org + instance; project scope exempt) | `isolation.TestLockoutInvariant{SQLite,Postgres}` |
| Lockout census counts org-or-above only (a project-scope holder is not an org holder); a principal covering the org at two scopes may lose one; the revocation trail records the origin kind released | `isolation.TestLockoutCensus{SQLite,Postgres}` |
| Machine allowlists refuse (11 cases + positive control) | `isolation.TestMachineAllowlist{SQLite,Postgres}` |
| Machine SCOPE bounds: workload env-only, automation project-or-below, one project — through individual / template / break-glass | `isolation.TestMachineScopeBounds{SQLite,Postgres}` |
| Audit lifecycle matches the state transition (no event on a no-op; modified when the row survives; revoked only when it died) | `isolation.TestGrantLifecycleEvents{SQLite,Postgres}` |
| **A2 uniformity through the REAL STACK**: 13 route pairs (the whole access surface), unauthorized-EXISTING vs missing, identical bytes, no count/items | `isolation.TestAccessWireUniformity{SQLite,Postgres}` |
| A3 structural timing measured on the REAL SERVICE PATH: every miss costs the same at any depth, a denial on an existing object costs exactly one query more | `isolation.TestAccessWireQueryTrace{SQLite,Postgres}` |
| The query-observer seam has no production call site | `isolation.TestQueryObserverIsTestOnly` |
| An origin join on an already-effective grant leaves the holder's session alive (with a revoke control) | `isolation.TestOriginAddKeepsSessionAlive{SQLite,Postgres}` |
| Project listing does not read sibling projects (asserted on ROWS, not query count) | `isolation.TestProjectListingDoesNotReadSiblings{SQLite,Postgres}` |
| CLI `project-settings set` is tri-state: a window-only update retains protection | `isolation.runHierarchyDemo` (real CLI) |
| Template expansion into independent revocable rows; org-only `manage-projects`; `operator` seeds no disclosure; wrong-level refusal | `isolation.TestTemplateExpansion{SQLite,Postgres}` |
| Membership surface per capability line with origin chips | `isolation.TestMembershipListing{SQLite,Postgres}` |
| Break-glass: origin distinguishable, durable record, allowlists still bind | `isolation.TestBreakGlassGrant{SQLite,Postgres}` |
| Break-glass has no network route | `isolation.TestBreakGlassGrantHasNoNetworkRoute` |
| Protected caps the window; raising above cap refused; every change audited | `isolation.TestProtectedEnvironment{SQLite,Postgres}` |
| **Wire byte-shape**: refusal and genuine miss are the same status and the same bytes on every grant/settings route | `server.TestUniformNonexistentAtEveryLevel` (the route table grew 13 access routes — handoff 44's deferred response-layer obligation landing) |
| **Counts leak nothing**: a refused listing is the uniform 404, never a 200 carrying `count: 0` | `server.TestRefusedListingLeaksNoCount` |
| **The acceptance demo through the WIRE**: template → membership listing shows independent lines with origin chips → revoke one → session dies (exit 3) | `isolation.runAccessDemo`, driven by the real CLI over the socket inside `TestDemoFlow{SQLite,Postgres}` |
| Grant writers hold the principal-row lock (now incl. origin writers) | `lint.TestGrantLock*`, `isolation` lint invariants |
| Every registered event has a real emitter | `isolation.TestAuditCore*/every_registered_type_is_actually_emitted` via `runGrantLifecycle` |

## Deviations from the ADR letter, stated

1. **`org rename`/`delete` keep `instance-config@instance`.** The ticket asked
   for a reading, not an amendment. Per the locked ADR the closed atom set has no
   org-lifecycle capability, so #48's disposition item 4 STANDS: **an org
   administrator cannot rename or delete the org they administer, and gets the
   uniform 404.** No atom was invented. This is a standing consequence for human
   disposition (below), not a defect in this slice.
2. **Break-glass grants carry a `break-glass` origin, not `manual` — this is an
   ADR AMENDMENT MADE IN CODE, not a settled reading.** Same shape as #54's
   `issued_by='recovery'` fourth issuer: the SCIM amendment's origin
   enumeration is closed at four kinds, and this adds a fifth. It is carried to
   the human as disposition item 4, not presented as decided. The reading
   behind it:
   `manual(granted_by)` names a granting principal whose own authority was
   evaluated; break-glass is by the ADR's own words "the only authorization path
   in the system not evaluated against a grant" and has no granting principal to
   name. Recording it as manual would put a principal's name on an act no
   principal performed and would make the row indistinguishable from an ordinary
   grant on the membership surface — the exact thing an auditor looks for after
   an incident. `break-glass` is added to the closed origin enumeration.
3. **A human revoke releases EVERY origin this surface owns** (manual +
   break-glass), not only the caller's own. Rationale: an administrator revoking
   a capability expects it gone, and a surface where "revoke" sometimes leaves
   the capability held by a colleague's origin is a foot-gun on the most
   security-sensitive verb. Origins the surface does NOT own (`scim`,
   `structural`, `lockout-retention`) are skipped and the row survives; the
   event is still `grant.revoked`, carrying `origins_remaining > 0` and
   `sessions_revoked` so a reader can tell a partial release from a real
   revocation without a second event type. That is the shape #73 needs,
   implemented but not exercisable yet.
4. **Machine `reveal` / `reveal-history` are refused outright.** The ADR admits
   them only under the source-of-truth ADR's explicit per-project operator
   opt-in (`reveal`) and only where a pin requires it (`reveal-history`).
   Neither mechanism exists, so the allowlists ship the fail-closed subset and a
   machine reveal grant is refused BY NAME until #17/#58 land the opt-in.
   Widening the list without the opt-in would hand every automation credential a
   standing decryption capability.
5. **`principals.class` carries no CHECK constraint.** sqlite cannot add one to
   a table this many tables reference, and the dialects must stay structurally
   identical. The closed set is enforced in Go at the grant writer, fail-closed:
   an unclassified machine principal holds nothing (asserted by
   `unclassified_read` in the allowlist fixtures).
6. **Bootstrap's `AdminTemplate` is unchanged** — still an instance-scope
   capability list, not the ADR's org/project `admin` template (the #47
   deviation, unchanged here). It now writes origins. Reconciling bootstrap's
   grant set with the canonical template table would change what the first
   administrator holds and belongs to a decision, not a refactor.
7. **`grant.template_applied` and `grant.membership_read` are registry
   additions.** The audit catalogue's `grant` row names created/modified/revoked
   plus denials. The template event records ONE administrator performing ONE act
   (without it the trail can say ten capabilities appeared but not why); the
   read event exists because the audited-none permit covers only tenant-class
   bare-`read` operations and "who can reveal production secrets" is not one.
   Precedent: `auth.provider_read`, `settings.org_read`.
8. **`DefaultReauthHardCap = 15m` DECIDES AN OPERATIONS-SPEC FOG VALUE.** The
   permission ADR's last line lists "default reauthentication window,
   protected-environment window cap, pin quotas and expiry, grant-count bounds
   per org" as fog owned by the operations spec. The hard cap is that same
   class of value, and the code needed a non-zero one to be correct at all — so
   a number was chosen here rather than left broken. **The ops spec owns the
   number; this is disposition item 5.** What was done and why: the constant was
   introduced and the three
   `hardCap <= 0 → hardCap = effWin` fallbacks were replaced.** This closes #54's
   disposition item 1 as a code fix rather than a doc note: with both the idle
   window and the hard cap at 0, a single-decision (0-window) WebAuthn reauth was
   minted with `hard_expires_at == authenticated_at` and was dead the instant it
   was created — so a protected environment, whose whole point is the 0 window,
   would have been unusable. `ProjectSettings.SetEnvironment` additionally
   refuses (`ErrNoReauthHardCap`) to leave an environment at effective 0 while no
   hard cap is configured, so the state cannot be reached silently.
9. **The ADR's ORG-scope lockout refusal is effectively unreachable on a
   bootstrapped instance, and that is the intended reading — stated rather
   than left implicit.** The org census counts holders AT the org or ABOVE it,
   which is what grant evaluation itself would answer, so an instance-scope
   `manage-members` holder counts for every org. The instance-scope arm of the
   same invariant guarantees at least one such holder always exists, and
   bootstrap seeds exactly one. Therefore, on any instance that came up through
   `wenv admin create`, the org-scope refusal can never fire: every org is
   administrable by the instance holder.

   This is intent-defensible — an org with an instance member manager IS
   administrable, and refusing there would be the over-refusal the ADR does not
   ask for — and it is why the invariant's two arms are not redundant: the
   instance arm is the one that actually holds the line. The org arm is
   reachable only where no instance holder exists, i.e. a deployment whose
   grants were built by hand rather than by bootstrap;
   `isolation.TestLockoutCensus{SQLite,Postgres}` constructs exactly that state
   (raw-deleting the instance grant) because it is the only way to observe the
   org census at all. **Re-checked after the review's P1 and P2 fixes: still
   true, and now true for the right reason** — before P1 a project-scope holder
   could also satisfy the org census, which would have made the arm wrong as
   well as unreachable.

10. **`effectiveReauthWindow` fails CLOSED at 0 for an environment that does not
   resolve**, rather than falling back to the instance default. Consequence: the
   isolation fixture gained a real `env_prod` row (the reauth ceremonies address
   it), and `ts` widened to microsecond precision so the authn resolver's
   fixed-width `decodeTime` reads grant and origin timestamps.

## Scope cuts (deliberate, not gaps)

1. **`member invite` is NOT built, and it IS in the ADR's CLI surface.** The
   api-cli-surface ADR's verb table, line 75, reads verbatim:

   > `| access | `grant list \| add \| remove`, `member list \| invite \| remove`, `credential-reset` | #15/#16 formulas; CLI surface here |`

   `grant list|add|remove` and `member list|remove` all ship. `invite` does not,
   because no spec anywhere fixes what an invitation IS: there is no
   `invitations` table, no claim flow, no delivery channel, and no expiry
   policy. Building it would lock three product decisions nobody has made. The
   seam #54 named is untouched (`service.ErrNoInvitationPath`). **This needs an
   explicit in/out decision — see disposition item 1.**
2. **SCIM origins** (`scim`, `structural`, `lockout-retention`) are declared in
   the closed enumeration and refused by the writer → #73. The revoke path
   already skips origins it does not own, so #73 adds writers, not semantics.
3. **Restore / recovery-mode grant quarantine** → #76. No seam was needed here:
   the ADR's rule is that ordinary authorization denies everything until an
   operator commits the reconciled set, which is a chokepoint state, not a grant
   surface concern.
4. **No formulas registered for publish / pin / adapter / values-export /
   copy.** Those tickets register their own; the matrix generator is what makes
   their fixtures automatic — a formula registered without an addressable atom
   fails `TestMatrixCoversEveryProofMintingOperation`.
5. **Project deletion's "no protected environment in it" clause is vacuously
   satisfied** and was therefore NOT implemented (a `CountProtectedEnvironments`
   query was written and then deleted). v1 deletes never cascade: #48 already
   refuses to delete a project that holds any environment at all, so a project
   with a protected environment is refused one step earlier. If #48's
   non-cascading delete is ever relaxed, this clause becomes live and must be
   added back — noted so it is closed by name, not omission.

## Disposition items (human)

1. **`member invite` is specified by the ADR's CLI surface and is not built**
   (scope cut 1, which quotes api-cli-surface line 75 verbatim). Decide: build
   it in a follow-up slice with a spec for claim/delivery/expiry, fold it into
   #56, or strike it from the v1 verb set.
2. **Standing consequence, unchanged from #48: an org administrator cannot
   rename or delete their own org** and receives the uniform 404, because the
   locked atom set has no org-lifecycle capability. This ticket deliberately did
   NOT amend the ADR. If the consequence is wrong for the product, the amendment
   is a separate decision.
3. **`grant.template_applied`, `grant.membership_read` and
   `recovery.break_glass_grant` are additions to the closed audit registry**
   (deviation 7). The audit ADR's `grant` and `recovery` category rows do not
   name them; they are consistent with the ADR's intent and with existing
   precedent (`auth.provider_read`, `settings.org_read`), but the catalogue text
   is the human's to amend.
4. **`break-glass` as an origin kind is an ADR amendment made in code**
   (deviation 2), extending the SCIM amendment's closed origin enumeration by
   one. Same disposition shape as #54's `issued_by='recovery'` issuer. Confirm
   the amendment, or fold break-glass grants into `manual` with a reserved
   subject and accept that the membership surface can no longer distinguish a
   recovery grant from an ordinary one.
5. **`DefaultReauthHardCap = 15m` decides an operations-spec fog value**
   (deviation 8). The code required a non-zero hard cap to make a 0-window
   (protected-environment) reauth usable at all — #54's disposition item 1 — so
   a number was chosen rather than shipping a broken gate. The ops spec owns the
   number; confirm or replace it.
6. **Two spelling joins to the closed CLI verb set**, declared additively under
   the ADR's own grammar exactly as #48 declared `rename`/`show`/`reorder`/the
   `folder` family: `wenv access grant template` (the ADR fixes no spelling for
   applying a role template, and the acceptance criteria require one) and
   `wenv project-settings get|set` with a required `--env` (the ADR puts
   "project-settings get/set" in the org/project lifecycle group, but both knobs
   are per-environment). **#27/freeze must confirm or rename.**
7. **Serializability of dedup and the lockout invariant is lock-argued, not
   race-fixtured** — same disposition shape as #54's item 3, and the honest
   statement of what holds:
   - Every read-then-write on this surface takes the target's `principals` row
     lock as its FIRST statement — `grantOne`, `BreakGlassGrant` and `Revoke`.
     An earlier draft took the lock inside `CreateGrant`, i.e. AFTER the dedup
     read; with no uniqueness over the triple by design, two concurrent creates
     could both have read no row and both inserted. Fixed before landing.
   - `checkLockout` locks every current `manage-members` holder's row in sorted
     order (sorted acquisition is what makes pairwise locking deadlock-free)
     and then **re-reads the census under those locks**. Counting from the
     pre-lock list was the same class of bug: two revocations of the last two
     holders would each have counted the other as remaining.
   - Postgres write transactions run at **Serializable** (`internal/store/tx`),
     with retry, so SSI is a second net under the locks; sqlite serializes on
     its single writer. The locks are what make the property true independent of
     isolation level rather than dependent on it.
   - No concurrent-revocation or concurrent-create fixture exists.
8. **`access member remove` is not atomic** — it is a client-side loop over the
   per-capability revoke, so each revocation is its own audited event (what the
   audit ADR asks for) but a mid-loop failure leaves the earlier capabilities
   revoked. That is the safe direction to fail in and the command reports how
   far it got. A server-side bulk verb would be atomic but would either collapse
   the per-capability audit events or need a second formula; neither is
   specified. Confirm the trade or spec the bulk verb.

## Two-axis review record (standards + spec), round 1

All nine findings fixed in-slice; none deferred, none disputed.

**Standards**

- **S1 (HARD)** — `hasOrigin` swallowed the origin read error and answered
  `false`, so a failed read became "attach an origin" and surfaced as a UNIQUE
  violation with the real cause gone. It now returns `(bool, error)` and
  propagates; the doc comment claimed it read the membership listing, which it
  never did.
- **S2** — `BreakGlassGrant` re-implemented ~50 lines of `grantOne`. Both now
  share `lockAndClassify` (row lock → class → normative allowlist) and
  `writeGrantRow` (dedup → create → origin attach → generation advance →
  session kill), differing in exactly the two things that differ: the origin
  kind and where the audit event goes. The swallowed error had already lived in
  both copies, which is the argument.
- **S3** — `GrantLinesInOrg` / `ManageMembersHolders` took `domain.OrgID`. The
  proof-signature analyzer walks `Repos`/`ReadRepos` only, so the resolution
  surface escaped it; both now take plain `string`, matching
  `EnvironmentReauthSettings` in the same file.
- **S4** — two stale comments: `internal/store/repos.go` named a
  `CountProtected` method that was written and then deleted (scope cut 5), and
  `internal/server/access.go` said a length mismatch "would panic" where the
  code returns `domain.ErrInvalid` from an explicit guard.
- **S5** — **kept, not deleted, and rewritten as a real clamp.** The arm is
  unreachable only because `ProtectedWindowCap` is 0 today; deleting it would
  make the protected read `return ProtectedWindowCap` unconditionally, so an
  operations spec that ever RAISES the cap would silently widen an environment
  explicitly stored at a smaller window — exactly the environment the flag
  protects. It is now `min(window, ProtectedWindowCap)`, which is the same
  value today, has no unreachable branch to flag, and stays correct if the
  constant moves.

**Spec**

- **P1 (WRONG)** — `ListManageMembersHoldersForOrg` lacked `project_id IS NULL`
  in both dialects, so a PROJECT-scope `manage-members` row counted toward the
  ORG census, contradicting the query's own doc, the test premise and ADR
  §Evaluation 5. Conjunct added both dialects; `annotated_queries.json`
  re-pinned (the hash is the review artifact).
- **P2 (WRONG)** — `checkLockout` excluded the target principal wholesale, so
  revoking one `manage-members` grant from a principal who still held a
  covering one at another scope was refused although the org stayed
  administrable by that same person. It now counts what REMAINS after the
  revocation: `retainsMemberManagement` asks whether another
  `manage-members` grant of the target's, at a different scope, still covers
  the scope in question.
- **P3 (WRONG)** — the revoke event hardcoded `origin_kind: "manual"` while the
  release loop also releases break-glass origins, erasing from the revocation
  trail the one distinction deviation 2 exists to make. It now records the
  kinds actually released, sorted and comma-joined (the `environment_order`
  precedent for a multi-valued trusted-vocabulary field).
- **P4 (GAP)** — `TestRevocationIsImmediate` was sqlite-only; the postgres twin
  now runs from the shared body.
- **P5 (DECLARE)** — the org-scope refusal's effective unreachability is now
  deviation 9, re-checked after P1 and P2.

New regression coverage: `isolation.TestLockoutCensus{SQLite,Postgres}` asserts
the census excludes project-scope holders (P1), that a principal covering the
org at two scopes may lose one of them (P2), and that the revocation trail
records `break-glass` when that is what was released (P3).

## Cross-model review (Codex `gpt-5.6-sol`, high effort)

### Round 1 — BLOCKED, 2 HIGH / 6 MEDIUM / 2 LOW

R1 verdict **BLOCKED** — 2 HIGH, 6 MEDIUM, 2 LOW. Report:
`.xreview/55-perms-r1.md`. Eight fixed in-slice; F10 dispositioned by the human
(below). Nothing disputed.

**F1 (HIGH) — machine allowlists bounded capability but not scope.**
`checkPrincipalClass` saw only `(class, capability)`, so a workload could take
`read` at org or instance scope — reaching every environment in the org, the
opposite of the ADR's "explicit (project, environment)" — and automation could
take grants across unrelated projects. Two rules added and enforced at the ONE
point all three writers share (`lockAndClassify`, called by the individual
grant, by template expansion through `grantOne`, and by break-glass):

- **scope depth** (`domain.machineDepths`): workload grants must address an
  environment, automation project depth or below;
- **one project**: the principal's existing grants fix the project and every
  later grant must match it.

*Stated limit, and the reason it is this shape:* the credential BINDING that
names a machine's project authoritatively is #17's and does not exist yet, so
the principal's own grants are today's record of which project it belongs to.
#17 replaces this with the binding, and the rule gets stricter, never looser.
Regression: `isolation.TestMachineScopeBounds{SQLite,Postgres}` runs org-,
instance- and foreign-project refusals through **all three writers**, plus
positive controls.

**F2 (HIGH) — bootstrap seeded a bespoke instance-scope bundle including
`read`, `reveal` and `reveal-history`.** The parallel `AdminTemplate` list is
gone. Bootstrap now applies the ADR's own `operator` template at instance scope
(`BootstrapTemplate = domain.TemplateOperator`), expanded from the locked
table.

*The reconciliation, stated because two ADR clauses pull apart at bootstrap:*
Propagations → #16 says the first administrator MUST be bootstrapped "via the
`admin` template (so reveal/reveal-history are seeded as separate visible
grants)"; the template table makes `admin` applicable at **org/project scope
only**, and § Administrative power says an instance operator reaches an org's
data "through an explicit audited grant, **never by bundle**". At bootstrap
there is no org, so both cannot be satisfied literally at once. The reading
taken: **bootstrap seeds `operator` at instance scope** — separate visible
grants, no disclosure, no tenant data by bundle — and the `admin`-template
clause is satisfied where it is applicable, at **org scope**, when the first
administrator creates the first org and applies `admin` to themselves through
their instance `manage-members` (the ADR's own unheld-granting power, audited
like any other grant). `reveal` and `reveal-history` arrive there, as the
separate seeded rows the clause asks for.

Knock-ons, all landed: the demo applies the admin template at the org it
creates and re-logs in (a self-grant advances the administrator's own
generation and deletes their sessions — the ADR's rule applied to the person
applying it, and now demonstrated); `credential-reset` is no longer bundled, so
#54's reset fixtures grant it explicitly through the real grant surface, which
is exactly the "explicit audited grant" the ADR describes.

**F3 (MED) — project listing read the whole org and filtered in Go.**
`ListGrantsWithOriginsForProject` added both dialects, plus
`GrantLinesInProject`; `Grants.List` switches on the addressed depth instead of
over-reading. Regression:
`isolation.TestProjectListingDoesNotReadSiblings{SQLite,Postgres}` lands 20
grants in a SIBLING project and asserts the project listing does not move —
**asserted on rows returned, not query count**, because the overfetch is one
query either way and a query-count trace structurally cannot see it.

**F4 (MED) — A2 uniformity was stub-proven only.**
`internal/isolation/access_wire_test.go`, dual-engine: a bootstrapped
instance, a WebAuthn-stepped-up session (the grant routes are MFA-mandatory,
so a password-only session would answer 403 and drown the comparison), the real
services behind the real router. Seven route pairs — genuinely missing scope vs
genuinely unauthorized existing scope — asserting identical status, identical
bytes, and no `count`/`items` member on refusal, with positive controls first
so "both answered 404" cannot be satisfied by a broken surface. Plus
`TestAccessWireQueryTrace{SQLite,Postgres}`: the structural timing control for
the new operations (1 query on a miss at any depth, 2 on a denial against an
existing object).

**F5 (MED) — audit lifecycle did not match the state transition.** Three fixes:
an idempotent repeat that created no row and attached no origin now emits **no
lifecycle event** (the zero event is "nothing happened", skipped by
`insertGrantEvent`); a release that leaves the row alive because a
`scim`/`structural` origin still holds it is a **`grant.modified`**, matching
the registry comment that already said so; and the generation advance and
session deletion on revoke now run **only when the row actually died**, because
releasing one of two origins takes no authority away and killing sessions for a
bookkeeping change is a denial of service dressed as security. The template
summary splits `grants_deduped` into `grants_joined` and `grants_unchanged`.
The four revoke operations declare both event types. Regression:
`isolation.TestGrantLifecycleEvents{SQLite,Postgres}`, which plants a `scim`
origin by raw SQL (only #73 can mint one, and the surface must already behave
correctly when it meets one).

**F6 (MED) — `project-settings set` silently cleared protection.** The
`--protected` bool defaulted to false and was sent on every `set`, so
`--reauth-window-seconds N` unprotected the environment through a command that
never mentioned protection. Now tri-state (`--protected true|false`,
`--reauth-window-seconds N|inherit`), unspecified preserving the stored value
by reading the current settings and overlaying only what was named — the route
is a full replacement, so the read is what makes "unchanged" mean it.
Regression in the CLI demo: protect, then a window-only update, then assert
still protected.

**F7 (MED) — only EFFECTIVE durations were compared.** The stored configuration
is now compared and audited too: `previous_configured_seconds`,
`configured_seconds` (with `-1` for "inherits", distinct from a real `0`),
`previous_inherited` and `inherited`. `widened` stays its own field and stays
about the effective value, so an inheritance flip that changes nothing today is
not filed as a widening. Regression in
`isolation.TestProtectedEnvironment{SQLite,Postgres}`: inherited→explicit at
the SAME duration, and back, each emit an event.

**F8 (MED) — the migration classified every legacy machine as automation.**
The backfill is **gone**, not softened. An unclassified machine principal stays
NULL and fails closed at every allowlist path, so it can hold no NEW grant
until an operator classifies it; its existing grants keep evaluating, because
authorization reads the grant table and never the class. Guessing `automation`
would have handed a pre-existing WORKLOAD credential the
edit/publish/definitions-edit set — a privilege escalation performed by a
migration. The isolation fixture now states its own machine class explicitly,
which is the honest consequence: a fixture that wants an automation credential
has to say so.

**F9 (LOW) — the protected branch was not a true clamp.** `effectiveWindow`
now computes the base window first (explicit or inherited) and applies
`min(base, ProtectedWindowCap)` to that. The old shape returned the cap flat
for the inherited case, so a positive ops-owned cap over a smaller instance
default would have made protecting an environment WIDEN it.

**F10 (LOW) — NOT changed in code, by orchestrator triage.** `break-glass` as
an origin kind and `DefaultReauthHardCap = 15m` are already disposition items 4
and 5 for the human merge gate — the house procedure for a code-made ADR /
ops-spec decision, same shape as #54's `recovery` issuer. The orchestrator
carries that answer to R2.

**Found while fixing, not reported:** every refusal sentinel in
`internal/service/grants.go` and `settings.go` was bare, so all of them
rendered `internal` — telling a script the server broke when it had answered
correctly. This is the same defect #48 found when `conflict` and
`limit_exceeded` fell through the CLI's status mapping. Each now wraps a domain
sentinel: shape errors `invalid`, post-authorization state refusals `conflict`,
a triple that is not held `not found`.

### Round 2 — 8/10 FIXED, F4 and F5 PARTIAL; both closed

Report: `.xreview/55-perms-r2.md`. R2 confirmed F1, F2, F3, F6, F7, F8, F9, F10
and the extra sentinel fix. Two remained partial; both are now closed.

**F4 — the real-stack pairs were not all unauthorized-vs-existing.**

- *(a)* The wire fixture created only an ORG, so the project-list and both
  settings "refused" legs were comparing a missing CHILD against a missing ORG
  — two kinds of missing, not the case the acceptance row is about. Setup now
  seeds a real project and environment under the wire org
  (`internal/isolation/access_wire_test.go`, `newAccessWireEnv`), so the
  refused leg addresses objects that genuinely exist. They are seeded directly,
  as every other fixture row is: creating them through the API would mean first
  granting the administrator `manage-projects` and `definitions-edit` and then
  re-authenticating (a self-grant kills the acting session), churn that changes
  nothing about the property under test.
- *(b)* The pair table went from 7 routes to **13** — the full access surface:
  org list/create/revoke/template, project list/create/revoke/template, env
  create/revoke/template, and settings read/update.
- *(c)* The query trace no longer calls `Authorize` directly. It runs the
  **real service path** (`Grants.List`, `Grants.Create`,
  `ProjectSettings.GetEnvironment`) with a real `service.Bearer` artifact, so
  session resolution and everything else the request does is inside the
  measurement. Two properties are asserted, relative to a measured baseline
  rather than a hardcoded number: **every miss costs the same whichever level
  is missing** (a per-level walk would make a missing environment cost more
  than a missing org, and a caller could count its way to which level exists),
  and **a denial against an existing object costs exactly one query more** —
  the grant lookup a miss skips, which is the residual the isolation ADR
  already accepts.

  Counting the service path needed a seam: `tx` builds the resolver inside
  itself, and `internal/store/tx` may not import the generated query packages
  (the driver-handle allowlist). The seam is therefore
  `authn.SetQueryObserver` — nil in production, installed at Resolver
  construction so an unset observer costs one atomic load per transaction and
  never per query. It lives on the resolution surface because that is the
  package the generated queries may be imported into at all, and because on a
  REFUSED request the resolution surface is the entire query traffic:
  authorization runs before any store call, so a request that does not
  authorize issues nothing else. `TestQueryObserverIsTestOnly` pins that the
  seam has no production call site, so the doc comment's claim is a check
  rather than a promise.

**F5 — an origin join was still treated as an authority change.** Adding a
second origin to a grant the holder ALREADY had advanced their generation and
deleted their sessions, although effective policy did not move: the capability
was held before and after. The advance is now gated on `out.Created` — a NEW
row, which is when the capability becomes held — and the join emits
`grant.modified` and nothing else. Symmetric with revoke, where the advance was
already gated on the row actually dying. Without this, one administrator's
bookkeeping logged another principal out.

Regression: `isolation.TestOriginAddKeepsSessionAlive{SQLite,Postgres}` — a
second grantor joins the triple and the holder's session survives, with a
control in the same test proving the same session DOES die when the grant is
revoked, so the assertion is the gate working rather than the machinery being
disconnected.

## Pickup notes

- **Adding a capability atom**: add it to `capabilityLevels` in
  `internal/domain/domain.go` (the map IS the closed set — `IsCapability` and
  the grant API's validation both read it), and to a machine allowlist if any
  machine class may hold it. A formula atom outside the map fails the A2 matrix
  planner by name.
- **Adding a role template**: add a row to `templates` in
  `internal/domain/permission.go`. Nothing else needs touching — expansion,
  audit and the CLI all read the table.
- **Adding a grant-surface operation**: register it in `authz.operations` AND
  add its depth to `grantOpsByLevel` in `internal/service/grants.go`; a depth
  with no quartet entry silently falls through to the zero Operation, which
  `Authorize` refuses loudly.
- **The A2 matrix needs no per-operation fixture author.** A newly registered
  formula is exercised automatically. What DOES need attention: a new addressed
  depth needs an entry in `matrixScopes`, and a new atom needs to be in the
  closed capability set — either omission fails
  `TestMatrixCoversEveryProofMintingOperation` with the operation named.
- **Re-pinning fixtures**: `operation_formulas.json` and
  `annotated_queries.json` have no `-update` flag. The throwaway repin test used
  here was deleted deliberately; regenerate by copying the `current:` JSON out of
  the failing test's output, or re-add a temporary test that writes
  `facts.FormulaPins()` and the `lint.ParseQueries` pin list.
- **Adding an access route**: the path decides the scope, so a new depth needs
  a new path, a new operation and a row in `grantOpsByLevel` — not a body
  member. All five `x-wenv-*` extensions, `wireRegistry` + `wireRoutes`, and a
  row in `hierarchyRoutes()` (`internal/server/contract_test.go`) so the new
  route joins the byte-shape assertion rather than getting a weaker one.
- **Postgres harness**: `grant_origins` drops BEFORE `grants` (RESTRICT FK) in
  BOTH `internal/isolation/harness_test.go` and
  `internal/conformance/conformance_test.go`. A missing entry fails only on
  postgres, with SQLSTATE 2BP01 on the NEXT run's re-migration.
- **Run the postgres leg.** `WENV_TEST_POSTGRES_DSN=postgres://wenv:wenv@127.0.0.1:5432/wenv_test go test ./... -count=1`.
  A sqlite-only run is structurally blind to drop-order, FK-restrict and
  isolation-level behaviour.
- **`seedOrigins`** in the isolation harness attaches a `manual` origin to every
  raw-SQL fixture grant. A fixture grant without one is invisible to the
  membership surface (an INNER JOIN onto origins) and un-revokable — which is
  the invariant, expressed as a query.

## Verification record

- `gofmt -l .` clean; `go vet ./...` clean.
- `go test ./... -count=1` on **sqlite**: **616 passed, 0 failed, 30 packages**.
- `go test ./... -count=1` with
  `WENV_TEST_POSTGRES_DSN=postgres://wenv:wenv@127.0.0.1:5432/wenv_test`
  (**both engines**): **958 passed, 0 failed, 30 packages**.
- The A2 matrix contributes 163 subtests per engine (one grant case plus one
  deny case per atom, per proof-minting operation).
- `go tool sqlc generate` idempotent; `go tool oapi-codegen --config
  api/oapi-codegen.yaml api/openapi.yaml` idempotent; 3.1 profile + freeze
  fixtures pass.
- TS client: `pnpm install --frozen-lockfile && pnpm run generate && pnpm run
  typecheck && pnpm run test` on Node 24 (per `.nvmrc`) — 4/4 contract fixtures.
  `clients/ts/src/generated/{index,sdk.gen,types.gen,zod.gen}.ts` regenerated.
- CLI goldens re-pinned with `go test ./internal/cli -update`; the diff is 10
  added help lines in `internal/cli/testdata/help.txt` and nothing else.
- `annotated_queries.json` re-pinned after the review's P1 conjunct: the census
  query's hash change IS the review artifact.

### Fixed during orchestrator verification (not by this agent)

Both postgres harness DROP lists (`internal/isolation/harness_test.go`,
`internal/conformance/conformance_test.go`) were missing `grant_origins` before
`grants`, so the postgres re-migration failed with SQLSTATE 2BP01. Caught by the
orchestrator's dual-engine run and fixed in this tree; recorded here because a
sqlite-only run structurally cannot see it — the RESTRICT FK is what makes the
drop order load-bearing, and sqlite's harness recreates the file per test.

- **Cross-model review: R1 BLOCKED (10 findings), R2 8/10 FIXED with F4 and F5
  PARTIAL — both closed in this round. R3 is the final verdict round.** See the
  round-1 and round-2 sections above.
