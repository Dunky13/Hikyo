# PROTOTYPE — app chrome: organisation, account & access surfaces (wayfinder ticket #29)

**Question:** how do the surfaces *around* the matrix hang together — where the
active organization lives in the chrome, the account/profile surface, project
settings, membership & role management, and whether instance administration is
in the v1 UI at all.

Sibling of `prototype/env-matrix/` (frozen at iteration 31, the reference
design) and `prototype/reveal-edit/` (#21). Design language unchanged; this
prototype varies **structure**, not skin.

**Run:** `./prototype/serve.sh` then open `/app-chrome/` (works on phones via
LAN). Every change is a new numbered iteration — published ones never mutate.

## Iteration 1 — baseline

Three **org-placement variants**, switchable via the floating bottom bar,
`←`/`→`, or `?variant=`:

- **a — rail owns orgs**: round org monograms stacked at the top of the 56px
  rail, projects of the active org below a divider. Org switch = one click,
  always visible.
- **b — crumb owns org**: rail is projects-only; the org name in the header
  breadcrumb is a button opening a popover (role + project count per org).
- **c — org overlay**: single active-org tile at rail top opens a Slack-style
  full overlay with org cards.

**"Unauthorized ≡ nonexistent" made visible** (permission ADR #15) via the
persona simulator in the header:

- `marc` — 2 orgs, org admin, instance admin: full chrome.
- `dana` — 1 org, developer: **no org-switching affordance in any variant**
  (an org you're not in doesn't exist; a single-org user gets no org chrome),
  no org-members panel entry, no instance gear.
- `sam` — external: rail shows **one project**; the members table is
  read-denied ("shows only what you're allowed to see").

Surfaces (same across variants):

- **Account & security** (rail avatar): active sessions with **browser vs CLI
  artifact types** visually distinct (ADR #16: distinct artifact types);
  factors (passkeys, TOTP, password framed as "signs you in — never
  authorizes security changes"); **display-once recovery codes** modal
  (hash-only storage stated, ack checkbox before close); **passkey-only
  precondition** (recovery codes + ≥2 passkeys) shown as a locked toggle with
  progress; identity linking keyed `(issuer, subject)` with "email never
  links" stated inline.
- **Step-up ceremony**: every account-security mutation runs a **blue
  "confirm it's you"** modal — possession factor only, with in-modal copy
  distinguishing it from the **teal reveal/disclosure ceremony** (#21) and
  stating why password and recovery codes don't count. Deliberately different
  color, icon, and framing per ADR #16's requirement that the two reauths be
  distinguishable.
- **Members & access** (project + org level): every grant is **one
  independently revocable line** `(principal, capability, scope)` with its
  origin template shown; a **"who can…?" inspection** query answers "who can
  reveal production secrets?" by selection; **org-scoped grants trigger a
  blast-radius warning** enumerating every current project/env plus "any
  project created later", with the narrower alternative offered.
- **Project settings**: identity (hue + optional glyph over the default
  monogram — matrix iteration 9 finding that monograms alone collapse at
  scale), metadata, and an access **entry point only** (no second permission
  editor).
- **Instance administration** (persona-gated gear): org list + create,
  read-mostly instance settings — and an in-UI question card posing the
  ticket's open decision: **Option A** (this thin surface in v1) vs
  **Option B** (no instance UI, CLI-only, UI starts at the organization).
  Root-key ops/migrate/restore/break-glass stay CLI regardless (API/CLI ADR).

Matrix itself is a stub linking to the frozen env-matrix/31 reference — this
prototype owns everything around it.

## Iteration 2 — round-1 feedback (Marc)

Marc on iteration 1:

1. The matrix has its own sidebar — a chrome designed without it risks a
   double sidebar.
2. Org switching broken on mobile: variant b's popover got an offset and
   didn't render; a and c barely differ on mobile; no way to switch org at
   all on a phone.
3. Member list too long — one row per grant. Group by (member, scope).
4. No way to create/invite members.

Changes:

- **One sidebar, merged.** The matrix view is now a real condensed matrix
  (subset of env-matrix/31's data: groups, secret dots, protected header,
  problem cell) and the side panel is the env-matrix-31 panel — group rows
  with problem badges + problems view, indented under "Environment matrix",
  with Members & access / Project settings / org section in the same panel.
- **Mobile org switching.** The drawer now opens with an *organizations*
  section in every variant (the rail is hidden on mobile, so a/b/c converge
  there — the org-placement question is desktop-only, stated in-file).
  Variant b's crumb popover renders as a full-width sheet under the header
  on ≤700px instead of an offset popover.
- **Members grouped.** One row per (member, scope); capabilities are chips
  in that row, each chip individually revocable — the grant stays the atom,
  only the presentation groups.
- **Invite flow.** Org-level "invite member": email (labelled *delivery
  only*), role template, scope. Modal states the ADR #16 rule: the
  invitation binds to the capability set and to whoever redeems it — never
  an email comparison. Pending invitations render in the member list with a
  dashed chip + revoke.

## Iteration 3 — round-2 feedback (Marc)

"Still no difference between a and c on mobile, and b doesn't render well on
my phone." Product is mobile-first, so the org-placement variants must differ
*on the phone*, not just desktop:

- **a** mobile: drawer opens with an organizations section (drawer owns orgs).
- **b** mobile: compact crumb (`envweave /` prefix hidden ≤700px), org
  segment opens a full-width sheet under the header with scrim; drawer has
  no org section.
- **c** mobile: org monogram button in the header opens the switcher
  full-screen; drawer has no org section.

Plus mobile header fixed to a single row (was stacking 4 rows tall).

## Iteration 4 — round-3 verdicts (Marc)

**Decided:**

- **Org placement: A — the rail owns orgs.** Monograms above the project
  squares; mobile drawer opens with the organizations section. Variants b/c
  and the switcher deleted.
- **Instance surface: in the v1 UI, full CLI ↔ UI feature parity** for
  instance management (#25's parity principle extended to instance scope).
  Reason: envweave may run locally / VPS / k8s / docker while managing orgs
  and projects hosted elsewhere — the CLI is not always the convenient
  surface. The instance page now shows org create, editable instance-config
  values, and keys & crypto (master-key / token-key rotation, reencrypt
  status), each row carrying its CLI-verb twin. **Parity exception stays
  locked:** the SystemProof local set (init, migrate, restore
  reconciliation, break-glass) is local host authority (#23/#25) and has no
  UI or network surface.

**New exploration (own wayfinder ticket, NOT decided here):** Portainer-style
multi-instance management — one MAIN instance connects to and manages other
envweave instances. Sketched as a "Connected instances" card (main badge,
reachable/unreachable states, connect button) purely to react to; the
decision (what "manage" means, credential model, tenancy/threat-model
consequences, v1 or not) belongs to that ticket and the MVP boundary.

## Iteration 5 — grant checklist (Marc)

"New grant, do we want checkbox instead of select, if you want multiple at
once?" — yes, and it stays ADR-consistent: the new-grant modal now shows a
**capability checklist**; each checked capability becomes its **own
revocable grant line** at the chosen scope (exactly what role templates do
with a preset checklist — batch creation, never a bundle). Empty selection
refused; the org-scope blast warning enumerates the checked capabilities and
states they are N separate lines.

## Iteration 6 — account layouts (Marc)

"Account & security is missing account-related settings, and it's too many
cards — scrolling is tedious. 3-5 approaches."

**Content added:** Profile (display name, email labelled *delivery only* —
never identity, never links, #16) and Preferences (theme; credential-expiry
warnings in-product always-on with email as optional added transport, #17;
security alerts always-on, not disableable).

**Five structural layouts**, switchable via bottom bar / ← → / `?account=`
only while the account view is open (sections identical across all five):

- **a — tabs**: chip-tab row, one section visible, zero scroll.
- **b — panel nav**: the side panel owns the account sections; the account
  surface navigates exactly like a project.
- **c — jump index**: one scroll retained, sticky chip index with smooth
  anchor jumps.
- **d — accordion**: collapsed cards with live summary lines
  ("2 passkeys · TOTP · password", "codes ✗ · passkey-only off"), one open
  at a time.
- **e — tiles + drill-in**: overview grid of summary tiles, tap to focus a
  single section, back out.

## Iteration 7 — account layout locked; shape treatments (Marc)

**Decided: account layout c — jump index** (one scroll, sticky chip index).
Other four layouts and their switcher removed.

**New question: rounded corners & pills are overused.** Impeccable pass;
what's being reopened is DESIGN.md's Shape line ("Radius: 6px controls,
999px pills"). Four app-wide treatments via bottom bar / ← → / `?shape=`:

- **a — baseline**: current skin (8-14px radii, 999px pills everywhere).
- **b — squared 2px**: one geometry, every radius collapses to 2px, pills
  become small rectangles, rail avatars included. Terminal/hairline feel.
- **c — role scale**: radius carries a role — containers 6px, controls 4px,
  badges 3px; the 999px pill is *reserved* for org identity circles, count
  badges and the matrix cell-state vocabulary, nothing else.
- **d — flat, de-carded**: sections separated by hairline rules instead of
  card boxes (uppercase ruled labels), tags become colored mono text with no
  border, radius 0 everywhere except overlays (8px).

DESIGN.md amendment + (if the verdict touches cell pills) an env-matrix
reference note land only after the verdict.

## Iteration 8 — shape c baked in; Codex placement audit (Marc)

**Decided: shape treatment c — role scale**, now the only skin (switcher and
a/b/d removed; DESIGN.md Shape section amended in the same commit):

- containers/cards **6px** · controls **4px** · badges/tags/chips **3px**
- **999px pill reserved** for org identity circles, count badges, and the
  matrix cell-state vocabulary — nothing else.

Then a **Codex placement audit** (gpt-5.6-sol, high effort, read-only):
17 findings (2 high / 11 med / 4 low). Disposition:

**Implemented (13):**

1. *(med, the load-bearing one)* CSS order defeated the role-scale override
   block — `.modal-box` computed 14px, `.capgrid` 8px, `.answerbox` 10px,
   `.scopechip` 6px. Fixed by **baking the role radii into every base rule**
   and deleting the override block: one source of truth, no order fragility.
2. `.pav` project tiles + rail buttons are controls → 4px (were 6/10px).
3. `.bigav` 6px; `.hue` swatches lose the forbidden circle → 4px; `.glyph` 4px.
4. `.atab` jump chips are interactive controls → 4px, not badge 3px.
5. Stale `999px`/`50%` base declarations removed (baking made them real).
6. `.codes code` are boxed content, not inputs → 6px.
7. *(high)* Mobile touch targets: 44px min-height for buttons/tabs/selects/
   checkbox labels, 44px swatches, 34px chip-revoke — `≤700px` media only,
   desktop keeps DESIGN.md's density.
8. *(high)* `.capchip .rm` revoke was ~9×12px → 26×26px hit area (34px
   mobile), kept **inside** the chip: grouped rows are a decided shape,
   relocation rejected.
9. Checkbox labels get `cursor:pointer` + min-height.
10. `Escape` now also closes the drawer; scrims marked `aria-hidden`
    (pointer convenience, keyboard path is explicit controls + Esc).
11. Condensed-matrix pen no longer lights up on hover (cells are
    illustration here; interactive implication removed, static affordance
    stays).
12. `.grants` row hover highlight removed (rows carry no action).
13. Panel group rows now do something on desktop: scroll the matrix to the
    group anchor; problems row scrolls to the violation cell.
14. Tag vocabulary: `.tag` = categorical status only; instance values
    (`envweave.went.io`, `90d`) and CLI refs are now unbordered
    `code.val` / `code.cliv` text.

**Rejected / deferred (3):**

- `#side .srow` → 4px + inset: rejected — full-bleed list rows, radius roles
  apply to discrete controls; flat panel rows are the reference design.
- Custom-drawn checkboxes: out of prototype scope; recorded as a UI-spec
  note (control-radius consistency for form elements).
- Relocating chip revokes to row-end `.xbtn`s: rejected, see 8.

DESIGN.md reserved-pill wording widened to "identity circles (org and
account avatars)" — the account avatar was always a circle; now the rule
says so.

## Iteration 9 — jump index everywhere (Marc)

"Apply same tabs/sticky to all settings, not just Account & security." The
sticky jump index is now the pattern for **every sectioned settings
surface**, via one shared `jump()` helper (`.secjump`, same chips, same
smooth anchor scroll):

- Account & security — 6 sections (unchanged)
- Project settings — Identity · Metadata · Access
- Members (project and org level) — Who can…? · Members
- Instance administration — Organizations · Settings · Keys & crypto · Instances

## Verdict

_Decided: org placement (it4), instance parity (it4), grant checklist (it5),
account layout c (it7), shape role-scale (it8), jump index on all settings
surfaces (it9). Open: final confirmation pass on iteration 9 resolves the
ticket._
