# PROTOTYPE — app chrome: organisation, account & access surfaces (wayfinder ticket #29)

**Question:** how do the surfaces *around* the matrix hang together — where the
active organization lives in the chrome, the account/profile surface, project
settings, membership & role management, and whether instance administration is
in the v1 UI at all.

**Status: LOCKED** (ticket #29 resolved 2026-08-04). Iteration 15 is the
reference chrome. All iterations stay runnable; no further edits to any
iteration directory.

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
- **b** mobile: compact crumb (`wenv /` prefix hidden ≤700px), org
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
  Reason: wenv may run locally / VPS / k8s / docker while managing orgs
  and projects hosted elsewhere — the CLI is not always the convenient
  surface. The instance page now shows org create, editable instance-config
  values, and keys & crypto (master-key / token-key rotation, reencrypt
  status), each row carrying its CLI-verb twin. **Parity exception stays
  locked:** the SystemProof local set (init, migrate, restore
  reconciliation, break-glass) is local host authority (#23/#25) and has no
  UI or network surface.

**New exploration (own wayfinder ticket, NOT decided here):** Portainer-style
multi-instance management — one MAIN instance connects to and manages other
wenv instances. Sketched as a "Connected instances" card (main badge,
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
    (`wenv.went.io`, `90d`) and CLI refs are now unbordered
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

## Iteration 10 — project identity: custom hue + image (Marc)

"Allow custom color, and upload of image, as well as current settings."

- **Custom hue slider** (native range, 0-359°): live preview without
  rerender, pinned to the brand formula — `oklch(0.62 0.11 <hue>)`, same
  lightness/chroma always, so any custom choice stays on-palette. Preset
  swatches remain as shortcuts.
- **Image upload** (native file input → FileReader dataURL): shown in the
  header avatar *and* the active rail tile; removable ✕ restores
  monogram+hue. Priority: image > glyph > monogram.

## Iteration 11 — grant explanations (Marc)

"On grant show a tooltip explaining each Grant." Every capability in the
new-grant checklist carries its explanation (permission-ADR wording) as an
**always-visible sub-line** rather than a hover tooltip: mobile-first
product, hover is dead weight on touch. The checklist is now rendered from
one `CAPDESC` map (single source); member-table capability chips carry the
same text as their `title`.

## Iteration 12 — explanations behind (?) (Marc)

"Hide it behind (?) so it doesn't take more space than it should." Each
capability row is single-line again with a 24px **(?)** at its end: tap
toggles the explanation inline under that row (`aria-expanded` tracked),
`title` supplies desktop hover. Checkbox untouched by the toggle.

## Iteration 13 — /impeccable critique fixes

Critique ran as two isolated assessments (design-director review in its own
browser tab + the impeccable deterministic detector with the [Human]
overlay tab). Score: **25/40**; verdict: not AI slop, held back by error
handling and undo. All five priority issues + minors fixed here:

1. **Contrast (P1)**: `--tx-faint` lifted 0.60→0.71 dark / 0.52→0.46 light
   (was 4.35:1 at 10-11px on an AAA-leaning product).
2. **Color-only validation (P1)**: zero-capability grant and empty invite
   email now show a text error with `role=alert` (border color stays as the
   secondary signal). "State is never color-only" honoured at the moment of
   confusion.
3. **Dangerous default (P1)**: new-grant scope reordered narrow→wide with
   **staging preselected**; protected production is never the default.
4. **Blast-cancel (P2)**: the org-scope warning gains "back, change scope",
   restoring the full composition (capabilities, principal, scope).
5. **Revoke asymmetry (P2, Marc's call)**: revoke stays one-click (absence
   is the only denial, removal is safe) but every revoke/grant/invite now
   fires an **undo toast** (8s, aria-live) — which also closes the
   silent-table-update feedback gap after granting.

Minors: modal headings h4→h3 (no h2→h4 skip), sticky modal footer ≤700px
(grant button was below the fold on phones), org-members crumb reads
"org members", matrix first/last column breathing room, **em dashes swept
from all UI copy** (detector counted 8; copy law).

Recorded, not changed: ADR refs (#16, #25…) stay in prototype copy as
scaffolding for spec synthesis — the UI spec strips them for the product.
Emoji icon set + `alert()` stubs are prototype-grade by design.

## Iteration 14 — org settings (confirmed shape brief)

New surface per the confirmed brief. Entry: **"Org settings"** row in the
panel organization section, org admins only (dana/sam see nothing:
unauthorized ≡ nonexistent). Jump index, three sections:

- **Identity**: name, preset hues, custom-hue slider (live), image upload —
  all propagating to the rail org circles, drawer rows and panel head. The
  org avatar stays a **circle** (reserved identity shape); rail org circles
  now carry the org hue/image (they were neutral before).
- **Members**: entry-point card only → Org members & grants.
- **Danger zone** (red-hairline card, last): rename slug with the URL
  warning; **delete organization** behind typed-name confirmation, inline,
  no browser confirm. Deleting really deletes in the demo: you land in your
  remaining org.
- **Zero-org empty state** (found by testing the delete): a persona whose
  last org disappears gets a "No organizations" surface (invitation hint,
  instance-admin shortcut to create one) instead of a crash — the brief's
  "delete your only org" open question, answered by construction.

Bug found & fixed in 13+14: `#toast{display:flex}` overrode the `hidden`
attribute — the toast was always visible (empty). `#toast[hidden]` rule
added.

Open questions carried to the map/spec (recorded, not decided here):
**the authorization atom for org settings** — locked #15's capability table
has no `org-settings`; the prototype gates on org admin; synthesis must
route the real atom (new capability vs manage-members) without silently
amending #15.

## Iteration 15 — project policy + danger zone (Marc)

"Project should also have danger zone, maybe other shared settings with
org?" The "other shared settings" turn out to be ADR-backed and were
missing: the **project-settings capability's actual contents** (#15).
Project settings now has five sections (Identity · Metadata · Policy ·
Access · Danger zone), symmetric with org settings:

- **Policy** (gated on the project-settings stand-in; dana sees neither
  Policy nor Danger zone): per-environment **protected flag** as toggle
  chips — protecting staging updates the matrix header live; **reveal
  reauth window** (protected always caps at 0: passkey per disclosure,
  #15/#16); **definitions_source db|git** with the read-only-UI
  consequence stated when git (#13).
- **Danger zone**: slug rename with URL warning; **delete project** behind
  typed-name confirmation. Deleting really deletes; deleting the last
  project lands on a **zero-project empty state** with a create shortcut
  for org admins (parallel to it14's zero-org state).

## Verdict — LOCKED (Marc, 2026-08-04)

Iteration 15 is the reference chrome for the UI spec. Decided across the
run: rail owns orgs (it4); instance surface in the v1 UI with CLI↔UI parity
(it4); grant modal = capability checklist (it5) with (?) explanations
(it11-12); account layout = sticky jump index (it7), generalized to every
sectioned settings surface (it9); shape = role scale, DESIGN.md amended
(it8, supersedes env-matrix-31's skin for the spec); project identity
custom hue + image (it10); critique fixes incl. AA+ faint tier, text+aria
errors, safe scope default, undo toasts (it13); org settings + zero-org
state (it14); project policy (the project-settings capability's contents)
+ danger zones + zero-project state (it15). definitions_source stays v1
(two locked ADRs bind the pipeline; formal confirmation at #26).

Carried out of the ticket: multi-instance management → #35 (blocks #26);
org-settings capability atom absent from locked #15 → synthesis (#27) must
route it. Cross-model passes: Codex placement audit (it8) + two-assessment
critique (it13).

## Iteration 16 — revision retention in settings (wayfinder #30 spillover)

Marc (during the revision-history prototype, #30): retention settings belong
here, not in the history drawer. Added on top of the locked iteration-15
reference chrome (15 stays the frozen base; this extends it):

- **Project settings › Policy › Revision retention**: inherit org default
  (follows org changes) or custom ≤ org — a custom value above the org is
  refused at set time (toast + revert); if the org later lowers its
  default, the custom value is shown "capped to N by the org" (red input),
  never rewritten.
- **Org settings › Policy** (new card, jump index updated): default
  revision retention ("new projects start here; projects still inheriting
  follow this value when it changes") + per-project state list
  (inherits → N / custom n / custom n — capped ⚠).
- Changes audited (#24 registry: retention-policy change). Concrete
  defaults → ops spec #32. Semantics decided in
  `prototype/revision-history/5/` (#30).

## Iteration 17 — sidebar hierarchy variants

Marc's nitpick on the panel: with the small indentation, top-level section
labels (`.stitle`) and sub-items (`.srow`) blur together at first glance.
Four CSS-only treatments on top of iteration 16, switchable via `?side=` +
floating bar (arrow keys cycle):

- **a — baseline**: iteration 16 untouched, for comparison.
- **b — breathing room**: inter-section padding 16 → 30px, nothing else.
  Marc's first idea; separation by whitespace alone.
- **c — mild separator**: a dull 1px bar, half the column wide, centered,
  above each section label (first section excluded). Marc's own sketch.
- **d — structural indent**: sub-items indented onto a hairline left rule
  (accent-colored on the active row); section labels stay flush left.
  Hierarchy by geometry instead of spacing — the one treatment that also
  scales when a section gets long.

All variants theme-safe (derive from `--line`/`--accent`). Verdict pending.

## Iteration 18 — variant e: b + d combined

Marc likes b (breathing room) and d (structural indent) both. Variant e
combines them: 30px inter-section spacing AND sub-items on the hairline
left rule with the accent active-row marker. Default view in iteration 18;
a–d kept in the switcher for side-by-side comparison. Verdict pending.

## LOCKED (2026-08-05): sidebar treatment e + retention UI

Marc's verdicts:

- **Sidebar hierarchy: variant e locked** (iteration 18) — 30px
  inter-section breathing room + sub-items on a hairline left rule with
  the accent active-row marker. This is the reference sidebar treatment,
  amending the iteration-15 reference chrome. UI-spec input: section
  labels flush; items `margin-left 19px · padding-left 13px · 1px rule at
  line/.75 · accent rule on active`; inter-section 30px (16px first).
- **Revision retention UI locked** (iteration 16) — project settings ›
  Policy › Revision retention (inherit org default / custom ≤ org,
  set-time refusal, capped-by-org state) + org settings › Policy card
  (org default stepper, per-project state list). Semantics per
  revision-history it-5: inherit-until-modified, org cap both ways,
  audited. The history drawer stays read-only (revision-history it-6).

Reference chrome for the UI spec = iteration 15 + the 16 retention
surfaces + the 18 sidebar treatment.
