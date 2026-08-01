# PROTOTYPE — environment matrix UI (wayfinder ticket #20)

**Question:** does a side-by-side environment matrix communicate inheritance,
overrides, gaps, validation, and drift legibly?

**Run:** `./prototype/serve.sh` then open `/env-matrix/` — an iteration index
(works on phones via LAN). Each iteration is frozen at `env-matrix/<n>/`,
newest is LATEST; `/4/` is current. New iteration = copy the current top into
`env-matrix/<n+1>/index.html`, add an `<li>` to `index.html`.

Throwaway code — delete this directory once the ticket resolves; the answer
lives in the ticket's resolution comment and the map.

## Iteration 2 (current)

Round-1 verdict from Marc: **Cascade (C) wins**, editorial style rejected
project-wide, mobile-first is now a standing rule (see PRODUCT.md / DESIGN.md
at repo root, created this round via impeccable teach).

Single design now, Cascade evolved:

- **Dark default + light theme** (auto from `prefers-color-scheme`, ◐ toggles).
- **Mobile-first**: sticky key column, horizontally scrolling lanes, 44px targets.
- **Env show/hide chips** (also the density valve on phones; min 1 visible).
- **Collapsible groups**; collapsed header shows a comma-separated key list.
- **Tap any cell → bottom sheet**: provenance chain, state explanation,
  in-place edit (override here / edit value), clear override, mask/unmask.
- **Permission-gated reveal**: role simulator top right (admin / developer /
  viewer). No permission → no reveal button, but **write-only replacement**
  stays available. Production (protected) reveal shows a stand-in reauth
  confirm (real ceremony is ticket #21).
- **Mask vs secret** explained in the sheet: secret = key classification
  (values exist, hidden, reveal-gated); mask = per-env value state ("no value
  here, on purpose", blocks inheritance).
- **Local edits** get a draft dot + header counter (publish flow is #21).

Demo data unchanged: 58 keys, seeded finds (type violation, relative-URL
violation, required-unset in prod, masked-while-required, secret satisfied in
prod only via inheritance from staging).

## Decided during testing (Marc)

- **Origin visibility = sharp rule (b)**: config keys always show provenance;
  a secret cell shows provenance only where the viewer holds reveal for that
  env (uniform 🔒 pill otherwise). Secret-row drift tint only when the viewer
  can reveal every readable env. Rationale: a visible "prod inherits stg" plus
  reveal(stg) is prod plaintext — the comparison oracle ADR #11 closes.
- **Whole environments hideable per principal**: no read(env) → env
  nonexistent (no column, chip, counts) — permission ADR #15 already locks
  this (unauthorized ≡ nonexistent). `external` role demonstrates.

- **"Masked" renamed "excluded" in the UI** (iteration 5): "mask" reads as
  "present but hidden" (masked ball), colliding with secret ••••. UI now says
  `∅ excluded` / "exclude here" / "include again". The ADR domain term stays
  `masked` (#10 locked); the synthesis ticket (#27) must reconcile naming —
  either a glossary mapping or a mechanical rename across the spec set.

## Iteration 8 — app-shell variants

Desktop full-width question: three shells around the identical matrix,
`?variant=a|b|c` + floating switcher (arrow keys), all collapsing to a
hamburger drawer on mobile:

- **A Sidebar** — 250px panel: project switcher, group links with problem
  badges (tap scrolls to the group), views (problems, drafts → publish).
- **B Centered + jump bar** — no sidebar; content capped at 1240px,
  horizontal group-jump pills with problem counts.
- **C Rail + panel** — 56px project icon rail + 210px group panel.

Projects list is demo-only (switching changes the crumb, not the data).

## Iteration 23 — json keys: multiline editor + schema validator

Marc flagged the gap: the json type from the schema grilling (#12, locked
ADR) was absent — the create sheet listed it but nothing implemented it.
Now per ADR #12's "binding on #20/#21" list:

- two demo keys: `FEATURE_FLAGS` (config json, schema: flags → booleans,
  staging invalid) and `GCP_SERVICE_ACCOUNT` (secret json, required props +
  additionalProperties:false, dev invalid via a pasted extra property);
- JSON Schema lives inline on the key; the sheet's schema disclosure shows
  it pretty-printed;
- cells render a compact one-line preview (whitespace collapsed, 42-char
  cap); the sheet view pretty-prints; edit mode is a multiline textarea
  (⌘/Ctrl+↵ saves, Enter stays newline) — same in the create sheet, which
  grows the value field when type=json;
- validator: JSON.parse first, then a tiny checker over the demo profile
  (type/required/properties/additionalProperties/enum). Config errors name
  the instance path (`/beta: expected boolean, got string`); secret errors
  redact instance-derived data — schema-keyword info only ("unexpected
  property — instance details redacted"), per #12's disclosure rule that
  errors never echo a secret, including through paths.

Not prototyped (noted, not forgotten): union editor (`any_of`), visible
trim, near-miss warning — smaller #12 bindings, fold into #21 or a later
iteration on demand.

## Iteration 22 — pencil affordance locked (Marc)

Decision: **pencil** — every editable slot (values, secret dots, absent)
carries a faint trailing ✎, accent on hover. The switcher, the ?cell=
param and the underline/well/baseline options are removed. Exception
states keep their exclusive border chrome.

## Iteration 21 — cell-affordance options (Marc: underline too subtle)

Four selectable strengths, cycle with the bottom-right "cell:" pill or
?cell= (composes with ?variant=):
- underline — iteration 20's dotted underline
- well — filled input-slot background
- baseline — solid bottom edge, spreadsheet feel
- pencil — trailing ✎ glyph
Winner becomes the fixed style in the next iteration. Shell selection
removed in-place (Marc): rail + panel (C) is the shell; the A/B switcher,
its keyboard cycling and CSS are gone, ?cell= is the only param.

## Iteration 20 — editable-slot underline (Marc)

Iteration 14's plain text stopped reading as input fields. Values carry
the inline-edit convention now: 1px dotted underline in faint text color
(accent on hover), same treatment on a widened absent slot — visible on
mobile where hover does not exist. Border chrome stays reserved for
missing/invalid.

## Iteration 19 — normalize (critique issue 5)

One .btn vocabulary (sheet actions, reveal, empty-state CTAs — three
duplicate rule-sets deleted). One badge rule: pending/error counts render
only when non-zero. The problems view is a real filter: total badge,
active state, matrix reduced to problem keys (empty groups skipped),
"no problems" state with a show-all escape, cleared on project switch.

## Iteration 18 — empty state + real projects (critique issue 2)

Per-project key store: envweave-demo is seeded, the other projects start
empty and keep whatever you declare (drafts/reveals clear on switch).
Empty project shows a first-run state: what the matrix is, a primary
"declare first key" (the create sheet gains a group field when no groups
exist), and an "import from .env" stub pointing at the locked scaffold →
review → apply → import flow (#13).

## Iteration 17 — polish pass

Unified :focus-visible ring on every control; key names truncate inside a
flex span so the req badge always survives; monogram hues assigned by
golden angle (no near-identical projects); light-theme zebra strengthened;
icon buttons fixed-width for optical equality; env picker button reaches a
32px target; inline SVG favicon kills the last console error; dead pill
CSS (own/inh/def/masked) removed.

## Iteration 16 — clarify pass (critique issue 3 + copy sweep)

Reveal gets real button chrome ("reveal value" / "hide value") — the most
security-relevant action no longer has the least affordance. Confirm
dialogs name the action and consequence ("Reveal the production value of
X? Re-authentication would be required…"). Validation messages are human
with examples ("must be a whole number, e.g. 8080" — seeded demo data
matched). Icon buttons (? ◐ ☰ envs) carry aria-labels; the sheet dialog
is labelled.

## Iteration 15 — distilled sheet (critique issue 4)

The cell sheet's one job is see/change this value. Removed: the permanent
no-inheritance/secret teaching paragraph (the header "?" legend owns
vocabulary), the redundant close button (backdrop, Escape, grab), and half
the hint copy. Required-in is now a one-line "schema · required in …"
disclosure that expands to the checkboxes and stays open while editing.
Create and publish sheet explainers trimmed to one line each.

## Iteration 14 — distilled cells (critique issue 1)

Border chrome reserved for exceptional states: ordinary set values render
as plain mono text (hover tint + focus ring keep the affordance), absent
stays a faint dot, secrets are dim masked dots without a per-cell lock
(the key column already carries 🔒). Pills survive only for missing and
invalid — 228 bordered elements down to 4 on the demo screen. Legend
updated to match.

## Iteration 13 — drawer backdrop + mobile project select

Marc's mobile findings: (1) tapping outside the open drawer fell through
to the matrix and opened a cell sheet — a backdrop now sits behind the
drawer and swallows the tap, closing the drawer; Escape closes it too.
(2) Variant C on small screens hides the rail, leaving no project
switching — the panel now tops with a project <select> styled via the
customizable-select API (appearance:base-select + ::picker(select)),
falling back to a plain styled select where unsupported. Shown only
below 700px on variant C.

## Iteration 12 — zebra rows, drift tint removed

Every other data row gets a lightly raised hue (both themes; the sticky
key cell gets a solid variant so horizontal scroll stays clean). The
amber drift tint on differing-value rows is removed entirely (Marc),
along with rowDiff/secretDriftVisible — no cross-env difference signal
remains in the grid.

## Iteration 11 — legend as header tooltip

The footer legend duplicated screen space (Marc) — moved into a "?" icon
popover in the header, same pattern as the env picker.

## Iteration 10 — env picker in header

The env chips bar duplicated the column header row (Marc) — removed.
Show/hide is now an "envs n/m ▾" checkbox popover anchored to the sticky
corner cell of the matrix header.

## Iteration 9 — rail + panel de-duped

**Standing convention (Marc): every change is a new numbered iteration —
never mutate a published one.**

Refinement (Marc): rail + panel leads, but rail and panel must not both
list projects — the rail owns switching, the panel navigates inside the
current project (its name as header + groups/views + a settings entry).
Rail avatars are two-letter monograms with a per-project hue; a letter is
not enough at scale ⇒ **project-level configuration (icon/avatar, access,
metadata) recorded as map fog, to be prototyped in a later ticket.**

## Iteration 7 — publish, required-in, create sheet

On top of the flat model: key creation in the bottom sheet (same design
language as editing); publish review sheet (per-env atomic revision with
r-number, selective publish, protected-env confirm, veto when an env has a
violation or missing required key); per-key required-in editor (cell sheet +
create sheet), changes counted as schema drafts riding the same publish.
Iteration 6 is frozen at the bare no-inheritance trial.

## Trialing in iteration 6 — NO INHERITANCE (major, reopens ADR #10)

Marc's direction (2026-07-31): drop cross-env inheritance AND the
project-defaults layer. Flat model: every value explicit per environment;
value states collapse to `set | absent` (the excluded/masked state has
nothing left to block). Ergonomics instead of inheritance:

- key creation takes a first value + checkboxes for which envs receive it;
- per-cell "copy to…" pushes a value into chosen envs (secret copy gated on
  reveal of the SOURCE env, per ADR #15 disclosure-by-proxy; copying into a
  protected env asks confirmation);
- secret-row drift stays gated (still a cross-env comparison oracle).

**Not locked.** This supersedes ADR #10 (and #7's base pointer +
project-defaults layer) and touches the competitive wedge (#2 lists
inheritance as a differentiator). Formal path: amendment ADR + blocking
cross-model grill, then ripple check over #12/#13/#15 references
(group-closure layers, bundle topology, base re-parenting formula — all
simplify or die). Until then iterations 4/5 remain the locked-model
prototypes.

## Trialing in iteration 5 (not yet decided)

- **Opaque inheritance**: grid shows only resolved values (uniform pill, no
  `◂ origin`, no base arrows anywhere); provenance appears only in the cell
  sheet, still under the sharp rule. Trade being felt: calmer grid and no
  confusion, versus losing at-a-glance "which cells are overrides" scanning.
  Compare against `/4/` which keeps origins in-grid.
- **Sticky header row + sticky group headers** while scrolling (the matrix
  scrolls inside a fixed-height container now; key column sticky as before).

## Verdict

_(fill in when the ticket resolves)_

- Cell-state visual language:
- Origin explanation mechanism:
- Density at 58 keys × 4 envs (desktop + phone):
- Add-key flow:
- Mask-vs-secret presentation:
- "Required satisfied only by inheritance" as a distinct signal?
