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
