# PROTOTYPE — environment matrix UI (wayfinder ticket #20)

**Question:** does a side-by-side environment matrix communicate inheritance,
overrides, gaps, validation, and drift legibly?

**Run:** `./prototype/serve.sh` then open `/env-matrix/` (works on phones via LAN).

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

## Verdict

_(fill in when the ticket resolves)_

- Cell-state visual language:
- Origin explanation mechanism:
- Density at 58 keys × 4 envs (desktop + phone):
- Add-key flow:
- Mask-vs-secret presentation:
- "Required satisfied only by inheritance" as a distinct signal?
