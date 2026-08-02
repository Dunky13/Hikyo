# PROTOTYPE — reveal, masking & multi-env editing (wayfinder ticket #21)

**Question:** how do reveal, masking, clipboard, and editing-across-environments
actually behave — the reveal ceremony, write-only replacement vs revealable
editing, editing one key across several environments in one motion, inline
validation, and the change-review step before save for production?

Sibling of `prototype/env-matrix/` (frozen at iteration 31, the reference
design from ticket #20). Same shell and matrix; only the interactions this
ticket owns are new.

**Run:** `./prototype/serve.sh` then open `/reveal-edit/` (works on phones via
LAN). Every change is a new numbered iteration — published ones never mutate.

## Iteration 1

ADR bindings made feelable (timings compressed and labeled in-UI):

- **Reauth ceremony** (ADR #15 + #16): purpose-bound modal (`reveal · production`),
  enumerated key set ("one decision over exactly the keys below"), passkey or
  TOTP. Explicitly framed as *disclosure* reauth, distinct from
  account-security step-up.
- **Sliding reveal window** (ADR #15): success in a non-protected env opens a
  90s window (stands in for a project-settings value like 15 min), counted
  down as a header chip. While it runs, non-protected disclosures skip the
  prompt — the window gates the prompt, never the permission check.
- **Protected cap = 0** (ADR #15 flag caps the window; ADR #16 TOTP cannot
  honour a zero window): production reveals take a passkey ceremony every
  time, grant no window, and the TOTP option disappears.
- **Auto-remask**: revealed values re-mask after 10s with a visible `↺Ns`
  countdown on the cell, the sheet button, and the row editor.
- **Clipboard = disclosure** (ADR #15 disclosure-by-proxy): copying a secret
  is gated and audited exactly like reveal — including *copy without
  display* from the masked state. Best-effort clear after 45s with honest
  microcopy (the OS may keep clipboard history). Non-secret copy is free.
- **Row edit — one key across all envs in one motion**: click a key *name*.
  One field per environment (protected rows outlined), fill-all shortcut,
  write-only replacement placeholders where reveal is missing, per-field live
  validation, per-env reveal/copy inline. Changed fields save as per-env
  drafts; publish stays the gate.
- **Live inline validation** while typing, in both the cell editor and the
  row editor (same anchored-pattern / typed rules as iteration 31; secret
  json errors stay schema-located, never instance paths — ADR #12).
- **No browser confirm() left**: publish-to-protected and copy-into-protected
  run the same ceremony, enumerating exactly the keys the decision carries.
- **Per-key audit toasts** (ADR #15: one event per disclosed key, never
  "revealed 40 secrets") — every reveal / copy / copy-into emits one.

## Decisions confirmed (Marc, 2026-08-02)

- **Remask default stays short** (10s-class): the exact value becomes a
  project setting later (ops-spec fog owns the default).
- **Row editor: empty field = unchanged** — no per-row clear affordance;
  clearing a value stays a per-cell action.
- **Clipboard microcopy keeps the honest caveat** ("cleared in 45s if this
  tab stays focused — the OS may keep clipboard history").

## Iterations 2-4 — style directions (Marc: "1 feels non-professional")

Three deliberately different surface languages over the SAME interaction
set, modeled on reference dev-tool design schools. Interactions and the
locked #20 structure (rail+panel, matrix, centered modal, pencil) are
identical in all three — only the design language varies. Common to all
(fixed in 2, inherited by 3/4): color emoji replaced by currentColor SVG
icons + masked SVG pencil; UI copy stripped of ADR citations and lecture,
one styled "prototype" footnote carries demo caveats; TOTP placeholder no
longer letter-spaced; toasts bottom-right, compact; passkey wait is a
progress bar, not a pulse.

- **2 "Instrument" — Geist/Vercel school**: flat precision. 4-6px rect
  chips, uppercase state labels, hairline borders, 36px button scale
  (44px touch on mobile), teal accent kept from DESIGN.md.
- **3 "Layered" — Linear school**: violet-slate 3-step elevation ladder,
  iris accent, hover-row highlight replaces zebra, blurred scrim + one
  deep soft shadow, 16px overlay radius, `kbd` caps for shortcuts.
- **4 "Ops console" — Doppler/HashiCorp school**: full table semantics
  (row gridlines, faint column separators, 2px header rule), ~30px rows,
  uppercase env headers, filled PROTECTED chip, neutral console grays,
  sober blue accent, 2-4px radii.

The winner (or the steal-list across them) updates DESIGN.md and becomes
the reference for the UI spec.

## Iteration 5 — style switch

2/3/4 folded into one file for side-by-side judging: floating bottom bar,
`←`/`→` arrow keys, `?style=instrument|layered|console` (shareable,
reload-stable). Style deltas live as `body[data-style]`-scoped CSS over
the Instrument base; interactions identical in all three. The switcher
bar is deliberately styled outside the design system — prototype chrome,
not part of what's being evaluated.

## Verdict

_(pending — Marc flips styles in 5, picks or mixes, then lock.)_
