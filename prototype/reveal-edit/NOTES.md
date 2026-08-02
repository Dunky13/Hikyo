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

## Iterations 2-5 — DROPPED (Marc, 2026-08-02)

Style-direction exploration (Geist/Linear/Doppler theming + a style
switcher). Verdict: **wrong axis** — "that's just theming; I was looking
for unique approaches in the reveal modal." Dirs deleted (live in git
history before d9695e6); original env-matrix-31 theming restored.
Numbering continues at 6 so ticket comments referencing 2-5 stay
meaningful.

## Iteration 6 — reveal approaches (structural, original theming)

Four structurally different shapes for the reveal interaction, switchable
live (`?reveal=`, floating bar, arrow keys). Publish/copy ceremonies stay
modal in every mode; permission checks identical.

- **a · ceremony modal** — iteration 1 baseline: centered purpose-bound
  modal, window on success, protected = passkey-only.
- **b · inline popover** — the same ceremony as a small card anchored at
  the reveal button; no scrim, the value appears where you're looking.
- **c · hold-to-reveal** — press-and-hold a masked cell: value visible
  only while held, release = instant remask (no timer at all). Ceremony
  precedes the first hold; protected grants one 10s hold per ceremony.
- **d · session drawer** — an explicit "disclosure session": authenticate
  once in a right-side drawer, every revealed value is listed there with
  countdowns and per-key hide, one "end session" re-masks everything.
  Protected values still take their own per-reveal ceremony.

## Verdict (locked 2026-08-02, Marc — ticket #21 resolved)

**Approach a — the ceremony modal — wins.** Inline popover (b),
hold-to-reveal (c) and the session drawer (d) rejected. Full interaction
notes in the ticket's resolution comment. Kept runnable: `1/` (baseline
interactions) and `6/` (approach comparison); theming stays the frozen
env-matrix-31 language.

Decided set: purpose-bound ceremony modal (passkey/TOTP, enumerated key
set, disclosure-vs-account-step-up distinction); sliding reveal window
with visible countdown (window gates the prompt, never the check);
protected environments cap the window at 0 ⇒ passkey per disclosure, no
TOTP; short auto-remask with visible countdown (value = project
setting); clipboard = audited disclosure incl. copy-without-display,
best-effort clear + honest OS caveat; row editor for one-key-across-envs
(empty field = unchanged); live inline validation; publish and
copy-into-protected run the same enumerated-key ceremony; one audit
event per disclosed key.
