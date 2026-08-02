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

## Verdict

_(pending — Marc reacts, iterate.)_
