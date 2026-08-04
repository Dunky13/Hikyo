# PROTOTYPE — version history & rollback (wayfinder ticket #30)

**Question:** how do per-environment revision history, diffs, pins, and
rollback actually look and behave?

Sibling of `prototype/env-matrix/` (frozen, flat model) and
`prototype/reveal-edit/` (ceremony modal, #21 verdict). Same shell; only the
history surfaces this ticket owns are new.

**Run:** `./prototype/serve.sh` then open `/revision-history/`. Every change
is a new numbered iteration — published ones never mutate.

## Iteration 1 — history drawer

Revision-ADR (#11) bindings made feelable:

- **Entry point:** `rev N · history` badge in each env column header (and the
  sidebar's per-env history rows). A key name click opens the same drawer
  **filtered to that key** — per-key history is a filter, not a second surface.
- **Timeline** (right drawer, per env with env tabs): monotonic r-numbers,
  actor, age, changed-key list (🔒 marked), pinned schema rev per publish.
  Lineage is permanent; **payloads keep last 6 + pinned** (demo values — ops
  spec #32 owns the real ones). Collected revisions stay in the timeline with
  a `payload collected` tag; diff/restore buttons are disabled with the
  policy named, and "why unavailable?" fails loud: no replay-from-metadata.
- **Secret-safe diffs** (centered modal, from/to pickers over retained revs):
  config = plaintext old→new; secret **without reveal-history = write-presence
  only** (edited/added/removed — never whether plaintext differs; comparison
  status is the guessing oracle); **with reveal-history = changed/unchanged**
  plus a per-key "reveal both sides" ceremony, audited with the revision read.
  The **auditor role** (history, no current reveal) makes the independence of
  the two grants feelable; the **developer role** (reveal, no history) shows
  the degradation.
- **Restore** = new revision through the normal publish pipeline. Preview
  stages per-key `set` / `clear` against the published state (**flat model:
  no mask machinery** — the inheritance ADR's mask asymmetry died with
  inheritance; flagged for the amendment ADR). Re-validates against the
  **current** schema: r≤24's `DB_POOL_SIZE='ten'` fails the s12 tightening,
  blocks loud naming the key, and offers an explicit inline resolution.
  Restoring an earlier **secret** occurrence needs reveal-history (refused
  loud, keys named, never silently split). Staged changes land as ordinary
  drafts (draft dots in the matrix), publish runs the #21 enumerated-key
  ceremony for protected envs. Per-key restore from any diff row.
- **Pins**: durable owned quota-bounded (5/project demo) expiring resources.
  Pin **non-current** ⇒ reveal-history + ceremony (disclosure by proxy). Pin
  onto a revision failing the current schema ⇒ explicit **recorded** override,
  surfaced as drift afterwards. A pin holding a payload past the retention
  window is flagged as the reason with a release action.
- **Others' pending drafts**: quiet outline dot in the matrix (sam @ staging),
  summarized in the drawer header — visible before publish, quieter than
  your own solid draft dot.
- **Δ recently-changed**: cells touched by the last published revision carry
  Δ with "changed in rev N" and degrade to write-presence without reveal.

Demo compressions labeled in-UI: retention 6, pin expiry 30d, reveal window
90s. Value *editing* is out of scope here — that's #21's locked surface.

## Open questions for Marc (iteration 1 → 2)

1. Drawer vs a full-page history view — is a 440px drawer enough room for
   diffs, or should "diff" take over the matrix area?
2. Timeline actions per row (diff/restore/pin) vs a single "open revision"
   detail — too many buttons per row?
3. Should the restore preview live inside the drawer instead of a modal?
4. Pin creation: worth a workload picker, or is pinning always done from the
   workload/integration side (#31's surface)?

## Verdict

_(pending — Marc reacts to iteration 1)_
