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

## Iteration 2 — four structural approaches to digestibility

Marc's iteration-1 verdict: **information too dense**. Iteration 2 keeps every
ADR binding and varies the *presentation structure* — four views in one file,
switchable via `?view=` + floating bottom bar (arrow keys cycle):

- **a `?view=collapse` — collapsed timeline.** One line per revision
  (rev · actor · n keys · tags · age); keys, schema rev and actions appear
  only on the expanded row. Current revision starts expanded.
- **b `?view=panes` — list + detail.** Wider drawer split into a slim rev
  list and a detail pane for the selected revision; per-row buttons are gone
  entirely, changed keys become kind-tagged rows.
- **c `?view=story` — activity story.** Plain-language sentences ("marc
  rotated 🔒SESSION_SECRET"), grouped under today/this week/this month;
  actions revealed only on an opened card. Secret edits phrase as "rotated"
  (write-presence in words). Optimizes read-aloud-ability over density.
- **d `?view=page` — full-page history.** The matrix steps aside; roomy
  table (rev / who / when / what) with a detail band on the selected row.
  Directly answers iteration 1's drawer-vs-page open question.

Shared in all four: long ADR prose demoted to `(?)` tooltips (`TIP` map);
pin warnings shrunk to badges (⚠ holds payload / Δ drift) with the full
sentence behind the tooltip; restore preview gained a summary chip line
(n set / n clear / n blocked) with prose only on problem rows; diff footer
one line. Diff/restore/pin/publish/ceremony mechanics identical to it-1.

## Iteration 3 — panes wins + pin clarity

Marc's iteration-2 verdicts: **view b (list + detail panes) wins** — it is now
the single history surface (switcher and views a/c/d retired with it-2, which
stays frozen for reference). Second ask: **clarify what pinning does and how
it affects the values a workload receives.** Pin clarity is *visible text*,
never tooltip-only:

- **Pins section** carries a one-line definition: "a pinned workload stops
  following latest — it keeps receiving exactly the pinned revision's values,
  restarts included, until the pin is released or expires."
- **Each pin row** states the gap in a plain sentence: "api-server (k8s)
  still runs on r27's values — 2 publishes behind latest (r29). New publishes
  don't reach it." (Pinned-at-latest gets the forward-looking phrasing.)
- **Detail pane** of a pinned revision names its consumers: "⚲ api-server
  receives this revision's values instead of latest (r29) — until the pin is
  released or expires."
- **Pin-create sheet** leads with a "what pinning does" list (keeps exactly
  rN's values across restarts · new publishes stop reaching the workload ·
  values kept from retention clean-up · release/expiry resumes latest on
  next fetch, loudly) followed by a **"compared to latest" value summary**
  phrased from the workload's point of view — config keys show both values
  ("stays at true — latest: false"), secret keys show comparison only under
  reveal-history ("stays at an older value than latest"), write-presence
  otherwise; added/removed keys phrased as "won't have" / "keeps".
- `TIP.pin` tooltip rewritten user-first (freeze semantics before the
  durable-resource machinery).

Observed while testing: the 640px panes drawer covers the header's role
select at ~1200px viewports — fine in the prototype (the role picker is demo
chrome), but the real chrome (#29) should treat the history drawer's width
as a layout constraint. Carried to the UI spec notes.

## Iteration 4 — pin = workload binding

Marc's iteration-3 findings:

1. **"holds payload" is jargon.** Replaced everywhere with consequence
   language: badge → `⚠ sole keeper` (tooltip: past normal retention, values
   exist only because of this pin, releasing deletes them permanently); the
   pin row's gap sentence gains "r21 is past normal retention: its values
   survive only because of this pin"; and **releasing a sole-keeper pin now
   opens a confirm sheet** — "this permanently deletes r21's values" with
   the three consequences spelled out (only keeper · collected means no
   diff/restore/reveal, lineage stays · workload resumes latest) and a
   danger-labeled button ("release — delete r21's values"). Non-sole
   releases stay one-click with an outcome toast.
2. **Pinning the same revision twice makes no sense.** Root cause: the model
   never said what a pin binds. Now explicit — **a pin is a workload
   binding: at most one pin per (workload, environment)**. The pin sheet
   gains a workload picker (each option shows its current state: "pinned to
   r27" / "follows latest"); choosing an already-bound workload turns the
   sheet into a **move** ("api-server is currently pinned to r27 — this
   moves it to r25", button relabels, old pin replaced atomically, with a
   sole-keeper consequence note when the move collects the old revision);
   same-revision re-pin is a refused no-op with the reason ("a workload
   fetches exactly one revision"). Two *different* workloads pinning the
   same revision stays legal — separate rows. Quota counts pins, so a move
   never trips it.

**Domain consequence for the ADRs/spec:** ADR #11 defines a pin as "a stored
record with an owner, quota, expiry" but never fixes its uniqueness. This
iteration asserts `(workload, environment) → at most one pin`, re-pin = move.
Feed into the UI spec + #31 (workload surfaces); if the synthesis ticket
(#27) finds this contradicts a locked text, it reopens #11 rather than
silently resolving.

## Iteration 5 — retention inheritance (org → project)

Marc's ask: revision retention configurable **per org and per project**, with:

- new projects **inherit** the org default;
- a project that overrides **detaches** — later org changes don't rewrite it;
- projects still inheriting **follow** org changes;
- a project may **never exceed** the org value — refused at set time
  (inline error + disabled apply), and an org *lowering* **caps** existing
  overrides loudly ("custom 10 — capped to 8 by org ⚠") rather than
  rewriting or silently ignoring them.

Made feelable via the **⚙ retention sheet** (entry: the drawer head's
"values kept: last N revisions + pinned" line, which also badges
inherits-org vs custom):

- org stepper + per-project state list (inherits → N / custom n / capped),
  previewed live against the *staged* org value so propagation is visible
  before apply;
- this-project inherit/custom radio with the cap rule stated in place;
- apply re-renders the timeline so "collected" tags move live; widening
  gets the honest toast — **nothing comes back**, collected values are gone
  (ADR #11), the wider window applies from now on;
- retention changes audited (#24 registry: retention-policy change);
- read-only for non-admin roles (org default = org admin; project value
  rides `project-settings`, ADR #15).

Verified in-browser: org 6→8 → inherited projects follow to 8, custom 4
stays, custom 10 re-caps to 8, effective window widens (5 → 3 collected
rows); custom 12 > org 8 refused inline with apply disabled.

**Domain consequence for the ADRs/spec:** #15 already places #11's payload
policy under `project-settings` at project scope, and #32 owns the concrete
defaults. NEW here: the **org-level default**, **inherit-until-modified**
semantics, and the **org cap** (a project may never out-retain its org).
The cap is a real authority hierarchy consistent with #15's org→project
scope order. Feeds the UI spec, #32 (defaults + GC cadence) and #27; org
settings surface (#29's org policy section) gains the default-retention
entry. If synthesis finds locked text contradicting the cap, that reopens
the relevant ticket rather than resolving silently.

## Iteration 6 — retention moves to the settings surfaces

Marc's iteration-5 verdict: **retention settings belong in app-chrome's
settings surfaces, not the history drawer.** Applied:

- **Editing moved to `prototype/app-chrome/16/`** (a new iteration of the
  locked chrome family — published iterations stay frozen, 15 remains the
  base reference): project settings › Policy gains a **Revision retention**
  row (inherit org default / custom ≤ org, set-time refusal with toast +
  revert, capped-by-org state with red input border), and org settings
  gains a **Policy** card (default retention stepper — "new projects start
  here; inheriting projects follow" — plus the per-project state list:
  inherits → N / custom n / capped ⚠). Verified in-browser: org 6→8
  propagates to inheriting projects, custom stays, cap re-computes,
  custom 12 > org 8 refused with revert.
- **This drawer keeps a read-only line** — effective window, inherits-org /
  custom badge, "→ project settings" pointer — the history surface reports
  the policy, never edits it.

Placement rationale: the retention knob is `project-settings` /
org-policy authority (#15), same family as the reveal window and
`definitions_source`, which already live on those surfaces (#29 it-15).

## Verdict

_(pending — Marc reacts to iteration 6 + app-chrome 16)_
