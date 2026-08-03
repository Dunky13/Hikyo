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

## Verdict

_Pending Marc's pass — record per-surface decisions here, then fold into the
ticket resolution._
