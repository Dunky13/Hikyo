# PROTOTYPE — environment matrix UI (wayfinder ticket #20)

**Question:** does a side-by-side environment matrix communicate inheritance,
overrides, gaps, validation, and drift legibly?

**Run:** `open prototype/env-matrix/index.html` (or any static server).
Switch variants with the floating bar, `←`/`→`, or `?variant=a|b|c`.

Throwaway code — delete this directory once the ticket resolves; the answer
lives in the ticket's resolution comment and the map.

## Variants

| Key | Name | Structure |
|---|---|---|
| `a` | Ledger | Editorial print. Full dense spreadsheet; origin as superscript footnote glyphs; sticky provenance footnote bar explains the hovered cell's layer chain; summary tally in the masthead. |
| `b` | Panel | Industrial dark master–detail. Left: key list with a 4-square per-env state strip. Right: per-env sections with the full defaults→base→env origin chain rendered per environment. Search + problems-only filter. |
| `c` | Cascade | Inheritance-first lanes on linen. Columns ordered along the base chain; every inherited cell is a ghost pill pointing `◂` at its origin; drift rows tinted amber. |

## Shared semantics (from locked ADRs #10/#11/#12)

- Layers: project-defaults → base chain → environment, nearest-ancestor-wins.
- Value states: set / absent / **masked** (deliberately unresolved).
- Required + (absent|masked) = publish-blocking violation; schema violations shown per cell.
- Δ = changed since last published revision; ≠ = resolved values differ across envs.
- Secrets (§) masked by default; click reveals with auto-remask; production
  (protected flag) throws a stand-in reauth confirm — real ceremony is ticket #21.
- Demo data seeds deliberate finds: `DB_POOL_SIZE` staging = "ten" (type violation),
  `OIDC_ISSUER` preview relative URL, `OIDC_CLIENT_SECRET` required in prod but only
  set in staging (satisfied via base-chain inheritance — a footgun worth discussing),
  `S3_SECRET_ACCESS_KEY` masked-while-required in prod (blocks publish),
  `SMTP_PASSWORD` masked in dev.

## Verdict

_(fill in when Marc has reacted — which variant, or which pieces of which)_

- Winning cell-state visual language:
- Origin explanation mechanism:
- Density at 58 keys × 4 envs:
- Add-key flow:
