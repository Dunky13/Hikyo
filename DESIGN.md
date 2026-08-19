# Design

Seed DESIGN.md (pre-implementation). Re-run `/impeccable document` once real frontend code exists.

## Theme

Dual theme, **dark default** (self-hosters at night, server closets, OLED phones), light fully supported and switchable; respect `prefers-color-scheme` when no explicit choice. Dark is desaturated graphite tinted toward the brand teal: never neon, never glow.

## Color

OKLCH throughout. Restrained strategy: tinted neutrals + one teal accent, state colors as a small fixed vocabulary.

Dark (default):

- `--bg` oklch(0.19 0.012 220) surface
- `--bg-raise` oklch(0.23 0.014 220) raised rows/sheets
- `--line` oklch(0.34 0.016 220) hairlines
- `--tx` oklch(0.93 0.008 200) primary text (≈13:1 on bg)
- `--tx-dim` oklch(0.76 0.01 210) secondary (≈7:1)
- `--accent` oklch(0.82 0.09 195) interactive teal; text on accent uses oklch(0.2 0.02 220)

Light: linen-tinted paper oklch(0.965 0.008 200), ink oklch(0.25 0.03 225), same accent hue at oklch(0.45 0.085 210).

State vocabulary (always paired with a glyph, never color-only):

- set-here: filled accent pill
- inherited: outline pill + `◂ origin`
- from-defaults: tinted pill + `◂ def`
- masked: hatched pill + `∅`
- missing/violation: red-family oklch(0.72 0.13 25) dark / oklch(0.48 0.14 30) light, + `!` or `✕`
- changed: `Δ` in blue-violet-free slate oklch(0.78 0.07 250)

## Typography

- UI: Archivo (400/500/700). Headings weight-contrast over size-inflation.
- Keys & values: IBM Plex Mono, 12-13px, tabular feel.
- Body line length ≤ 72ch. Scale ratio ≥ 1.25.

## Shape & Space

- **Radius carries a role** (decided app-chrome iteration 8, ticket #29): containers/cards 6px; controls (buttons, inputs, selects) 4px; badges/tags/chips 3px.
- **The 999px pill is reserved** for exactly three things: identity circles (org and account avatars), count badges, and the matrix cell-state vocabulary. Nothing else is a pill.
- Hairline borders (1px) over shadows; shadows only on overlays (bottom sheet).
- Density: matrix rows ~36px desktop, ~44px touch targets mobile.

## Motion

- 150-220ms, ease-out-quart. Transform/opacity only.
- Bottom sheet slides up; group collapse animates via grid-template-rows.
- `prefers-reduced-motion`: transitions off.

## Components

- Environment chips: toggleable visibility, show base-chain arrow and protected badge.
- Cell pills: the state vocabulary above.
- Bottom sheet: single editing/inspection surface (provenance chain, value editor, mask/clear/reveal actions), same component desktop and mobile.
- Group headers: collapsible; collapsed state shows comma-separated key names.
