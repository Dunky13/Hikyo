# Product

## Register

product

## Users

Self-hosting developers first (homelab operators, 1-3 orgs, up to ~25 users), platform engineers second (from positioning ADR #3). They live in terminals and dashboards, administer their own infrastructure, and reach this UI from a desk during the day and from a phone or tablet on the couch or in the server closet at night. The job on any screen: see the whole configuration surface across environments at a glance, spot gaps, violations and drift, and change values safely.

## Product Purpose

Wenv is a fully open-source, self-hosted control plane for validated, inherited secrets and configuration across environments (Docker Compose and Kubernetes first-class). The environment matrix is the product's signature surface. Success: an operator trusts it enough to manage production secrets in it, and understands every resolved value's origin without reading docs.

## Brand Personality

Precise, calm, trustworthy. The quiet confidence of good infrastructure tooling: no drama, high signal, nothing decorative that isn't also informative. Secrets handling should feel deliberate, never gamified.

## Anti-references

- Editorial/serif print aesthetic (tried, explicitly rejected for this project).
- Generic cloud console (AWS-style gray chrome, wall-of-tables sameness).
- AI-slop dark mode: neon accents, purple-blue gradients, glassmorphism, glow.
- Enterprise security theater: badge walls, shield icons, fear-based copy.

## Liked references

- Infisical's environment/field arrangement (structure, not styling).
- Linear/Tailscale-class product calm.

## Design Principles

- Mobile-first, always. Every prototype and every surface must work well on a phone; density features (env hide/show, group collapse) are how the matrix earns its room on small screens.
- State is never color-only. Every matrix state carries a glyph or text alongside its color.
- Provenance is one gesture away. Any resolved value can explain where it came from (defaults, base chain, or here) without leaving the screen.
- Disclosure is a ceremony. Revealing a secret is deliberate, permission-gated, and auto-remasks; editing without reveal (write-only) is a first-class path.
- Dense but calm. 50+ keys by 4+ environments must stay scannable; rhythm and grouping over chrome.

## Accessibility & Inclusion

WCAG AAA-leaning: body text contrast targets 7:1, large text 4.5:1; full keyboard navigation; reduced-motion respected; state signals readable without color perception; touch targets 44px+ on mobile.
