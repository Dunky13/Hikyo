# Envweave — UI & Interaction Specification (synthesis, 2026-08-06)

Binds the design system ([DESIGN.md](../../DESIGN.md) — dual theme dark-default, OKLCH tokens, AAA-leaning accessibility, state-never-color-only), the five locked reference prototypes, and the UI obligations the ADRs delegated to synthesis. The prototypes are the reference for structure and interaction shape; DESIGN.md is the reference for visual language; the owning ADR is the reference for semantics. The 1.0 gate's S3 criterion ([mvp-boundary.md](../adr/mvp-boundary.md)) requires a closed flow registry with one Playwright flow each and the pinned assertion set (axe-core serious/critical = 0, ARIA text with color stripped, focus indicators, contrast ≥ 4.5:1, touch ≥ 44 px, computed styles vs DESIGN.md tokens).

## Reference prototypes (locked; frozen under `prototype/`)

| Surface | Reference | Ticket |
|---|---|---|
| Environment matrix (signature surface; flat model trialed and adopted here) | `prototype/env-matrix/` iteration 31 | [#20](https://github.com/Dunky13/envweave/issues/20) |
| Secret reveal, masking & multi-env editing — **ceremony modal**; validation-error presentation; write-only replacement; change review & confirm | `prototype/reveal-edit/` iteration 6 | [#21](https://github.com/Dunky13/envweave/issues/21) |
| App chrome — organisation, account & access surfaces (incl. `definitions_source` select + read-only consequence) | `prototype/app-chrome/` iteration 15 | [#29](https://github.com/Dunky13/envweave/issues/29) |
| Version history & rollback — list + detail, write-presence-only secret signals, others'-pending markers, least-blast restore preview, pins | `prototype/revision-history/` iteration 6 | [#30](https://github.com/Dunky13/envweave/issues/30) |
| Workload integration & machine-identity surfaces — write-only credential list, display-once mint, grant-mutation warning, federation management, restore reconciliation, K8s CR-condition vocabulary | `prototype/machine-access/` iteration 3 | [#31](https://github.com/Dunky13/envweave/issues/31) |

## ADR-delegated UI deltas (carried by synthesis)

**GitHub adapter** ([github-adapter.md](../adr/github-adapter.md)) — the adapter-configuration surface locked at #31 extends with the GitHub-only knobs: destination-kind picker (repo / org / repo-environment), org-visibility control enforcing the recipient-set widening rules (plain narrowing only `all→private`, `all→selected`, id removal; everything else runs the routing-mutation ceremony), environment-auto-create consent explicitly naming the Administration:write scope, GHES base-URL field carrying the best-effort statement, and the `possible_capture` / `owned, missing` finding surfaces in sync status.

**Secret scanning** ([secret-scanning.md](../adr/secret-scanning.md)) — finding presentation rides the locked editing surfaces (#21 reveal/edit, #29 chrome): S1 config-value warning is non-blocking with reclassify-as-secret primary action and sticky-dismissal secondary; S2 declaration block presents the finding (rule ID + locator, never matched text) with the content-bound acknowledgement flow. Microcopy stays within DESIGN.md's calm register — no security theater.

**SCIM** ([scim-provisioning.md](../adr/scim-provisioning.md)) — binding admin, mapping authoring (blast warning at authoring time), origin chips per capability line on grant views, deprovision attention flag on accounts with surviving manual grants.

**SAML** ([saml-sp.md](../adr/saml-sp.md)) — provider configuration on the existing instance-config surface; metadata fingerprint ceremony at trust establishment; diff-and-confirm on metadata refresh.

**Multi-instance** ([multi-instance.md](../adr/multi-instance.md)) — the delegated UI states. *Directory entries*: reachable (version, org/project names + counts) · unreachable (last-known snapshot shown with its staleness timestamp, marked stale, never silently fresh) · pin-mismatch (marked, not served) · duplicate instance identity (both entries marked, neither served) · self-connection (refused at add, by instance identity). *Workspace*: connect = the popup ceremony on the remote's origin (never embedded); "session expired — reconnect" as a one-click state re-opening the popup; step-up re-opens the popup and runs the remote's own ceremonies (the workspace session never substitutes); origin-removal and every locked invalidation trigger surface as the expired state. Live updates in a workspace degrade to polling — no push affordance is promised.

## Git-mode definitions state ([source-of-truth.md](../adr/source-of-truth.md))

When `definitions_source: git`, definition-editing surfaces are read-only with a persistent banner: **"Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`."** A blocked edit explains itself with that sentence plus the last-applied provenance labels (commit/ref/actor) when present — labels are display-only, never trusted. Envweave stores no repository URL (it never reads a repository), so the banner names the mechanism, not a repo link.

**Declaration authoring statement** (every declaration ingress, both modes): free-text declaration fields (descriptions, enum labels, schema annotations) are **exported to Git in definitions bundles and are to be treated as public — never paste secret values**. This is the UI restatement of the bundle's documentation-class guarantee; the structural backstop is S2 scanning.

## Key declaration & schema editing requirements

These behaviors are locked by the schema ADR; visual treatment follows DESIGN.md (no separate prototype was run — recorded in [open-items.md](./open-items.md)):

- **Multiline `string`** editing (interior newlines are legal) — the value editor grows; never silently strips newlines.
- **`any_of`** editing as free text with alternative hints, not a forced chooser.
- **Near-miss warning** on key creation (small edit distance to an existing key), non-blocking.
- **Visible trim** on save: when Unicode TrimSpace altered the value, say so; whitespace-significant values are refused knowingly, not silently trimmed into validity.
- **Owner-only invalid-draft marker**: advisory validation verdicts on secret drafts render only to the draft's owner (the predicate channel is a disclosure).
- **Deprecation warning** on keys pending deletion with live occurrences; **shared-secret-default** and **post-tightening-history** advisories ("tightening cannot un-disclose; rotate") at the moments the schema ADR names.

## Interaction invariants (restated)

Disclosure is a ceremony (permission-gated, auto-remask, write-only editing first-class); provenance one gesture away; density features (env hide/show, group collapse) are how the matrix earns phone screens; every state carries a glyph or text beside its color; reveal windows and reauth prompts follow [permission-model.md](../adr/permission-model.md) and the ops-spec values.
