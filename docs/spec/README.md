# Envweave — Specification handoff (the destination of wayfinder map [#1](https://github.com/Dunky13/envweave/issues/1))

This is the build-ready specification set for Envweave 1.0: a fully open-source, self-hosted control plane for validated secrets and configuration across environments, Docker Compose and Kubernetes first-class. Synthesized 2026-08-06 at ticket [#27](https://github.com/Dunky13/envweave/issues/27) from 26 locked ADRs, 5 locked prototypes, and the map's ticket resolutions.

## How this set works

**The ADRs are canonical.** Every decision lives in exactly one locked ADR (or ticket resolution); this spec layer indexes, synthesizes across, and discharges what the ADRs delegated to synthesis — it never restates a decision at length, and where any wording here diverges from an ADR, **the ADR wins and the contradiction reopens the owning ticket** (the standing synthesis rule; never patch silently).

**Amendments are banners.** A locked ADR changes only through the [oss-mechanics.md](../adr/oss-mechanics.md) § Governance procedure: reopen the ticket, cross-model review, record an operative banner in the amended file. Read every ADR **through its banners** — the banner text wins over the body below it. [inheritance-model.md](../adr/inheritance-model.md) is superseded in full by [flat-model.md](../adr/flat-model.md); consume it only through the flat-model ripple register.

**Reading order for an implementing team:** product-requirements → domain-model → threat-model → system-architecture → then per-subsystem as the sequencing reaches it.

## Document map

| Required document | Canonical location |
|---|---|
| Product requirements | [product-requirements.md](./product-requirements.md) (+ root [PRODUCT.md](../../PRODUCT.md)) |
| Domain model + data-model index | [domain-model.md](./domain-model.md) |
| Threat model | [adr/threat-model.md](../adr/threat-model.md) |
| Security architecture | [encryption-model](../adr/encryption-model.md) · [tenant-isolation](../adr/tenant-isolation.md) · [human-auth](../adr/human-auth.md) · [machine-identities](../adr/machine-identities.md) · [saml-sp](../adr/saml-sp.md) · [scim-provisioning](../adr/scim-provisioning.md) · [secret-scanning](../adr/secret-scanning.md) · [audit-model](../adr/audit-model.md) |
| System architecture & stack | [adr/system-architecture.md](../adr/system-architecture.md) |
| Permission model | [adr/permission-model.md](../adr/permission-model.md) |
| Value model (supersedes "inheritance specification") | [adr/flat-model.md](../adr/flat-model.md) |
| Revisions, publishing & rollback | [adr/revision-model.md](../adr/revision-model.md) |
| Schema & validation | [adr/schema-model.md](../adr/schema-model.md) |
| Source of truth & Git | [adr/source-of-truth.md](../adr/source-of-truth.md) |
| UI & interaction spec | [ui-spec.md](./ui-spec.md) (+ [DESIGN.md](../../DESIGN.md), frozen `prototype/`) |
| Docker Compose integration | [adr/compose-integration.md](../adr/compose-integration.md) |
| Kubernetes integration | [adr/k8s-integration.md](../adr/k8s-integration.md) |
| Deployment modules | [adr/deployment-adapter.md](../adr/deployment-adapter.md) (seam + Forgejo) · [adr/github-adapter.md](../adr/github-adapter.md) |
| Import & migration | [adr/import-paths.md](../adr/import-paths.md) |
| API & CLI spec | [adr/api-cli-surface.md](../adr/api-cli-surface.md) (skeleton) + [api-cli-spellings.md](./api-cli-spellings.md) (deferred spellings, discharged) |
| Multi-instance | [adr/multi-instance.md](../adr/multi-instance.md) |
| Deployment & operations | [adr/ops-spec.md](../adr/ops-spec.md) + [ops-catalogue.md](./ops-catalogue.md) (deferred values, discharged) |
| MVP scope & acceptance criteria | [adr/mvp-boundary.md](../adr/mvp-boundary.md) §1–§2, §6 + [self-hoster-checklist.md](./self-hoster-checklist.md) (passed) |
| Out-of-scope / roadmap appendix | [adr/mvp-boundary.md](../adr/mvp-boundary.md) §4, verbatim |
| Implementation sequencing | [adr/mvp-boundary.md](../adr/mvp-boundary.md) §5 (CI-invariant subsystems first; promotions design-early/build-late) |
| License & governance | [LICENSE](../../LICENSE) (MPL 2.0, [#9](https://github.com/Dunky13/envweave/issues/9)) + [adr/oss-mechanics.md](../adr/oss-mechanics.md) |
| Audit & event model | [adr/audit-model.md](../adr/audit-model.md) |
| OSS project mechanics | [adr/oss-mechanics.md](../adr/oss-mechanics.md) |
| Post-spec open items (fog sweep) | [open-items.md](./open-items.md) |

## Synthesis obligations, discharged

Every "at synthesis (#27)" delegation in the corpus resolves as follows: exact SCIM/SAML/import/multi-instance spellings and serializations → [api-cli-spellings.md](./api-cli-spellings.md); canonical key grammar restatement → [domain-model.md](./domain-model.md); delegated tunable values + ops-spec row-15 numbering fix → [ops-catalogue.md](./ops-catalogue.md); the §3 self-hoster checklist (normative deliverable) → [self-hoster-checklist.md](./self-hoster-checklist.md), **passed, no blocking defect**; UI deltas (GitHub adapter knobs, scanning presentation, git-mode banner, declaration-is-public statement) → [ui-spec.md](./ui-spec.md); everything still unspecified → [open-items.md](./open-items.md), none foundational. One contradiction was found and fixed per procedure: oss-mechanics misquoted the license decision as Apache-2.0 (locked: MPL 2.0) — corrected via banner, [#33](https://github.com/Dunky13/envweave/issues/33) reopened and re-closed.

## The 1.0 gate, in one sentence

1.0 exists when every [mvp-boundary](../adr/mvp-boundary.md) §1.2 criterion (plus the four promotion criteria sets) is green as [E2E] on sqlite **and** postgres, [UI] via Playwright desktop+mobile, and [CI] invariants, the backup/restore drill has run on floor hardware, the self-hoster checklist re-asserts, and the freeze tag fires — nothing satisfiable by deleting or weakening its check.
