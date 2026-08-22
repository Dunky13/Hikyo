# Hikyo — post-spec obligations (synthesis, 2026-08-06)

This document preserves obligations left by the specification synthesis. It does
not report current implementation state. Stable IDs connect each immutable
obligation to the machine-checked [implementation-status ledger](../status/README.md),
which is the sole current-status authority. ADRs own contracts; historical
handoffs remain evidence.

## Implementation-pinned evidence

| ID | Immutable obligation | Contract |
| --- | --- | --- |
| `OBL-SCAN-PERFORMANCE` | Commit Pi-class evidence that gates scan p99 ≤ 5 ms, scanner boot compile ≤ 2 s, and scanner boot memory ≤ 32 MiB. | [ops-spec.md](../adr/ops-spec.md), [secret-scanning.md](../adr/secret-scanning.md) |
| `OBL-OPERATOR-PI-FIT` | Record an arm64 cgroup run showing the operator reconciles within its 128 MiB limit under load. | [ops-spec.md](../adr/ops-spec.md) |
| `OBL-IMPORT-FIXTURES` | Pin adversarial import fixtures, sanitized hostile-provider errors, the Infisical exporter floor, and canonical JSON conversion. | [import-paths.md](../adr/import-paths.md) |
| `OBL-ADAPTER-FIXTURES` | Pin minimal-scope credential spellings, expiry behavior, conflict/sealed-box fixtures, and non-UTF-8 disposition. | [deployment-adapter.md](../adr/deployment-adapter.md), [github-adapter.md](../adr/github-adapter.md) |
| `OBL-CI-ACTION-PINS` | Pin exact CI action SHAs and release pipeline steps under the supply-chain rules. | [oss-mechanics.md](../adr/oss-mechanics.md), [system-architecture.md](../adr/system-architecture.md) |
| `OBL-CLI-GOLDENS` | Keep the CLI scenario matrix and closed-flow registry executable before accepting a build. | [api-cli-surface.md](../adr/api-cli-surface.md), [mvp-boundary.md](../adr/mvp-boundary.md) |
| `OBL-REPOSITORY-TRANSFER` | Host the canonical repository and its organization controls under `Hikyo-Org/Hikyo`. | [oss-mechanics.md](../adr/oss-mechanics.md) |

## Product and editorial obligations

| ID | Immutable obligation | Contract |
| --- | --- | --- |
| `OBL-UI-SCHEMA-POLISH` | Refine key-declaration and schema-editing dialogs within the frozen surface contracts. | [ui-spec.md](./ui-spec.md) |
| `OBL-OPS-SUPERSESSION` | On the next standalone ops-spec reissue, consolidate the release-range key-validity wording governed by oss-mechanics. | [ops-spec.md](../adr/ops-spec.md), [oss-mechanics.md](../adr/oss-mechanics.md) |
| `OBL-DOCS-SITE` | Publish the 1.0 documentation information architecture with O4-O6 artifacts and the required federation-vs-push guidance. | [oss-mechanics.md](../adr/oss-mechanics.md), [product-requirements.md](./product-requirements.md) |
| `OBL-OPS-ROW-NUMBERING` | Renumber the duplicate inventory row on the next editorial amendment without changing name-based references. | [ops-catalogue.md](./ops-catalogue.md) |

## Accepted residual boundary

`OBL-ACCEPTED-RESIDUALS` preserves the named residuals and their owning-ADR
reopen triggers: engine microtiming; dismissal-probe oracle; workspace-channel
CA/DNS-compromise MITM plus XSS bearer extraction; adapter dispatch-capture
window; never-reconnecting Compose host; clock rollback; retained-old-backup
decryptability after root-key theft; and operator audit-trail tampering.
