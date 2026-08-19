# Hikyo — Domain Model (synthesis, 2026-08-06)

The ubiquitous language, as locked in the domain-model grilling ([#7](https://github.com/Hikyo-Org/Hikyo/issues/7)) and amended by the flat-model ADR ([flat-model.md](../adr/flat-model.md), which supersedes the inheritance model in full). This document is the consolidated current state; the owning ADRs hold the rationale and the full semantics. It decides nothing.

## Hierarchy

**Instance → Organization → Project → Environment → Folder → Key/Value.**

- **Instance** — one Hikyo installation. Holds instance configuration, identity providers, remotes, the operator capability set.
- **Organization** — tenancy boundary. All isolation is application-layer, proof-carrying ([tenant-isolation.md](../adr/tenant-isolation.md)); org admins are trusted within their org ([threat-model.md](../adr/threat-model.md)).
- **Project** — owns the key catalogue (the schema), environments, service accounts, adapters, per-project DEK ([encryption-model.md](../adr/encryption-model.md)).
- **Environment** — user-defined per project, display-ordered. **No `base` pointer** (deleted by flat-model); no inheritance of any kind.
- **Folder** — organizational only in v1: namespace + display grouping. No folder-scoped RBAC, no folder-level values.
- **Key** — declared **once per project**: immutable id, mutable name (unique among live keys), folder path, `secret | config` classification, inline constraints, description. Classification is a property of the key: a matrix row is uniformly secret or config. Typing an undeclared name is a key creation, never a silent value write ([schema-model.md](../adr/schema-model.md)).
- **Value** — attached to `(key, environment)`. Presence is two-state: **`set | absent`**. No project-defaults layer, no masking state; "must never exist here" is the schema's `forbidden_in`.

## Resolution

Resolution is a lookup: environment E resolves key K to E's own `set` entry, else K is unresolved in E. No provenance record exists (the winning layer is always the environment itself); explainability rides revision lineage + audit.

Ergonomics for shared values are three explicit operations with no ongoing relationship: declare-into-environments, copy-to/bulk-apply, clone-at-creation. Every copy is independent; `values diff` is the on-demand comparison. Copy/clone/bulk-apply and restore are the closed re-delivery triggers requiring `reveal`/`reveal-history` ([flat-model.md](../adr/flat-model.md)).

## Revision & delivery vocabulary

- **Pending change** — per-user draft version at `(key, environment)`, immutable version id ([revision-model.md](../adr/revision-model.md)).
- **Publish** — the authority: atomic per project, validates resolved values at the pinned schema revision, materializes snapshots.
- **Resolved snapshot** — immutable, per `(project, environment)`: resolved key→value map + validation verdict, pinned to (schema revision, own value-entry revisions). Workloads fetch latest or a pinned id.
- **Revision** — monotonic per `(project, environment)`; the **change token** is a keyed HMAC over the delivery manifest, an opaque change-detection cache, never workload-visible as content.
- **Pin** — durable authorized resource holding a non-current snapshot deliverable; quota'd, expiring, blocks GC.

## Identity & principal vocabulary

- **Human account** — local credential and/or linked external identities `(kind ∈ {oidc, saml}, issuer, subject)`, byte-exact matching ([human-auth.md](../adr/human-auth.md)).
- **Service account** — machine principal, project-owned, kind `workload | automation`; credentials: `hikyo-token` (bearer `hik_…`) or `oidc-federation` ([machine-identities.md](../adr/machine-identities.md)).
- **Provisioning connection** — org-owned machine principal, one per SCIM binding, holds exactly `scim-provision` ([scim-provisioning.md](../adr/scim-provisioning.md)).
- **Instance connection** — instance-owned machine principal for the multi-instance directory, holds exactly `instance-directory` ([multi-instance.md](../adr/multi-instance.md)).
- **Grant** — `(principal, capability, scope)` triple with origins (`manual | scim | lockout-retention | structural`); the only authorization input ([permission-model.md](../adr/permission-model.md)).

## Canonical key grammar (restated per import-paths.md's delegation)

A key name matches **`\A[A-Z_][A-Z0-9_]*\z`** — uppercase ASCII letters, digits, underscore; no leading digit. This is the environment-variable-safe grammar every delivery surface assumes: Compose exec/dotenv delivery, K8s Secret data keys, adapter effective names (which additionally refuse non-uppercase *effective* names arising from a lowercase `name_prefix` — [deployment-adapter.md](../adr/deployment-adapter.md), [github-adapter.md](../adr/github-adapter.md)). Maximum name length is an ops-spec bound ([ops-catalogue.md](./ops-catalogue.md)). Names are unique among live keys per project; identity is the immutable id, so rename never breaks references. Import behavior relative to this grammar (byte-preserve valid, deterministic transform, hard-stop otherwise): [import-paths.md](../adr/import-paths.md) § Renames.

## Entity inventory (data-model index)

One row per persisted entity class; the owning ADR holds the authoritative shape. The store layer is engine-neutral (sqlite + postgres, [system-architecture.md](../adr/system-architecture.md)); rows carry denormalized immutable tenant-id chains per scope class ([tenant-isolation.md](../adr/tenant-isolation.md)).

| Entity | Owner |
|---|---|
| Organization, Project, Environment, Folder | #7 + [flat-model.md](../adr/flat-model.md) |
| Key (declaration, constraints, group membership) | [schema-model.md](../adr/schema-model.md) |
| Value entry `(key, environment)`, encrypted | [flat-model.md](../adr/flat-model.md), [encryption-model.md](../adr/encryption-model.md) |
| Pending change (draft version) | [revision-model.md](../adr/revision-model.md) |
| Resolved snapshot, revision, change token | [revision-model.md](../adr/revision-model.md) |
| Pin | [revision-model.md](../adr/revision-model.md) |
| Human account, external identity link, session, workspace session | [human-auth.md](../adr/human-auth.md), [multi-instance.md](../adr/multi-instance.md) |
| MFA factors, recovery codes (encrypted) | [human-auth.md](../adr/human-auth.md) |
| Service account, credential (hashed verifier), federated binding | [machine-identities.md](../adr/machine-identities.md) |
| Grant (with origins) | [permission-model.md](../adr/permission-model.md), [scim-provisioning.md](../adr/scim-provisioning.md) |
| Identity provider (OIDC/SAML), SP material (encrypted) | [human-auth.md](../adr/human-auth.md), [saml-sp.md](../adr/saml-sp.md) |
| SCIM binding, mapping row, provisioning connection | [scim-provisioning.md](../adr/scim-provisioning.md) |
| Adapter, target, ownership-ledger row | [deployment-adapter.md](../adr/deployment-adapter.md) |
| Adapter outbox job | [system-architecture.md](../adr/system-architecture.md) |
| Remote (directory entry), instance-connection credential | [multi-instance.md](../adr/multi-instance.md) |
| Key hierarchy (wrapped master, DEKs, token key, scanning key) | [encryption-model.md](../adr/encryption-model.md) |
| Audit events (tenant + instance tables) | [audit-model.md](../adr/audit-model.md) |
| Scanning dismissal row | [secret-scanning.md](../adr/secret-scanning.md) |
| Import plan / run manifest | [import-paths.md](../adr/import-paths.md), [source-of-truth.md](../adr/source-of-truth.md) |
| Definitions bundle (artifact, not a table) | [source-of-truth.md](../adr/source-of-truth.md) |
