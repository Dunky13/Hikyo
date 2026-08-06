# Envweave — Product Requirements (synthesis, 2026-08-06)

Synthesized from the positioning decision ([#3](https://github.com/Dunky13/envweave/issues/3)), the competitive research ([competitive-landscape.md](../research/competitive-landscape.md)), the license decision ([#9](https://github.com/Dunky13/envweave/issues/9)), the MVP boundary ([mvp-boundary.md](../adr/mvp-boundary.md)), and the product register at the repo root ([PRODUCT.md](../../PRODUCT.md)). This document restates locked decisions; it decides nothing. On any divergence, the owning ADR or ticket resolution wins and the contradiction reopens that ticket.

## One-liner

> **Fully open-source secrets & config across environments — with validation, explicit per-environment values, and no enterprise tier.**

"Fully open, no enterprise tier" leads; validation and the environment matrix back it. Compose-first is a feature bullet, not the headline. (The original one-liner said "inheritance"; the flat-model ADR ([flat-model.md](../adr/flat-model.md)) superseded inheritance with explicit per-environment values after matrix-prototype trial — the wedge is unchanged, the mechanism wording follows the locked model.)

## Users

1. **Self-hosting developers** (primary; the beachhead): homelab operators, 1–3 orgs, up to ~25 users. Live in terminals and dashboards, administer their own infrastructure, reach the UI from a desk by day and a phone in the server closet by night.
2. **Platform engineers** (secondary; the goal): the architecture carries them (org layer from day one, pluggable datastores, deployment-module seam) while staying thin for the primary user.

## Problem & wedge

Every surveyed competitor (Infisical, Phase, Vault/OpenBao, SOPS, ESO — [competitive-landscape.md](../research/competitive-landscape.md)) either paywalls the operational core (audit, RBAC, SSO, SCIM, secret scanning — the classic `/ee` lineup) or lacks the environment-matrix + schema-validation combination entirely. No surveyed product combines explicit multi-environment values + schema validation + fully-open licensing.

Envweave's wedge is structural, not promotional:

- **MPL 2.0**: file-level copyleft keeps every existing file open in any fork, and DCO means contributors keep their copyright — so no one can unilaterally relicense *contributed* work (the specific lever a BUSL-style pivot needs). What this does *not* do is legally prevent new proprietary code beside old open code — that boundary is held by governance, not law. See [oss-mechanics.md](../adr/oss-mechanics.md) and #9.
- **The no-`/ee` pledge** is published governance (GOVERNANCE.md full text + README sentence), amendable only through the locked-decision procedure: audit, rollback, RBAC, SAML, SCIM, secret scanning ship free.
- **Four classic paywall items are promoted into 1.0** as wedge proof: GitHub Actions adapter, SAML SP, SCIM provisioning, secret scanning ([mvp-boundary.md](../adr/mvp-boundary.md) §2).

## Product principles (settled; reopen only on serious contradiction)

- Fully open source; no paid gate on any production-required capability.
- Self-hosting first: single-server Compose and K8s/K3s are the reference deployments; a Raspberry Pi 4 (4 GB, sqlite) is the calibration floor ([ops-spec.md](../adr/ops-spec.md)).
- The **environment matrix** is the signature surface; secrets vs config distinguished throughout; disclosure is a ceremony.
- Deterministic, explainable values: every value is explicit per environment ([flat-model.md](../adr/flat-model.md)); schema validation before delivery ([schema-model.md](../adr/schema-model.md)).
- Multi-tenant single installation; changes apply on restart (no live process mutation in v1).
- Fail fast, fail loud: every bound is a named refusal, never silent truncation.

## Delivery overview

Envweave delivers values three ways, presented as a gradient: **fetch-based delivery** under the workload's own identity (`envweave run` / rendered dotenv on Compose, the K8s operator, CI federation fetching at runtime) is the first-class path; **push adapters** (Forgejo, GitHub Actions) exist for destinations whose workflows need standing values before the first fetch. The gradient sentence, carried from [deployment-adapter.md](../adr/deployment-adapter.md) as positioning: ***if your job can fetch, federate; push what must exist before the first fetch.***

## Scale envelope (v1 designed-for)

1 instance · 1–3 orgs · ≤25 human users · ≤50 projects · ≤10 environments/project · ≤10k secret entries · ≤100 workload clients. Single node, no HA. Load-tested at 10× each number. Concrete bounds: [ops-spec.md](../adr/ops-spec.md).

## Success criteria

- An operator trusts Envweave enough to manage production secrets in it.
- Every resolved value's origin is understandable without reading docs.
- The 1.0 gate ([mvp-boundary.md](../adr/mvp-boundary.md) §1.2, §6) is green on sqlite **and** postgres, and the [self-hoster checklist](./self-hoster-checklist.md) passes wholesale.

## Explicitly not in this product's v1

The complete out-of-scope register with per-item dispositions and reopen triggers is [mvp-boundary.md](../adr/mvp-boundary.md) §4 (the spec's roadmap appendix, verbatim). Headline outs: hosted SaaS + billing (committed follow-on map after 1.0), HA/multi-region, dynamic credentials, PKI/CA, approval workflows, plugin marketplace, LDAP.
