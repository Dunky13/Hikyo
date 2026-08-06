# Envweave — Self-hoster checklist (synthesis deliverable, 2026-08-06)

[mvp-boundary.md](../adr/mvp-boundary.md) §3 binds 1.0 wholesale to the oss-mechanics **decidable self-hoster test**: every capability in the spec set must be fully exercisable by a self-hoster — policy, API shape, recovery path, tenancy behavior, data transformation. Any capability failing is a **synthesis-blocking defect**. This checklist runs the instrument over the §1.2 capability list plus the four promotions. It is re-asserted against the release candidate's capability list at 1.0 (§6 item 4).

Verdict legend: **PASS** = fully exercisable on a self-hosted single-node install (sqlite or postgres, no external service beyond what the self-hoster operates).

| Capability | Verdict | Evidence |
|---|---|---|
| C1–C2 flat domain & value model | PASS | Pure server-side; sqlite floor |
| C3 schema & validation | PASS | Inline constraints, pinned local JSON Schema lib, no remote refs by design |
| C4 revisions & publishing | PASS | Server-side pipeline |
| C5 rollback & pins | PASS | CLI/UI, no external dependency |
| C6 retention & GC | PASS | instance-config values, local pruner |
| A1 human auth | PASS | Local accounts are the floor; OIDC/SAML optional against self-hostable IdPs (Keycloak/ZITADEL/Authentik bridge recipes documented); instance-capability holders always keep a local credential — no cloud IdP on any critical path |
| A2 permission model | PASS | Eight templates, no license gate |
| A3 tenant isolation | PASS | Application-layer, engine-neutral |
| A4 audit + A6 log non-disclosure | PASS | Local append-only tables; JSONL export; no external sink required |
| A5 reveal ceremonies | PASS | WebAuthn/TOTP self-enrolled |
| K1–K3 encryption, backup/restore, headline guarantee | PASS | Root key operator-held; age backups to operator-owned identities; restore drill on floor hardware |
| S1 API / S2 CLI | PASS | One `/api/v1` surface; CLI local |
| S3 Web UI | PASS | embed.FS, no CDN |
| S4 definitions Git flow | PASS | Envweave never reads a repository; any Git host (or none) works |
| M1 machine identities & federation | PASS | Bearer path needs nothing external; OIDC federation works against self-hosted CI (Forgejo Actions) and static-JWKS air-gap alternative exists |
| M2 Compose delivery | PASS | exec wrapper + dotenv, systemd timer |
| M3 K8s operator | PASS | Own minimal operator, K3s floor documented, Pi-class footprint |
| M4 deployment adapters | PASS with note | Forgejo adapter: self-hostable end to end. GitHub adapter: the *counterparty* is GitHub (github.com or self-hosted GHES best-effort) — the capability itself carries no Envweave-side gate; a self-hoster without GitHub simply has no use for it, which the test permits (it gates paywalls and SaaS coupling, not integrations with third parties) |
| M5 import | PASS | All connectors read local files or self-hosted sources; ambient credentials only |
| M6 multi-instance | PASS | Symmetric, no "main"; zero remotes = zero outbound |
| O1 single binary & migrations | PASS | `--dev` sqlite; prod explicit datastore |
| O2 ops conformance | PASS | Pi-4 calibration floor is the self-hoster |
| O3 release pipeline | PASS | Signed artifacts verifiable offline; fail-closed installers |
| O4–O6 disclosure, governance, support | PASS | Public docs; no CLA; MPL 2.0 |
| O7 zero unsolicited egress | PASS | CI-enforced air-gap boot |
| §2.2 SAML SP (promotion) | PASS | Works against self-hosted IdPs; no per-seat gate (the classic paywall this promotion exists to disprove) |
| §2.3 SCIM (promotion) | PASS | Push-only inbound; self-hosted IdPs with SCIM clients work; zero egress |
| §2.4 secret scanning (promotion) | PASS | Vendored ruleset, no runtime config, no cloud service |

**Named instances from §3, asserted:**

- **Operator ≡ org-admin must not harden into API shape**: no endpoint's formula distinguishes a hosted-operator persona; instance capabilities are grants like any other. Holds across the corpus (single grant table, no persona enum).
- **Multi-tenancy invariants strict**: the tenant-isolation machinery (proof-carrying authorization, 13 CI invariants, probe harness) applies at every install size — nothing relaxes at 1 org.
- **Billing hooks absent, not stubbed**: no entitlement checks, no seat counting, no license keys anywhere in the corpus. The follow-on SaaS map must clear the non-preclusion gate without retrofitting any.

**Result: no synthesis-blocking defect.** Every capability passes; the one note (GitHub adapter counterparty) is a third-party-integration fact, not a self-hoster gate.
