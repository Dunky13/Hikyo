# Envweave — Post-spec open items (synthesis, 2026-08-06)

The map's fog sweep, discharged: everything still unspecified at synthesis is recorded here explicitly. **None of these is a foundational question** — an implementing team is not blocked by any row; each names its owner and its resolution moment. The post-v1 feature register (with dispositions and reopen triggers) is [mvp-boundary.md](../adr/mvp-boundary.md) §4 and is *not* duplicated here.

## Resolved-at-implementation (pinned moments, contracts already fixed)

| Item | Contract lives in | Resolves |
|---|---|---|
| *(measured)* values: operator resources (50m/64Mi–200m/128Mi), scan p99 ≤5 ms, scanner boot compile ≤2 s/≤32 MiB | [ops-spec.md](../adr/ops-spec.md), [secret-scanning.md](../adr/secret-scanning.md) | Pi-class measurement **before implementation freeze** (`bench-scan` artifact) |
| Import connector fixtures (adversarial parsers, hostile-provider errors, per-source captures); Infisical exporter command + minimum version; canonical `json`-conversion serialization | [import-paths.md](../adr/import-paths.md) | Fixture-pinned when connectors are built |
| Forgejo + GitHub PAT minimal-scope exact spellings; GitHub expiry header pin; contract-test fixtures (POST-409 oracle, sealed-box vectors); non-UTF-8 disposition | [deployment-adapter.md](../adr/deployment-adapter.md), [github-adapter.md](../adr/github-adapter.md) | Implementation, against fixture evidence |
| Exact pinned CI action SHAs, pipeline steps | [oss-mechanics.md](../adr/oss-mechanics.md), [system-architecture.md](../adr/system-architecture.md) | Implementation under #22's pinning rules |
| Golden-snapshot CLI scenario matrix; S3 closed flow registry enumeration | [api-cli-surface.md](../adr/api-cli-surface.md), [mvp-boundary.md](../adr/mvp-boundary.md) | First CI wiring; gate exists before any build |
| Repository transfer `Dunky13/envweave` → GitHub organization | [oss-mechanics.md](../adr/oss-mechanics.md) | Fixed implementation step |

## Open items proper (no owner-locked answer yet; none foundational)

1. **UI polish for key-declaration/schema-editing refinements** — behaviors are specified textually in [ui-spec.md](./ui-spec.md) § Key declaration; **no visual prototype was run for them** (the map's remaining-prototypes fog; all five foundational surfaces have locked references, this batch is dialog-level refinement on #20/#21's surfaces). If visual iteration is wanted, run it against the frozen prototypes before the S3 flow registry is enumerated; otherwise implementation designs within DESIGN.md.
2. **ops-spec §13/§14 supersession hygiene** — oss-mechanics's release-range key validity supersedes ops-spec's earlier one-release-overlap sketch, and release cadence/support window now live in oss-mechanics; ops-spec's banner records this, no value conflict remains. Purely editorial follow-up if ops-spec is ever re-issued as a standalone operator handbook.
3. **Docs site** — deferred artifact, ships with 1.0 ([oss-mechanics.md](../adr/oss-mechanics.md)); its information architecture is unconstrained by this spec beyond carrying O4–O6 artifacts.

## Accepted residuals (restated once, not open)

Engine microtiming; dismissal-probe oracle; workspace-channel CA/DNS-compromise MITM + XSS bearer extraction; adapter dispatch-capture window; never-reconnecting Compose box; clock rollback; retained-old-backup decryptability after root-key theft; operator tamper capability on the audit trail. Each is documented in its owning ADR with its revisit trigger; none reopens at synthesis.
