# Envweave — Ops catalogue additions landed at synthesis (2026-08-06)

[ops-spec.md](../adr/ops-spec.md) owns every concrete operational value; several post-lock ADRs declared **categories** into its composable-maxima catalogue and delegated the **values** to synthesis. This document lands those values under ops-spec's rules: every bound is a named user-visible refusal; every default is overridable at the stated scope unless marked fixed; all values are sane at the Pi-4/4 GB calibration floor. These rows join the ops-spec decision inventory; contradictions reopen the owning ticket.

## Row numbering correction

The ops-spec inventory carries **two rows numbered 15** (the secret-scanning post-lock insertion collided with plans/pins/grants). Corrected numbering: secret scanning = **row 15a**, plans/pins/grants = **row 15b**. No values change; references by name stay valid.

## SAML (defaults fixed in [saml-sp.md](../adr/saml-sp.md); catalogued here as tunable entries)

| Entry | Default | Scope |
|---|---|---|
| Clock skew | 60 s | instance-config |
| Transaction TTL (login/reauth/link) | 10 min | instance-config |
| `IssueInstant` max age (Response + Assertion) | 5 min | instance-config |
| Reauth `AuthnInstant` freshness | 5 min (+ skew) | instance-config |
| Replay-cache retention | assertion `NotOnOrAfter` + skew | fixed |
| Document bounds | ≤ 256 KiB decoded · depth ≤ 32 · ≤ 50 000 XML tokens | fixed |

## SCIM ([scim-provisioning.md](../adr/scim-provisioning.md) § 9 delegation)

| Entry | Default | Scope |
|---|---|---|
| Binding staleness threshold (no IdP write → stale badge; never revokes) | 24 h | instance-config |
| Wire request body cap | 256 KiB | fixed |
| Page size (`count` clamp, list responses) | 100 (max 200) | fixed |
| Per-binding rate limit | 120 req/min, burst 240 (uniform 429 beyond) | instance-config |

## Multi-instance directory + workspace ([multi-instance.md](../adr/multi-instance.md) delegation)

| Entry | Default | Scope |
|---|---|---|
| Per-remote fetch deadline | 10 s | instance-config |
| Per-remote response size cap | 1 MiB | fixed |
| Remote count cap | 25 | instance-config |
| Parallel fan-out cap | 4 | instance-config |
| Coalescing window (duplicate view triggers) | 5 s | fixed |
| Per-viewer trigger rate | 6/min | instance-config |
| Instance-wide aggregate trigger rate | 60/min | instance-config |
| Workspace session idle / absolute lifetime | 15 min / 4 h (mirrors the reveal window row: hard-short) | instance-config, capped by remote |
| Handoff transaction expiry | 5 min, single-use | fixed |

## Import connectors ([import-paths.md](../adr/import-paths.md) bounds-existence delegation)

| Entry | Default | Scope |
|---|---|---|
| Per-file size (file mode) | 10 MiB | instance-config |
| Per-response size (live mode) | 5 MiB (runtime response-cap row) | fixed |
| Decoded-bytes cap per run | 50 MiB | instance-config |
| Record count per run | 50 000 | instance-config |
| Tree depth | 32 (matches declaration-depth row) | fixed |
| Per-request deadline (live) | 30 s | instance-config |
| Whole-run deadline | 10 min | instance-config |
| Page/request cap (live pagination) | 1 000 pages | fixed |
| Wizard session aggregate (wall clock / decoded bytes) | 30 min / 100 MiB | fixed |

## Key-name bound (grammar restated in [domain-model.md](./domain-model.md))

| Entry | Default | Scope |
|---|---|---|
| Key name length | ≤ 128 bytes (safe under the K8s Secret data-key limit with adapter prefixes applied) | fixed |

## Values still pending measurement (not deferrable past implementation freeze)

Per ops-spec, all *(measured)* entries — operator resource requests/limits, scan p99, scanner boot compile — are verified on Pi-class hardware **before implementation freeze**. Tracked in [open-items.md](./open-items.md).
