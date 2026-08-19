# Architecture decision records

The locked design authority for Hikyo. Every non-trivial invariant in the
code cites one of these files by short name — "the encryption-model ADR",
"the permission-model ADR" — and the tests under `internal/isolation/` and
`internal/lint/` enforce the invariants the ADRs name. The ADRs were
synthesised on the `wayfinder-docs` branch and vendored here on 2026-08-19 so
the authority the code cites ships with the code; `docs/adr/` on `main` is the
canonical copy from that date. The frozen UI prototypes the ui-spec refers to
stay on that branch (`prototype/`), as do the research notes' images.

Read every ADR **through its amendment banners**: the banner text wins over
the body below it. A change that contradicts a locked ADR reopens the ADR
(amendment banner, cross-model review) rather than diverging silently — the
procedure is [oss-mechanics.md](./oss-mechanics.md) § Governance. The
build-ready synthesis across these files is [`../spec/`](../spec/README.md);
`inheritance-model.md` is superseded in full by `flat-model.md` and is kept only
for its ripple register.

## Short name → file

| Cited as | File |
| --- | --- |
| api-cli-surface ADR | [api-cli-surface.md](./api-cli-surface.md) |
| audit-model ADR | [audit-model.md](./audit-model.md) |
| compose-integration ADR | [compose-integration.md](./compose-integration.md) |
| deployment-adapter ADR | [deployment-adapter.md](./deployment-adapter.md) |
| encryption-model ADR | [encryption-model.md](./encryption-model.md) |
| flat-model ADR | [flat-model.md](./flat-model.md) |
| github-adapter ADR | [github-adapter.md](./github-adapter.md) |
| human-auth ADR | [human-auth.md](./human-auth.md) |
| import-paths ADR | [import-paths.md](./import-paths.md) |
| inheritance-model ADR (superseded) | [inheritance-model.md](./inheritance-model.md) |
| k8s-integration ADR | [k8s-integration.md](./k8s-integration.md) |
| machine-identities ADR | [machine-identities.md](./machine-identities.md) |
| multi-instance ADR | [multi-instance.md](./multi-instance.md) |
| mvp-boundary ADR | [mvp-boundary.md](./mvp-boundary.md) |
| ops-spec ADR | [ops-spec.md](./ops-spec.md) |
| oss-mechanics ADR | [oss-mechanics.md](./oss-mechanics.md) |
| permission-model ADR | [permission-model.md](./permission-model.md) |
| revision-model ADR | [revision-model.md](./revision-model.md) |
| saml-sp ADR | [saml-sp.md](./saml-sp.md) |
| schema-model ADR | [schema-model.md](./schema-model.md) |
| scim-provisioning ADR | [scim-provisioning.md](./scim-provisioning.md) |
| secret-scanning ADR | [secret-scanning.md](./secret-scanning.md) |
| source-of-truth ADR | [source-of-truth.md](./source-of-truth.md) |
| system-architecture ADR | [system-architecture.md](./system-architecture.md) |
| tenant-isolation ADR | [tenant-isolation.md](./tenant-isolation.md) |
| threat-model ADR | [threat-model.md](./threat-model.md) |

Background research the ADRs cite lives in [`../research/`](../research/).
