<div align="center">
  <a href="https://hikyo.app/">
    <img src="./docs/site/public/favicon.svg" alt="Hikyo" width="128" />
  </a>

  <h1>Hikyo</h1>

  <p><strong>Secrets and configuration you can reason about.</strong></p>

  <p>
    A fully open-source, self-hosted control plane for explicit values across
    development, staging, and production.
  </p>

  <p>
    <a href="https://hikyo.app/docs/"><strong>Documentation</strong></a> ·
    <a href="https://hikyo.app/docs/getting-started/">Getting started</a> ·
    <a href="https://hikyo.app/docs/self-hosting/">Self-hosting</a> ·
    <a href="./CONTRIBUTING.md">Contributing</a>
  </p>

  <p>
    <a href="https://github.com/Hikyo-Org/Hikyo/actions/workflows/ci.yml"><img alt="CI status" src="https://github.com/Hikyo-Org/Hikyo/actions/workflows/ci.yml/badge.svg?branch=main" /></a>
    <a href="./LICENSE"><img alt="Mozilla Public License 2.0" src="https://img.shields.io/badge/license-MPL--2.0-3b82f6" /></a>
  </p>
</div>

> [!IMPORTANT]
> Release maturity, interface freeze, and distribution status live only under
> [`CAP-PUBLIC-RELEASE`](./docs/status/README.md#cap-public-release) in the
> machine-checked implementation-status ledger.

<!-- implementation-status:start -->
## Implementation status

<details>
<summary>Show fully implemented, partially implemented, and open features</summary>

“Implemented” means the feature and its acceptance evidence are present in the
repository. The machine-checked [implementation-status ledger](./docs/status/README.md)
is the only current-status authority; ADRs/specs define obligations and handoffs
remain immutable evidence.

### Fully implemented

| Feature | Included |
| --- | --- |
| [`CAP-RUNTIME-STORAGE`](./docs/status/README.md#cap-runtime-storage) Runtime and storage | Single multicall binary, SQLite and PostgreSQL stores, migrations, and CI |
| [`CAP-SECURITY-FOUNDATIONS`](./docs/status/README.md#cap-security-foundations) Security foundations | Envelope encryption, authorization chokepoint, append-only audit trails, and gap-free PostgreSQL audit export |
| [`CAP-CORE-API-CLI`](./docs/status/README.md#cap-core-api-cli) Core API and CLI | Bootstrap administration, local login, hierarchy CRUD, key declarations, validation, encrypted values, copy, clone, and bulk apply |
| [`CAP-HUMAN-ACCESS`](./docs/status/README.md#cap-human-access) Human identity and access | OIDC, WebAuthn, TOTP, recovery, sessions, grants, role templates, and protected environments |
| [`CAP-MATRIX-DISCLOSURE`](./docs/status/README.md#cap-matrix-disclosure) Matrix and disclosure UI | Embedded app shell, environment matrix, row editor, problems filter, reveal/copy ceremonies, and protected publish flows |
| [`CAP-MACHINE-ACCESS`](./docs/status/README.md#cap-machine-access) Machine access | Service accounts, display-once credentials, OIDC workload federation, and machine-access UI |
| [`CAP-MULTI-INSTANCE`](./docs/status/README.md#cap-multi-instance) Multi-instance workspaces | Directory-tier remotes and browser-direct workspace sessions |
| [`CAP-ENTERPRISE-IDENTITY`](./docs/status/README.md#cap-enterprise-identity) Enterprise identity protocols | SAML service-provider support and SCIM provisioning, fully open-source |
| [`CAP-BACKUP-RESTORE`](./docs/status/README.md#cap-backup-restore) Backup and restore | Encrypted export/restore plus the cross-engine recovery drill |
| [`CAP-REVISION-LIFECYCLE`](./docs/status/README.md#cap-revision-lifecycle) Revision lifecycle | Drafts, snapshots, selective publish, rollback, durable pins, retention, GC, and history restore/pin lifecycle |
| [`CAP-ADMINISTRATION-UI`](./docs/status/README.md#cap-administration-ui) Administration UI | Members, organisation/project settings, account security, instance administration, and browser step-up |
| [`CAP-IMPORTS-ONBOARDING`](./docs/status/README.md#cap-imports-onboarding) Imports and onboarding | Kubernetes, SOPS, and Infisical file imports; live Kubernetes and Vault/OpenBao connectors; import wizard; dotenv scaffolding |
| [`CAP-DELIVERY`](./docs/status/README.md#cap-delivery) Delivery | Compose delivery and `hikyo run`, Kubernetes operator/CRDs, Forgejo and GitHub Actions adapters, and machine-reveal opt-in |
| [`CAP-KEY-ROTATION`](./docs/status/README.md#cap-key-rotation) Key rotation | Root, master, DEK, token, and scanning-key rotation plus resumable re-encryption |
| [`CAP-SECRET-SCANNING`](./docs/status/README.md#cap-secret-scanning) Secret scanning | Surface-1 warnings and Surface-2 blocks on every CLI/API value ingress |
| [`CAP-SUPPLY-CHAIN-SITE`](./docs/status/README.md#cap-supply-chain-site) Supply chain and project site | Signed release pipeline, SBOMs, documentation/governance site, matching icons, and offline-capable PWA |

### Partially implemented

| Feature | What works now | Needed for complete implementation |
| --- | --- | --- |
| [`CAP-PRODUCTION-OPS`](./docs/status/README.md#cap-production-ops) Production operations | All registered operational bounds, doctor, upgrade path, no-egress posture, and pinned operator resource limits | Record an arm64 cgroup run proving operator reconciliation within the 128 MiB limit under load |
| [`CAP-PUBLIC-RELEASE`](./docs/status/README.md#cap-public-release) Public release and distribution | Cosign trust, SBOM generation, GoReleaser/Helm packaging, and installer verification | Run full acceptance, freeze API/CLI, and publish 1.0 under [#79](https://github.com/Hikyo-Org/Hikyo/issues/79) |
| [`CAP-BROWSER-SCANNING`](./docs/status/README.md#cap-browser-scanning) Secret scanning in the browser | CLI/API Surface-1 warnings and Surface-2 blocks | SPA block dialog after declaration editing lands under [#183](https://github.com/Hikyo-Org/Hikyo/issues/183) |

</details>
<!-- implementation-status:end -->

## One matrix. No hidden inheritance.

Hikyo makes every environment answer for itself. A value is explicitly `set`
or `absent`; production never silently borrows a development default.

| Key | development | staging | production |
| --- | :---: | :---: | :---: |
| `DATABASE_URL` | ● secret set | ● secret set | ● secret set |
| `LOG_LEVEL` | `debug` | `info` | `info` |
| `SENTRY_DSN` | ○ absent | ● secret set | ● secret set |

The same model is available through the embedded web UI, CLI, and API. Hikyo
ships as one Go binary and supports both SQLite and PostgreSQL.

## What makes Hikyo different

- **Explicit state.** Empty never means “inherited,” “unknown,” or “use a
  default.” Each environment records `set` or `absent`.
- **Declarations before values.** Define config vs. secret, validation, and
  presence rules first. Invalid writes are refused before state changes.
- **Deliberate secret disclosure.** Normal reads return metadata and presence.
  Reveal and copy require reauthentication and create dedicated audit events.
- **One authorization chokepoint.** Humans, machine identities, and local
  break-glass use the same capability-and-scope decision model.
- **Self-hosting is the product.** One binary, an embedded UI, your database,
  your root key, and no enterprise-only implementation.

## Quick start

Requires Go 1.26+, Node.js 24 (see [`.nvmrc`](./.nvmrc)), and Corepack/pnpm.

```bash
git clone https://github.com/Hikyo-Org/Hikyo.git
cd Hikyo

corepack enable
pnpm --dir clients/ts install --frozen-lockfile
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
go build -tags ui -o ./bin/hikyo ./cmd/hikyo

./bin/hikyo server --dev
```

Open <http://127.0.0.1:8080>. The command creates `hikyo-dev.db` and a
permission-`0600` root key in the current directory.

`--dev` is loopback-only and intended for evaluation. A `-tags ui` build embeds
the browser app; a plain `go build` produces an API-only binary.

Next, follow [Getting started](https://hikyo.app/docs/getting-started/) to create
the first administrator, then [Your first project](https://hikyo.app/docs/first-project/)
to declare a key and set its first value.

## CLI at a glance

One binary handles both operator and day-to-day client workflows.

```bash
# Operate the instance
hikyo server [--dev] [--listen ADDR] [--root-key-file PATH]
hikyo migrate
hikyo admin create --username admin
hikyo backup export
hikyo restore run --from <archive> --identity-file <path>

# Create a scoped environment
hikyo login <instance-url> --local --as <user>
hikyo org create --name <name>
hikyo project create --name <name> --org <org-id>
hikyo env create --name <name> --org <org-id> --project <project-id>
hikyo context create <name> --instance <url> --org <id> --project <id> --env <id>

# Declare and manage values
hikyo key create --context <ctx> --name NAME --classification config|secret \
  --declaration '{"rule":{"type":"string"}}'
hikyo values set NAME --context <ctx> --value-file PATH
hikyo values get NAME --context <ctx>
hikyo values get NAME --context <ctx> --reveal --output-file PATH
hikyo values list --context <ctx>
hikyo values diff --context <ctx> --left development --right production
hikyo values copy --context <ctx> --from staging --to production --keys NAME
```

Secret values never belong in command-line arguments. Use `--value-file` or
`--stdin`. See the complete [CLI reference](https://hikyo.app/docs/cli-reference/).

## Run in production

Outside `--dev`, provide a datastore, external origin, trusted proxy boundary,
and root key:

```bash
HIKYO_DB=sqlite:/var/lib/hikyo/hikyo.db \
HIKYO_EXTERNAL_ORIGIN=https://hikyo.example.com \
HIKYO_TRUSTED_PROXY_CIDRS=127.0.0.1/32 \
./hikyo server --listen 127.0.0.1:8080 \
  --root-key-file /etc/hikyo/root.key
```

`HIKYO_DB` accepts `sqlite:PATH` or a PostgreSQL DSN. Terminate TLS at a reverse
proxy and keep the Hikyo listener private.

Read [Self-hosting](https://hikyo.app/docs/self-hosting/) before deployment and
[Configuration](https://hikyo.app/docs/configuration/) for every flag and
environment variable.

## Fully open. One product.

Every capability required to run Hikyo in production is and will remain open
source; there is no `/ee` directory and there will never be one.

The enforceable commitment and amendment process live in
[GOVERNANCE.md](./GOVERNANCE.md#fully-open-pledge).

## Explore the project

| Goal | Start here |
| --- | --- |
| Learn the model | [Core concepts](https://hikyo.app/docs/core-concepts/) |
| Build from source | [Installation](https://hikyo.app/docs/installation/) |
| Operate an instance | [Self-hosting](https://hikyo.app/docs/self-hosting/) |
| Use the terminal | [CLI reference](https://hikyo.app/docs/cli-reference/) |
| Contribute code | [Contributing guide](./CONTRIBUTING.md) |
| Read the design decisions | [Architecture decision records](./docs/adr/README.md) and [specification set](./docs/spec/README.md) |

[Security](./SECURITY.md) · [Support](./SUPPORT.md) ·
[Governance](./GOVERNANCE.md) · [Trademark](./TRADEMARK.md)

## License

Hikyo is licensed under the [Mozilla Public License 2.0](./LICENSE).
