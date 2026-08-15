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
    <img alt="Active 0.x development" src="https://img.shields.io/badge/status-active%200.x-f97316" />
  </p>
</div>

> [!IMPORTANT]
> Hikyo is in active `0.x` development. Interfaces are not frozen, and there
> are no published binaries, images, or Helm charts yet. Build from source to
> evaluate it today.

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

[Security](./SECURITY.md) · [Support](./SUPPORT.md) ·
[Governance](./GOVERNANCE.md) · [Trademark](./TRADEMARK.md)

## License

Hikyo is licensed under the [Mozilla Public License 2.0](./LICENSE).
