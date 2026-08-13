# Hikyo

Fully open-source secrets and configuration across environments, with
validation, explicit per-environment values, and no enterprise tier.

Hikyo is a self-hosted control plane for developers and platform engineers. It
ships as one Go binary, embeds its own web UI, supports SQLite and PostgreSQL,
and treats every value as explicitly `set` or `absent` in each environment.

> **Status:** active `0.x` development. Interfaces are not frozen until the
> `1.0.0` release gate passes, and there are no published binaries, images, or
> Helm charts yet — the supported install today is a source build.

## Why Hikyo

- **Explicit state.** Each key's value in each environment is `set` or `absent`.
  Values never inherit between environments, so development cannot silently
  supply a default to production and an empty cell is never ambiguous.
- **Declare before you write.** A key is declared (config vs. secret, validation
  and presence rules) before any value exists. Writes are validated at write
  time and rejected if the resulting environment state is invalid.
- **Secrets are a separate disclosure path.** Ordinary reads return presence and
  metadata, not plaintext. Revealing or copying a secret is a deliberate,
  reauthenticated action with its own audit event.
- **One authorization chokepoint.** Human sessions, machine identities, and
  local break-glass all evaluate against the same capability-and-scope model.
- **Fully open, no enterprise tier.** See below.

## Quickstart (local evaluation)

Requires Go 1.26+, Node.js 24 (see `.nvmrc`), and Corepack/pnpm.

```bash
# 1. Build the binary with the embedded UI
git clone https://github.com/Dunky13/hikyo.git
cd hikyo
corepack enable
pnpm --dir clients/ts install --frozen-lockfile
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
go build -tags ui -o ./bin/hikyo ./cmd/hikyo

# 2. Run a zero-config, loopback-only dev instance
#    Creates hikyo-dev.db + a 0600 root key in the current directory.
./bin/hikyo server --dev              # serves API + UI on http://127.0.0.1:8080
```

Open <http://127.0.0.1:8080> for the web UI, or check `curl --fail
http://127.0.0.1:8080/healthz`. The `-tags ui` build embeds the browser app; a
plain `go build` produces an API-only binary.

`--dev` is for evaluation only. From there,
[Getting started](https://hikyo.app/docs/getting-started/) walks through
creating the first administrator and
[Your first project](https://hikyo.app/docs/first-project/) through your first
key and value.

## CLI at a glance

One binary handles both server and client roles.

```bash
# Server / operator
hikyo server [--dev] [--listen ADDR] [--root-key-file PATH]
hikyo migrate                         # apply DB migrations
hikyo admin create --username admin   # host-only: bootstrap first authority
hikyo backup export | restore run     # host-only backup/restore

# Client (day to day)
hikyo login <instance-url> --local --as <user>
hikyo org create --name <name>
hikyo project create --name <name> --org <org-id>
hikyo env create --name <name> --org <org-id> --project <project-id>
hikyo context create <name> --instance <url> --org <id> --project <id> --env <id>
hikyo key create --context <ctx> --name NAME --classification config|secret \
  --declaration '{"rule":{"type":"string"}}'
hikyo values set NAME --context <ctx> --value-file PATH   # or --stdin / --clear
hikyo values get NAME --context <ctx>                     # presence + metadata
hikyo values get NAME --context <ctx> --reveal --output-file PATH   # plaintext
hikyo values list | diff | copy --context <ctx>
```

Secret values are never passed on the command line — use `--value-file` or
`--stdin`. Full command list:
[CLI reference](https://hikyo.app/docs/cli-reference/).

## Running in production

Outside `--dev` you must supply a datastore and a root key:

```bash
HIKYO_DB=sqlite:/var/lib/hikyo/hikyo.db \
HIKYO_EXTERNAL_ORIGIN=https://hikyo.example.com \
HIKYO_TRUSTED_PROXY_CIDRS=127.0.0.1/32 \
./hikyo server --listen 127.0.0.1:8080 --root-key-file /etc/hikyo/root.key
```

`HIKYO_DB` accepts `sqlite:PATH` or a PostgreSQL DSN. Terminate TLS at a reverse
proxy and keep the listener private. See
[Self-hosting](https://hikyo.app/docs/self-hosting/) and
[Configuration](https://hikyo.app/docs/configuration/) for every flag and
environment variable.

## Fully open, no enterprise tier

Every capability required to run Hikyo in production is and will remain open
source; there is no `/ee` directory and there will never be one.

The full commitment, including how it may be amended, is in
[GOVERNANCE.md](./GOVERNANCE.md#fully-open-pledge).

## Documentation

Full docs live at **<https://hikyo.app/docs/>**.

- [Getting started](https://hikyo.app/docs/getting-started/)
- [Core concepts](https://hikyo.app/docs/core-concepts/)
- [Self-hosting](https://hikyo.app/docs/self-hosting/)
- [CLI reference](https://hikyo.app/docs/cli-reference/)

Project policies:

- [Security policy](./SECURITY.md)
- [Support policy](./SUPPORT.md)
- [Governance](./GOVERNANCE.md)
- [Trademark policy](./TRADEMARK.md)
- [Contributing](./CONTRIBUTING.md)

## License

Hikyo is licensed under the [Mozilla Public License 2.0](./LICENSE).
