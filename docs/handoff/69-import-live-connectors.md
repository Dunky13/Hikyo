# #69 — Import live connectors (Kubernetes, Vault/OpenBao)

Parent: #41. Dependency: #68. Owning ADR: `docs/adr/import-paths.md`.
CLI spellings: `docs/spec/api-cli-spellings.md` § 3.

This slice adds read-only live source discovery to the two-phase import
framework from #68. `hikyo import` still only authors reviewable artifacts;
`hikyo values import` remains the only phase that writes values to Hikyo.

## Public entry points

```text
hikyo import --from k8s --live --namespace <ns> [--name <secret>] \
  [--kube-context <context>] --project <project> --environment <environment>

hikyo import --from vault --live --mount <mount> [--path <prefix>] \
  [--kv-version <1|2>] --project <project> --environment <environment>
```

`--file` and `--live` are mutually exclusive. SOPS and Infisical remain
file-only. A live mapping replay records its source selectors and does not need
`--file`; file-source replay continues to require one.

The library seam is `importer.RunLive(ctx, connector, LiveInput)`. Live
connectors implement the read-only `LiveConnector` interface and return the
same `Result` consumed by the planner as file connectors. Their non-secret
source identity is persisted in `run-manifest.json`; source credentials are
not.

## Kubernetes connector

- Loads the standard kubeconfig and optionally selects `--kube-context`.
- Requires a namespace. An optional `--name` reads one exact Secret; otherwise
  the connector lists the namespace with Kubernetes pagination. A reviewed
  replay may carry multiple previously discovered names.
- Imports Secret `data`, records each Secret `resourceVersion`, and preserves
  namespace/name selectors in `mapping.json`.
- Uses the official Kubernetes client. ExecCredential resolution, decoding,
  caching, refresh, and transport injection remain owned by client-go. The
  configured plugin command is carried in an environment-only invocation spec
  through Hikyo's hidden re-exec wrapper, which enforces the shared sanitized
  environment, deadline, and output cap before starting the plugin.

## Vault/OpenBao connector

- Uses the OpenBao API client so `BAO_*` configuration takes precedence, with
  compatible `VAULT_*` fallback.
- Requires a mount and accepts an optional path prefix. KV version may be
  pinned to 1 or 2 or detected from the mount.
- Recursively LISTs and reads keys, imports only the latest live version, and
  skips deleted or destroyed KV v2 versions. Non-string values are canonical
  JSON.
- Supports ambient tokens, token files, and external token helpers. The Vault
  library still owns `TokenHelper.Get`; external helpers are pointed at the
  same hidden re-exec wrapper so the actual helper receives the selected
  address and shared environment, deadline, and output bounds. Operator output
  states which ambient address, token, namespace, and TLS convention names won
  without exposing their values; only the origin enters the manifest.
- Adds strict JSONL capture-file parsing for replay fixtures. Each line must
  explicitly pin path, mount, engine version, secret version, both deletion
  state members, and data (including `{}` for skipped rows).

### Vault/OpenBao capture recipe

Use the source CLI's ambient configuration; never put a token on argv. Choose
`mount`, `prefix`, and `kv_version` first. Recursively enumerate the prefix with
`bao list -format=json` (or the compatible `vault` command), following names
ending in `/` and treating other names as leaves. Stop and fail if the walk
exceeds 1,000 LIST/READ requests, depth 32, any 5 MiB response, or a 4 MiB final
JSONL file. Sort complete leaf paths before capture so the file is stable.

For KV v1, emit one line per leaf:

```sh
bao read -format=json "$mount/$secret" |
  jq -c --arg path "$secret" --arg mount "$mount" \
    '{path:$path,mount:$mount,engine_version:1,deleted:false,destroyed:false,data:.data}'
```

For KV v2, read metadata first, pin `current_version`, inspect that version's
`deletion_time` and `destroyed`, then read that exact version only when it is
current. Emit deleted/destroyed lines with `{}` data so replay records the skip:

```sh
meta="$(bao read -format=json "$mount/metadata/$secret")"
version="$(printf '%s' "$meta" | jq -r '.data.current_version')"
deleted="$(printf '%s' "$meta" | jq -r --arg v "$version" '.data.versions[$v].deletion_time != ""')"
destroyed="$(printf '%s' "$meta" | jq -r --arg v "$version" '.data.versions[$v].destroyed')"
if [ "$deleted" = false ] && [ "$destroyed" = false ]; then
  bao kv get -mount="$mount" -version="$version" -format=json "$secret" |
    jq -c --arg path "$secret" --arg mount "$mount" --argjson version "$version" \
      '{path:$path,mount:$mount,engine_version:2,secret_version:$version,
        deleted:false,destroyed:false,data:.data.data}'
else
  jq -cn --arg path "$secret" --arg mount "$mount" --argjson version "$version" \
    --argjson deleted "$deleted" --argjson destroyed "$destroyed" \
    '{path:$path,mount:$mount,engine_version:2,secret_version:$version,
      deleted:$deleted,destroyed:$destroyed,data:{}}'
fi
```

Append each line to one `0600` file, then run `hikyo import --from vault
--file <capture.jsonl> …`. A bare `bao kv get -format=json` or `vault kv get
-format=json` response is not this capture format and is refused with this
section's path.

Required source ACLs, stated before the walk:

| Mode | Required capabilities |
|---|---|
| auto-detect | `read` on `sys/internal/ui/mounts/<mount>` |
| KV v1 | `list` and `read` below `<mount>/<prefix>` |
| KV v2 metadata | `list` and `read` below `<mount>/metadata/<prefix>` |
| KV v2 data | `read` below `<mount>/data/<prefix>` |

## Shared safety boundary

Both live connectors are read-only and share these fail-closed limits:

| Boundary | Limit |
|---|---:|
| whole live run | 10 minutes |
| individual request | 30 seconds |
| response body | 5 MiB |
| list pages / requests | 1,000 |

Cross-origin redirects are refused before credentials can follow. Provider
response bodies are never copied into errors. Every connector auth subprocess
runs through the hidden shared wrapper; its opaque invocation spec is removed
from the environment before the foreign child starts, all `HIKYO_*` material
is stripped, stderr is discarded, and timeout/overflow failures name only the
bound.

## Verification map

- `internal/importer/live_test.go`: pagination, exact scope/identity/version,
  hostile provider errors, redirects, OpenBao/Vault environment precedence,
  token helpers, and bounded Kubernetes exec auth.
- `internal/importer/connector_test.go`: strict Vault/OpenBao JSONL capture,
  exact JSON-number preservation, and streaming record bounds.
- `internal/cli/importer_internal_test.go`: fail-closed selector validation and
  live mapping replay.
- `internal/conformance/import_test.go`: live Kubernetes and Vault fixtures run
  through phase 1, reviewed artifacts, and the real phase-2 import path on each
  available database engine.

## Coordination notes

- #70 should consume `SourceIdentity` as an informational, non-secret manifest
  field. File sources continue to use their digest.
- The Kubernetes flag is `--kube-context`; `--context` already names a Hikyo
  context and must not be overloaded.
- No source-side mutation API is exposed. Future live connectors should
  implement `LiveConnector`, reuse the shared transport and subprocess bounds,
  and keep authentication out of mappings, manifests, and diagnostics.
