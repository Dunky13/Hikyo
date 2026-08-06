# Envweave — API & CLI spellings deferred to synthesis (2026-08-06)

[api-cli-surface.md](../adr/api-cli-surface.md) is the API/CLI spec's skeleton; several later ADRs joined its closed grammar at declared join points and delegated their **exact spellings** to this document. Every spelling here is bound by the locked grammar (noun-verb families, output classes, print triad, exit codes, parity rules) and by the delegating ADR's constraints; a spelling that would violate either is a defect here, not a licence to reinterpret the ADR. Nothing here adds a verb class, an output class, or an endpoint outside the declared join points.

## 1. SCIM administration ([scim-provisioning.md](../adr/scim-provisioning.md))

Human-session verbs (UI↔CLI parity, ordinary stdout; the *wire* endpoints under `/api/v1/orgs/{org}/scim/v2/{binding}/…` are fixed in the ADR and are parity-exempt protocol paths):

```
envweave scim binding create --org <org> --provider <provider>
envweave scim binding list   [--org <org>]
envweave scim binding show   <binding>
envweave scim binding delete <binding>            # runs the ADR's atomic 4-step teardown

envweave scim mapping add    <binding> --group <idp-group-id> --template <template>
envweave scim mapping update <binding> --group <idp-group-id> --template <template>
envweave scim mapping remove <binding> --group <idp-group-id>
envweave scim mapping list   <binding>

envweave scim credential mint   <binding>          # display-once, print triad; manage-members(org) ∧ reauth
envweave scim credential show   <binding>          # metadata only, never the token
envweave scim credential revoke <binding>

envweave scim directory users  <binding>
envweave scim directory groups <binding>
```

Admin REST resources (ordinary `/api/v1` grammar, proof-carrying): `/api/v1/orgs/{org}/scim-bindings`, `…/scim-bindings/{binding}`, `…/scim-bindings/{binding}/mappings`, `…/scim-bindings/{binding}/credential`, `…/scim-bindings/{binding}/directory/users|groups`. All formulas per the ADR (`manage-members` at org scope; credential mint additionally reauth).

## 2. SAML provider configuration ([saml-sp.md](../adr/saml-sp.md))

Joins the **existing** instance-config provider surface — no new verb family:

```
envweave provider create --kind saml --name <name> …   # metadata by --metadata-file or fetch-with-fingerprint ceremony
envweave provider list | show <name> | update <name> | disable <name> | remove <name>
envweave provider refresh-metadata <name>              # diff-and-confirm ceremony, instance-config
```

Identity-protocol endpoints (exception class, per-provider, parity-exempt):

- ACS: `POST /api/v1/auth/saml/{provider}/acs`
- SP metadata: `GET /api/v1/auth/saml/{provider}/metadata`

Per-provider ACS paths satisfy the validation algorithm's per-provider `Destination`/ACS binding. The initiator cookie is path-scoped to `/api/v1/auth/saml/{provider}/acs`.

## 3. Import ([import-paths.md](../adr/import-paths.md))

Top-level human-only verb `import`; one connector per source; phase 1 authors artifacts and stops.

```
envweave import k8s       --project <p> [--file <manifest.yaml> | --live [--namespace <ns>…]] [flags]
envweave import sops      --project <p> --file <file> [flags]
envweave import vault     --project <p> [--file <capture.jsonl> | --live --mount <m> [--path <prefix>]] [flags]
envweave import infisical --project <p> --file <export.json> [flags]
```

Common flags: `--out-dir <dir>` (artifact destination, `O_EXCL`/`0600` discipline for values files); wizard is the default on a TTY; **flag mode** = `--no-wizard --environment <env>` (exactly one `(project, environment)`, everything typed `string`). Phase 2 is the existing pipeline: `definitions plan/apply`, then `values import --manifest <run-manifest.json> [--overwrite KEY,…]` (`--overwrite` names an enumerated list of `set`-bucket keys; skip-by-default otherwise).

**Mapping template** (`mapping.json`, versioned): `{"version": 1, "source": "<connector>", "project": "<id>", "renames": [{"from": "<source-name>", "to": "<KEY>", "transform": "auto|manual"}], "classifications": [{"key": "<KEY>", "class": "secret|config", "downgraded": bool}], "trim_acknowledgements": ["<KEY>", …], "types": [{"key": "<KEY>", "type": "<primitive>", "accepted": bool}]}` — every rename, every explicit downgrade, every trim acknowledgement is recorded here; unknown fields reject loudly naming a version mismatch.

**Run manifest** (`run-manifest.json`, versioned): `{"version": 1, "project": "<id>", "source": "<connector>", "occurrences": [{"key": "<KEY>", "environment": "<env-id>", "token": "<server-minted opaque>"}]}` — the phase-2 precondition; `values import` verifies each occurrence token in-transaction; a key movement rejects by name. Tokens are single-run, server-minted during phase-1 reads (which require `read(E)` per consulted environment, never `reveal`).

Connector test fixtures (adversarial parsers, hostile-provider errors, per-source captures) are **implementation artifacts** pinned when the connectors are built, per the ADR's fixture language; the contract they must satisfy is fixed in the ADR. Recorded in [open-items.md](./open-items.md).

## 4. Multi-instance ([multi-instance.md](../adr/multi-instance.md))

Verb spellings already fixed by that ADR's declared #25 amendment: `remote add|list|show|remove`, `remote-credential create|list|show|revoke`. Remaining delegated serializations:

- **Handoff transaction** (cross-origin UI handoff, exception-class endpoints on the remote): popup opens `GET {remote}/api/v1/auth/handoff/start?tx=<id>&code_challenge=<S256>&origin=<requesting-origin>`; completion posts `POST /api/v1/auth/handoff/complete` with `{"tx": "<id>", "code_verifier": "<pkce>"}` returning the workspace-session bearer in the response body (never a redirect fragment, never a cookie). Transaction is server-side, single-use, purpose-bound, expiring per [ops-catalogue.md](./ops-catalogue.md).
- **CORS**: remote allows exactly its configured requesting origins (no wildcard, no `null`), methods `GET POST PUT DELETE`, headers `Authorization, Content-Type`, `Access-Control-Allow-Credentials: false` (bearer rides the Authorization header; cookies never cross this channel).

## 5. Canonical key grammar

Restated in [domain-model.md](./domain-model.md) § Canonical key grammar, satisfying import-paths.md's delegation.
