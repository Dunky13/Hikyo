# Wenv — API & CLI spellings deferred to synthesis (2026-08-06)

[api-cli-surface.md](../adr/api-cli-surface.md) is the API/CLI spec's skeleton; several later ADRs joined its closed grammar at declared join points and delegated their **exact spellings** to this document. Every spelling here is bound by the locked grammar (noun-verb families, output classes, print triad, exit codes, parity rules) and by the delegating ADR's constraints; a spelling that would violate either is a defect here, not a licence to reinterpret the ADR. Nothing here adds a verb class, an output class, or an endpoint outside the declared join points.

## 1. SCIM administration ([scim-provisioning.md](../adr/scim-provisioning.md))

Human-session verbs (full UI↔CLI parity: binding CRUD, mapping-table administration, credential mint/rotate/revoke, provisioned directory views; the *wire* endpoints under `/api/v1/orgs/{org}/scim/v2/{binding}/…` are fixed in the ADR and are parity-exempt protocol paths):

```
wenv scim binding create --org <org> --provider <provider>
wenv scim binding list   [--org <org>]
wenv scim binding show   <binding>
wenv scim binding delete <binding>            # runs the ADR's atomic 4-step teardown

wenv scim mapping add    <binding> --group <idp-group-id> --template <template>
wenv scim mapping update <binding> --group <idp-group-id> --template <template>
wenv scim mapping remove <binding> --group <idp-group-id>
wenv scim mapping list   <binding>

wenv scim credential mint   <binding>                    # a NEW credential; several may be live
wenv scim credential list   <binding>                    # ids + metadata, never token material
wenv scim credential show   <binding> <credential-id>
wenv scim credential revoke <binding> <credential-id>

wenv scim user  list <binding>                           # provisioned directory views
wenv scim group list <binding>
```

Credentials are **plural and id-addressable**: overlap rotation is mint-new → update IdP → revoke-old, identical authority throughout, per the machine-identity credential model the ADR inherits. `mint` is display-once under the print triad; formula `manage-members(org)` ∧ reauth.

Admin REST resources (ordinary `/api/v1` grammar, proof-carrying): `/api/v1/orgs/{org}/scim-bindings`, `…/{binding}`, `…/{binding}/mappings`, `…/{binding}/credentials`, `…/{binding}/credentials/{id}`, `…/{binding}/directory/users|groups`.

## 2. SAML provider configuration ([saml-sp.md](../adr/saml-sp.md))

Joins the **existing `instance-config` verb surface** — no new top-level verb family. Identity providers are a resource under that family (OIDC providers administer identically; `--kind` selects):

```
wenv instance-config provider create --kind saml --name <name> \
    --entity-id <byte-exact-entityID> \
    (--metadata-file <xml> | --metadata-url <url>)    # URL fetch runs the fingerprint ceremony
wenv instance-config provider list
wenv instance-config provider show    <name>
wenv instance-config provider update  <name> …
wenv instance-config provider disable <name>
wenv instance-config provider remove  <name>
wenv instance-config provider refresh-metadata <name>   # diff-and-confirm ceremony

wenv instance-config saml-sp-key list
wenv instance-config saml-sp-key rotate                 # old active becomes retiring; both publish
wenv instance-config saml-sp-key retire <fingerprint>   # retiring only; erases the private key
wenv instance-config saml-sp-key compromise-retire <fingerprint> # active only; replace atomically
```

All under `instance-config` capability, grant-evaluated `InstanceProof`, network path — never the local-admin class. `refresh-metadata` is the ADR's "action on the provider resource". SP keys are instance-wide, so their noun is deliberately a sibling of `provider`, not a provider subresource. Fingerprints are `sha256:` plus URL-safe unpadded base64 of SubjectPublicKeyInfo, so the exact value is safe as one path segment. `rotate` atomically marks the active key retiring and mints its replacement. Ordinary `retire` accepts only a retiring fingerprint; `compromise-retire` accepts only the active fingerprint and atomically erases and replaces it without an overlap window.

Admin REST resources (ordinary `/api/v1` grammar, proof-carrying):

- `GET /api/v1/instance/saml-sp-keys`
- `POST /api/v1/instance/saml-sp-keys/rotate`
- `DELETE /api/v1/instance/saml-sp-keys/{fingerprint}`
- `POST /api/v1/instance/saml-sp-keys/{fingerprint}/compromise-retire`

Provider list/show responses carry a required `warnings` array. Its closed warning codes are `metadata_expires_soon`, `metadata_expired`, `signing_certificate_not_yet_valid`, and `signing_certificate_expired`; each item carries `severity`, the relevant timestamp, a server-authored message, and a certificate fingerprint where applicable. The 30-day metadata threshold is server-authoritative. Provider table output names warnings, JSON preserves the structured array, and the existing top-level `wenv doctor [--instance REF] [-o table|json]` reports the same server-authoritative items (no second warning calculation and no additional endpoint). Doctor returns success for no findings or warning-severity findings; metadata-expired is error severity and returns the stable refused exit code after rendering the findings.

Identity-protocol endpoints (exception class, per-provider, parity-exempt):

- Start: `POST /api/v1/auth/saml/{provider}/start` (server-mints the AuthnRequest, RelayState transaction and path-scoped initiator binding)
- ACS: `POST /api/v1/auth/saml/{provider}/acs`
- SP metadata: `GET /api/v1/auth/saml/{provider}/metadata` (unauthenticated, documentation-class, pre-auth admission)

Per-provider ACS paths satisfy the validation algorithm's per-provider `Destination`/ACS binding. The initiator cookie is path-scoped to `/api/v1/auth/saml/{provider}/acs`.

## 3. Import ([import-paths.md](../adr/import-paths.md))

One top-level human-only verb `import`; the ADR fixes **three entry modes** — the spellings:

```
wenv import                                   # wizard: TTY, no source arguments
wenv import --from <k8s|sops|vault|infisical> --project <p> --environment <e> [selectors]
wenv import --mapping <mapping.json>          # replay, non-interactive
```

`import` without a TTY and without `--from`/`--mapping` is a hard error. Flag-mode selectors per connector: `--file <path>` (file mode, all connectors); live mode: `--live --namespace <ns> [--name <secret>]` (k8s), `--live --mount <m> [--path <prefix>] [--kv-version <1|2>]` (vault; version auto-detected from the mount when omitted); `--env <slug>` selects the source environment inside an Infisical export; SOPS and Infisical are file-only in v1. Flag mode targets exactly one `(project, environment)` and declares every value `string`. Common: `--out-dir <dir>` for the emitted artifacts (values files under the secret-file discipline: dirfd-parent-checked `O_EXCL`, `0600`).

Phase 2 is the existing pipeline, no new grammar: `definitions plan --file` → `definitions apply --plan`, then `values import --manifest <run-manifest.json> [--overwrite KEY,…]` (the one declared additive input: the run-manifest expected-state precondition; `--overwrite` names an enumerated list of `set`-bucket keys, skip-by-default otherwise).

**Wizard interaction states** (closed enumeration; the wizard is an authoring frontend for the mapping template):

1. Source select + mode (file/live) and credential-presence check (ambient only, never prompted for storage)
2. Source scope walk (connector selectors, bounded per the ops catalogue)
3. Environment mapping — including environments the session will create, declared up front
4. Folder mapping
5. Key review — renames (transform surfaced per rename; hard-stop names require explicit rename), classification (secret default; downgrades explicit per key), types (deterministic suggestions, applied only on accept)
6. Cross-environment reconciliation — one canonical identity/type/classification per key project-wide; conflicts resolved interactively (flag mode fails instead)
7. Collision review — `new | set` buckets; overwrite selection enumerated
8. Trim acknowledgements (values altered by TrimSpace refused unless acknowledged; recorded in the template)
9. Artifact emission + the plaintext-still-on-disk warning

**Mapping template** (`mapping.json`) — the portable record of every *choice*; names/paths/types only, **never values**; committable, replayable. Exact serialization (unknown fields reject loudly naming a version mismatch):

```json
{
  "format_version": 1,
  "connector_contract_version": 1,
  "source": "k8s | sops | vault | infisical",
  "scope": { "namespace": "…", "names": ["…"] },
  "project": "<project-id>",
  "environments": [ { "source": "<source-env-or-null>", "target": "<environment-id>", "create": false } ],
  "folders": [ { "source_path": "…", "target_path": "…" } ],
  "renames": [ { "from": "<source-name>", "to": "<KEY>", "transform": "auto | manual" } ],
  "classifications": [ { "key": "<KEY>", "class": "secret | config", "downgraded": false } ],
  "types": [ { "key": "<KEY>", "type": "string | integer | boolean | enum | url | json", "accepted": true } ],
  "overwrites": [ { "key": "<KEY>", "environment": "<environment-id>" } ],
  "trim_acknowledgements": [ { "key": "<KEY>", "environment": "<environment-id>" } ]
}
```

`scope` is connector-shaped: k8s `{namespace, names[]}` · vault `{mount, path_prefix, kv_version}` · sops/infisical `{file_digest}` (+ infisical `{env_slug}`).

**Run manifest** (`run-manifest.json`) — the bound record of one *run* and the phase-2 **precondition**; value-free, committable. `values import` verifies each occurrence token in-transaction; key movement rejects by name. Exact serialization:

```json
{
  "format_version": 1,
  "connector_contract_version": 1,
  "template": { "digest": "sha256:…" },
  "source_identity": { "kind": "k8s | sops | vault | infisical",
                       "context": "<cluster/context name | VAULT_ADDR origin | export-file digest>" },
  "source_versions": [ { "key": "<KEY>", "environment": "<environment-id>",
                         "version": "<resourceVersion | secret_version>" } ],
  "target": { "project": "<project-id>", "environments": ["<environment-id>"],
              "keys": [ { "name": "<KEY>", "id": "<key-id-or-null>" } ] },
  "definitions_revision": 0,
  "occurrences": [ { "key": "<KEY>", "environment": "<environment-id>", "token": "<server-minted opaque>" } ],
  "phase_completion": { "authored": true, "applied": false, "imported": { "<environment-id>": false } }
}
```

**Connector fixture contracts** (fixed here; byte content pinned when each connector is built): per connector, (a) true-positive mapping fixtures for its named capture format, (b) adversarial-parser fixtures (malformed/oversized/decompression-bomb inputs failing loudly at the named bound), (c) hostile-provider-error fixtures (errors sanitized structurally: keys/paths/bounds/codes, never content). Recorded in [open-items.md](./open-items.md) as an implementation-pinned moment.

## 4. Multi-instance ([multi-instance.md](../adr/multi-instance.md))

Verb spellings already fixed by that ADR's declared #25 amendment: `remote add|list|show|remove`, `remote-credential create|list|show|revoke`. The delegated handoff serialization, restating the locked **three-leg flow** exactly:

1. **Start** — the viewing UI opens the remote's authorization page in a popup with `noopener`: `GET {remote}/api/v1/auth/handoff/start?state=<opaque>&code_challenge=<S256>&redirect_uri=<exact pre-registered callback>&purpose=<establishment|step-up>`. The remote creates a short-lived server-side **transaction** binding state, the exact callback URI, the requesting origin, the PKCE challenge, the purpose, and — once authenticated — the target human. An **establishment** transaction additionally records that no prior session exists (purpose alone licenses issuance); a **step-up** transaction binds the initiating workspace-session id, the exact operation elevated, and (where key-scoped) the environment and enumerated key set. These bindings are server-side transaction state, never URL parameters. The human authenticates with the remote's own ceremonies.
2. **Callback** — on approval the remote redirects **code + state only** to the exact pre-registered callback (the allowlist entry is the `redirect_uri` authority) — a same-origin page of the viewing UI, which hands the result to the shell over a **nonce-named `BroadcastChannel`** and closes. The front channel never carries the artifact.
3. **Redemption** — the shell redeems cross-origin: `POST {remote}/api/v1/auth/handoff/token` with `{"code": "<code>", "code_verifier": "<pkce>"}` → the **workspace session** bearer in the response body (never a redirect fragment, never a cookie; JS memory only).

Transactions are single-use, atomically consumed, expiring per [ops-catalogue.md](./ops-catalogue.md); every handoff path (start, callback, redemption) is classified pre-authentication under the remote's admission limits.

**CORS** (remote side): allowed origins = exactly its configured requesting origins (no wildcard, no `null`); methods `GET POST PUT DELETE`; headers `Authorization, Content-Type`; `Access-Control-Allow-Credentials: false` — the bearer rides the Authorization header, cookies never cross this channel, CSRF posture untouched.

Directory and workspace **UI states** are specified in [ui-spec.md](./ui-spec.md) § Multi-instance.

## 5. Canonical key grammar

Restated in [domain-model.md](./domain-model.md) § Canonical key grammar, satisfying import-paths.md's delegation.
