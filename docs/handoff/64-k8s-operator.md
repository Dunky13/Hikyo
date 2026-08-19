# Handoff: #64 Kubernetes operator — CRDs, controller, kind harness

Issue: https://github.com/Hikyo-Org/hikyo/issues/64 (parent #41; mvp-boundary
M3). Spec: [`docs/adr/k8s-integration.md`](../adr/k8s-integration.md), with
[`system-architecture.md`](../adr/system-architecture.md) § multicall (operator
is a separate deployable, controller-runtime, no root key in the operator pod),
[`ops-spec.md`](../adr/ops-spec.md) § K8s operator values, and
[`machine-identities.md`](../adr/machine-identities.md) § fetch path. Blocked-by
#62 is merged; this builds on its `delivery.fetch` surface and cursor.

## Part 0 — Contract (locked by the orchestrator before fan-out)

Everything below is a decision, not a proposal. Implementers follow it; an
implementer who finds it wrong stops and reports rather than improvising.

### 0.1 Why this ticket touches the server: values on `delivery.fetch`

`delivery.fetch` today delivers names, classification and presence — **no
value member** — and `internal/service/delivery.go` plus the audit registry
explicitly reserve "the ticket that ships values" for the first delivery
consumer. The operator cannot converge a Secret from a value-free projection,
so #64 ships that slice; #63 (Compose) rebases onto it (recorded on issue #63).
It is integration-neutral (k8s ADR § *Expansion-ready*: no operator-special
endpoints).

Wire contract (`api/openapi.yaml`, spec-first, then `go tool oapi-codegen
--config api/oapi-codegen.yaml api/openapi.yaml` and `pnpm generate` for the TS
client):

- `DeliveredKey` gains optional `value: string` (maxLength per the existing
  value bound). Present **iff** the plaintext was delivered; absent means
  presence-only. Rules, evaluated server-side per key at the addressed
  environment, uncached, in-transaction:
  - `config` keys: delivered under `read` (the operation's existing formula).
  - `secret` keys: delivered under `read ∧ reveal` (grant rows on the machine
    principal); for a **pinned non-current** revision, `read ∧ reveal-history`.
    Otherwise the key is delivered **presence-only** (`presence: set`, no
    `value`).
  - The per-project machine-`reveal` opt-in API (#17/#58) is NOT built here.
    Machine `reveal` grants are refused by the grant API today; tests seed the
    grant row at store level exactly as `internal/isolation` already does.
- New query parameter `projection`, enum `[full, config-only]`, default
  `full`. `config-only` is a **server-side authorized term**: secret keys are
  omitted from `keys` entirely (not presence-only), the manifest the change
  token is computed over is the config projection, and the mode is **bound
  into the cursor** (new `Mode` field in `internal/delivery.Cursor`, encoded
  like the other fields — every outstanding cursor mismatches once, which is
  the designed upgrade path).
- New query parameter `acknowledged_keys`: array of key names (style `form`,
  `explode: false`, i.e. comma-separated; each item under the key-name
  grammar, max 64 items). The server **records** it on the fetch audit record
  and otherwise ignores it — it filters nothing and refuses nothing. The
  loader-control refusal is enforced by the operator against its mapping (the
  server cannot see the mapping); see § 0.6 and the deviations section.
- `DeliveryResponse` gains optional `credential_expires_at: date-time` — the
  presenting credential's expiry when it is finite (bearer `expires_at`;
  federated: the binding's expiry). Absent for indefinite. The operator
  surfaces it as the ADR's ahead-of-time expiry condition/event.
- Stale prose to fix in the same pass: `change_token` description in
  `api/openapi.yaml` and the `ChangeToken` comment in
  `internal/service/delivery.go` say the operator's annotation consumes the
  change token. The k8s ADR's declared amendment says the opposite: **the change
  token is cursor/change-detection material only; the workload-visible value is
  the client-side per-target keyed stamp.** Reword both.

Audit (`internal/audit/registry.go`, closed registry with closure invariant):

- Register `identity.disclosure` — one immutable event **per delivered
  value**, `class=access`, referencing the fetch record by correlation id,
  payload: `key` (name), `classification`, `credential_id`, `credential_kind`,
  `principal_class`, `scope`, `revision` (the delivered revision — pinned or
  latest), `projection`. Presence-only keys emit **nothing** (no value crossed).
- Extend `identity.delivery_fetched` payload with `projection`
  (`full|config-only`), `acknowledged_keys` (the list as presented, may be
  empty), `delivered_count` (values actually delivered) alongside the existing
  `key_count`. The fetch record is the envelope; per-key events reference it
  (audit-model § envelope). `disposition: current` → zero per-key events.
- No migration is expected. Values come from snapshot entries already opened
  in `deliveryRows`; audit payloads are schemaless. Reaching for a migration is
  a smell to stop and report.

Tests for this slice (Go): service-level in `internal/service` or
`internal/isolation/delivery_e2e_test.go` — config value delivered under
`read`; secret presence-only without `reveal`; secret plaintext with seeded
`reveal`; `config-only` omits secrets and moves the cursor vs `full`;
`acknowledged_keys` lands verbatim on the record; per-key cardinality (N values
→ N `identity.disclosure` rows, 0 on `current`); `credential_expires_at`
present for finite, absent for indefinite; contract test for the new params in
`internal/server` or `api/noproxy_test.go` per the existing pattern. Run the
PG leg for the store-touching tests (`HIKYO_TEST_POSTGRES_DSN`, see
`docs/handoff/62-oidc-federation-cursor.md` § Verification).

### 0.2 API group, kinds, spellings

- Group `hikyo.dev`, version `v1alpha1`. Go types in
  `internal/operator/api/v1alpha1` (kubebuilder markers, `controller-gen`
  pinned as a `go tool` — same pattern as `go tool oapi-codegen`), CRD YAML
  generated into `chart/hikyo/crds/` and checked by the `generated` CI job
  (regenerate + `git diff --exit-code`).
- **`HikyoInstance`** (cluster-scoped). `spec`: `url` (string, CEL:
  `self.startsWith('https://')`), `caBundle` (optional, base64 PEM; absent =
  system roots), `audience` (optional string; **required for the federation
  path**, the per-instance TokenRequest audience — never the API-server
  default). **Whole `spec` immutable**: `x-kubernetes-validations:
  self == oldSelf` on `spec`. No credential-shaped field exists. There is no
  insecure-skip-verify field and never will be.
- **`HikyoSecret`** (namespaced, status subresource). `spec`:
  - `instanceRef.name` (immutable).
  - `auth`: exactly one of `secretRef.name` | `serviceAccountRef.name`
    (CEL one-of). Both same-namespace only (never a namespace field).
  - `scope`: `org`, `project`, `environment` (Hikyo ids as the API takes them
    in the path).
  - `mapping[]`: `{key: <source key name>, secretKey: <data key; default =
    key>}`; `mapping` non-empty, `secretKey` unique.
  - `target`: `name` (immutable, ≤ 63 chars — see stamp annotation below),
    `creationPolicy: Owner|Orphan` (default `Owner`). `Orphan` keeps the
    controller ownerRef during the CR's life (so the authority test is one
    rule) and a finalizer `hikyo.dev/orphan` strips the ownerRef on CR
    deletion before the CR is released — the Secret survives, unowned.
  - `projection: full|config-only` (default `full`).
  - `acknowledgedLoaderKeys: []string` (see § 0.6).
  - `resyncInterval` (duration string, default `5m` — ops-spec requeue).
  - `status`: `conditions[]` (below), `observedGeneration`, `cursor`
    (opaque server cursor; non-secret by construction), `cursorBinding` (hex
    digest of the local binding tuple, § 0.5), `stamp` (last delivered stamp),
    `managedSecretUID`, `managedSecretResourceVersion`, `lifecycle`
    (`Synced|Retained|Scrubbed|Refused|Unreconciled`), `credentialExpiresAt`,
    `lastFetch` (time), `lastDelivery` (time).
- **Designation** (ADR § identity — naming a credential is not authority to use
  it). On the bootstrap Secret and on the ServiceAccount, **both labels**
  required: `hikyo.dev/delivery: "true"` and `hikyo.dev/instance:
  <HikyoInstance name>`; the instance label must equal the CR's
  `instanceRef.name`. Bootstrap Secret data key: `hikyo-token`. Missing or
  mismatched designation → no reconcile, condition below.
- **Workload opt-in annotation** (on Deployment/StatefulSet/DaemonSet
  `metadata.annotations`): `hikyo.dev/secrets: "<name>[,<name>…]"` naming the
  managed Secret(s) it consumes. The operator patches the **pod template**
  annotation `stamp.hikyo.dev/<managed-secret-name>: v1:<32 hex>` (key
  name-part ≤ 63 chars, hence `target.name` ≤ 63). Only workloads in the CR's
  namespace; only those carrying the opt-in naming this target.
- Operator stamp root: Secret `hikyo-operator-stamp-root` in the operator's own
  namespace, data key `root` (32 random bytes), created by the operator on first
  need if absent. Per-target key = HKDF-SHA256(root, salt = nil, info =
  `"hikyo/k8s-stamp/v1|" + instanceUID + "|" + crUID + "|" + secretName`).
  Stamp = `v1:` + hex(first 16 bytes of HMAC-SHA256(key, canonical encoding)).
  Canonical encoding: version byte/prefix `hikyo-k8s-stamp-v1`, then the
  delivered `(secretKey, value)` pairs sorted by `secretKey`, each field
  length-prefixed (reuse the `internal/delivery` `appendField` shape). **Code
  lives in `internal/crypto` (`stamp.go`)** — the boundary test confines
  `crypto/hmac` and `crypto/hkdf` there. Only the legacy
  `wenv/change-token/v1` label is frozen; new labels use `hikyo/`.

### 0.3 Conditions (closed reason set — one reason per ADR-named state)

Type `Ready` (summary, True only when `Synced=True` and no refusal condition
is active) and type `Synced` plus the specific ones:

| Condition | Reason | When |
|---|---|---|
| `Synced=True` | `Delivered` / `Current` | full delivery written / cursor answered current |
| `Synced=False` | `FetchFailed` | network error, 5xx, 429, **401** — retain last Secret, requeue with backoff |
| `Synced=False` | `NotMaterialized` | server says no published revision (409) — retain/empty, requeue |
| `Designation=False` | `SecretNotDesignated` / `ServiceAccountNotDesignated` / `InstanceMismatch` | designation labels missing or naming another instance |
| `Designation=False` | `AudienceMissing` | SA path with an instance lacking `audience` |
| `Conflict=True` | `ManagedSecretNotOwned` | target exists without this CR's controller ownerRef (takeover refused) |
| `Conflict=True` | `TargetClaimed` | another HikyoSecret (earlier by UID/creation) names the same target |
| `Delivery=False` | `UndeliveredSecrets` | all-or-nothing: mapped secret keys arrived presence-only; message names keys + the opt-in |
| `Delivery=False` | `KeysMissing` | mapped source keys absent from the manifest → converge (drop them); condition lists them |
| `Delivery=False` | `LoaderControlUnacknowledged` | mapped `secretKey` on the baseline without exact acknowledgement; names keys |
| `Delivery=False` | `EnvFromSkip` (warning, `Synced` still True) | a `secretKey` is not a valid env identifier — documented Kubernetes caveat |
| `Scrubbed=True` | `AuthorizationWithdrawn` | 404 under an authenticating credential → Secret converged to empty |
| `Rollout=False` | `Stalled` | opted-in workload not progressed after the stamp patch (observedGeneration/unavailable per the workload controller's own status) |
| `CredentialExpiry=True` | `ExpiresSoon` / `Expired` | `credential_expires_at` within 7 days / passed |
| `Unreconciled=True` | `NamespaceNotBound` | cluster-wide install, CR in a namespace excluded from authority (RBAC forbidden) |

Every `False`/refusal condition also emits a Kubernetes Event on the CR.

### 0.4 Server outcome → Secret lifecycle (the ADR's three answers)

| Outcome | Class | Action |
|---|---|---|
| transport error, 5xx, 429, 401 (dead/expired/revoked credential, failed TokenRequest, unbound federation) | ADR case 2 | **retain** last-synced Secret unchanged, `Synced=False/FetchFailed`, event, exponential backoff 1 s → 5 min jittered; **no staleness scrub, ever** |
| 404 (authenticated principal; scope nonexistent-or-unauthorized) | ADR case 3 | **converge**: managed Secret data → empty (`Scrubbed=True`), cursor cleared, stamp re-computed and patched (so opted-in workloads roll into the scrubbed state) |
| 200 with mapped keys missing from manifest | ADR case 3 | converge: drop those data keys; `Delivery=False/KeysMissing` informational |
| 200 with mapped secret keys presence-only | refusal | **no write at all** (not even partial); `Delivery=False/UndeliveredSecrets`; retain existing Secret |
| 200 `current: true` | normal | nothing written, `Synced=True/Current` |
| 200 full | normal | write ordering § 0.5 |

401-vs-404 is verified against the chokepoint: `authenticateMachine` answers
`ErrUnauthenticated` (→ 401) for unknown/revoked/expired/epoch-stale bearers;
lost `read` or a missing scope answers the uniform `ErrNotFound` (→ 404). Any
unrecognized status → treat as case 2 (fail-safe: retain).

### 0.5 Write ordering and cursor eligibility (normative)

Per CR, serialized (controller-runtime's per-key serialization suffices;
`MaxConcurrentReconciles` may be > 1 because keys are distinct CRs):

1. **Managed Secret** — create only if absent, **always** with this CR's
   controller ownerRef (the controller-UID check is the authority test in both
   policies); otherwise `Update` only when
   `metav1.IsControlledBy(secret, cr)` — **never adopt** — with the
   `resourceVersion` precondition from the read, then re-`Get` and verify the
   data matches what was written.
2. **Workload patches** — for each Deployment/StatefulSet/DaemonSet in the
   namespace whose `hikyo.dev/secrets` names the target and whose current pod
   template stamp differs: strategic-merge patch the pod template annotation.
   Patch failures are surfaced (`Rollout=False`) but do not roll back the
   Secret.
3. **Cursor** — persist `status.cursor` + `status.cursorBinding` + `stamp` +
   `managedSecretResourceVersion` **last**, only after 1 and 2 succeeded. A
   failure before this leaves no cursor, so the next reconcile is a full fetch
   (idempotent: content-convergent Secret write, pure-function stamp).

Cursor is presented only when **all** hold: `status.cursor != ""`; managed
Secret exists, is controlled by this CR, and `stamp(current data) ==
status.stamp`; and `status.cursorBinding` equals the digest of
`(credential identity = referenced Secret/SA UID + resourceVersion, org,
project, environment, projection, mapping digest over (key, secretKey) pairs,
target name, HikyoInstance UID, stamp-key version "v1")`. Any mismatch →
cursor-less full fetch. The cursor is never advanced after a failed or refused
sync. Rotate-token-key on the server invalidates cursors server-side; the
resulting full fetch with unchanged content yields the same stamp → **no
workload patch, no restart wave** (the ADR's declared consequence; an E2E
asserts it).

Credential use per fetch: bootstrap → `Authorization: Bearer <hikyo-token>`;
federation → `TokenRequest` on the designated SA with `audiences:
[instance.spec.audience]`, `expirationSeconds: 600` (the API-server minimum),
token held in memory only, re-minted per fetch (never cached to disk/status).

### 0.6 Loader-control baseline (operator-enforced)

Baseline list verbatim from the Compose ADR: `LD_*`, `PATH`, `IFS`, `ENV`,
`BASH_ENV`, `SHELLOPTS`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PYTHONPATH`,
`PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`,
`_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CLASSPATH`, `GIT_*`, `SSL_CERT_FILE`,
`SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`.
Lives in `internal/delivery/loadercontrol.go` (shared with #63 later). A
mapping whose `secretKey` matches the baseline is refused
(`LoaderControlUnacknowledged`) unless `spec.acknowledgedLoaderKeys` lists
**exactly** those keys (extra acknowledged names that are not mapped are
also a refusal — the acknowledgement is exact, not a wildcard). The
acknowledged list is sent as `acknowledged_keys` on every fetch so the server's
record carries it.

### 0.7 Operator deployable, scoping, chart

- `hikyo operator` mode in `cmd/hikyo/main.go` → `internal/operator`
  (manager: controller-runtime **v0.24.x**, pairs with k8s.io/* v0.36; leader
  election on; health/readyz on `:8081`, metrics on `:8080`; informer resync
  **10h explicit**; requeue 5 min; backoff 1 s → 5 min jittered). Config via
  `HIKYO_OPERATOR_*` env only: `NAMESPACES` (comma list; empty = cluster-wide),
  `TRIGGER_ROLLOUTS` (bool, default true), `OPERATOR_NAMESPACE` (own ns for the
  stamp root; default from the downward API / `POD_NAMESPACE`). Missing
  required config = hard error at boot. No keyring, no root key, no datastore.
- Helm chart `chart/hikyo`: add `operator` Deployment (mode-pinned
  `args: [operator]`), CRDs under `crds/`, ServiceAccount, RBAC generated from
  ONE input `operator.namespaces` (empty → ClusterRole+ClusterRoleBinding;
  list → Role+RoleBinding per namespace, and the watch list env derived from
  the same value), `serviceaccounts/token` `create` restricted by
  `resourceNames` to `operator.designatedServiceAccounts[<ns>]`, workload
  patch verbs omitted entirely when `operator.triggerRollouts=false`, stamp-root
  Secret referenced not templated. Hardening defaults ON for **both** server
  and operator Deployments: `runAsNonRoot`, read-only root fs, drop ALL caps,
  `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`,
  operator resources `50m/64Mi`–`200m/128Mi`. `helm lint` + `helm template`
  assertions in CI (the existing chart test pattern if any; else a Go test
  that shells `helm template`).

### 0.8 E2E harness (M3) — scope statement

Go test package `internal/operator/e2e` behind build tag `k8se2e`, run only
when `HIKYO_K8S_E2E_KUBECONFIG` (or `KIND_CLUSTER` created by the harness) is
set. The Hikyo server runs **in-process on the host** (the `internal/isolation`
harness pattern, ports from the claimed block `45850–45852`), the operator
manager runs **in-process against the kind API**, workloads use
`registry.k8s.io/pause`. Deploying the operator as a pod (image build + `kind
load`) is deliberately out of scope for M3's assertions; the chart is verified
by `helm template`/lint. Stated here so the PR says it out loud.

Scenarios (each an assertion, not a smoke): converge (config + seeded-reveal
secret, Secret data byte-exact, stamp annotation on the opted-in Deployment,
non-opted-in Deployment untouched); rotate-token-key → full fetch, **zero**
workload patches / no new ReplicaSet; undesignated Secret refused, undesignated
SA refused, wrong-instance designation refused; existing unowned Secret refused
(no write, condition), two CRs same target → loser refused; orphan-vs-scrub:
CR delete with Owner → Secret GC'd, with Orphan → retained; revoke credential →
retain + `FetchFailed`; remove `read` while credential alive → scrubbed;
write ordering asserted via a recording client interposed on the manager
(Secret update → workload patch → status cursor, and a fault injected after
the Secret write leaves `status.cursor` empty); federation leg via static JWKS
from `kubectl get --raw /openid/v1/jwks`, issuer = the cluster's SA issuer,
`refused_audiences` = the API-server default audience, bound per-instance
audience.

CI: job `k8s-e2e` (kind via pinned `helm/kind-action` or a pinned binary),
added to `scripts/ci/classify-changed-paths.sh` AND `ci-required.needs`.

### 0.9 Fog values chosen (ratify or override)

| Value | Chosen | Source |
|---|---|---|
| requeue / resync interval default | 5 min | ops-spec |
| error backoff | 1 s → 5 min, jittered | ops-spec |
| informer full resync | 10 h explicit | ops-spec |
| operator resources | 50m/64Mi – 200m/128Mi | ops-spec (measured on Pi before freeze, #77) |
| TokenRequest expiry | 600 s | API-server minimum |
| credential expiry warning horizon | 7 days | this ticket (no ops-spec value) |
| stamp length / version | 128 bit, `v1:` | k8s ADR |
| `acknowledged_keys` max items | 64 | this ticket |

## Part 1 — What shipped

_(filled in by the orchestrator as work packages land)_

## Deviations and interpretations needing ratification

1. **Loader-control refusal has no server emitter.** The audit catalogue lists
   "loader-control refusal" under `fetch`; the server cannot evaluate it (it
   does not see the CR mapping), so it is a CR condition + Kubernetes Event, and
   the server records the acknowledged list on the fetch record (the ADR
   sentence verbatim). Not registered in the closed audit registry (closure
   invariant refuses emitterless types).
2. **Machine-`reveal` opt-in API not built** (#17/#58 ownership); tests seed
   grant rows.

## Files touched / Verification / Open items

_(filled in as work lands)_
