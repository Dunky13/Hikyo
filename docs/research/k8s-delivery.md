# Kubernetes Secret Delivery for Hikyo

Research memo, 2026-07-29. Scope: how Hikyo-managed values reach workloads on K3s/small K8s. Five mechanisms compared, ranked recommendation at the end. Sources are primary (official docs, GitHub repos) and linked inline.

## Option 1 — Own minimal operator (HikyoSecret CRD → native Secret)

A small Go controller (controller-runtime) watching an `HikyoSecret` CRD, fetching values from the Hikyo server, and writing/patching a native `Secret` it owns.

### Prior art

- **External Secrets Operator (ESO)** is the reference architecture: [`ExternalSecret`](https://external-secrets.io/latest/api/spec/) maps provider keys to Secret keys via `data[].remoteRef` / `dataFrom`, with `refreshPolicy` (`CreatedOnce` | `Periodic` with `refreshInterval`, default 1h | `OnChange`), `creationPolicy` (`Owner` default — ownerReference so the Secret is GC'd with the CR; `Orphan`; `Merge`), `deletionPolicy` (default `Retain` — don't delete the Secret if the upstream disappears), and Go-template `template` for reshaping values. Connection/auth config lives in a separate `SecretStore`/`ClusterSecretStore` object. This split (store = connection, secret = mapping) is worth copying; it keeps credentials out of every manifest.
- **Infisical's operator** ([InfisicalSecret CRD](https://infisical.com/docs/integrations/platforms/kubernetes/infisical-secret-crd)) is the closest shape to what Hikyo needs: one CRD carrying auth ref + project/env selector + `managedKubeSecretReferences` (with `creationPolicy` Owner/Orphan for GitOps friendliness), `resyncInterval` (default 60s, min 5s), `hostAPI` + `tls.caRef` for self-hosted instances, Go-template transformation, and **auto-redeploy**: workloads annotated `secrets.infisical.com/auto-reload: "true"` get a rolling restart when their managed Secret changes. Auth options include Kubernetes-native auth (ServiceAccount token, reviewed server-side), universal auth (client id/secret), and static service token.
- **Sealed Secrets** ([bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)) shows the same CRD→Secret controller pattern for the GitOps-encrypted case: `SealedSecret` CR, controller decrypts to a native Secret, `kubeseal` CLI, 30-day sealing-key renewal, three scopes (strict / namespace-wide / cluster-wide). Relevant to Hikyo mostly as proof that a single-purpose controller of this kind is a small, boring, long-lived piece of software — not for its crypto model (Hikyo holds plaintext server-side).
- **Reloader** ([stakater/Reloader](https://github.com/stakater/Reloader)) is the standard rollout trigger: annotation `reloader.stakater.com/auto: "true"` (or per-resource `secret.reloader.stakater.com/reload: "name"`), and it forces the rollout by mutating the pod template — default strategy injects a dummy env var whose value is a hash of the changed resource; alternative `annotations` strategy writes `reloader.stakater.com/last-reloaded-from` into pod template metadata (preferred under Argo/Flux to avoid drift). Footprint: 10m CPU / 128Mi requests. Apache-2.0.

### Assessment

- **Build cost**: one CRD + one reconcile loop + one HTTP client. With kubebuilder scaffolding this is days-to-weeks, not months. Restart triggering (hash annotation on owning workloads, Infisical-style opt-in annotation) is ~100 lines; alternatively document "pair with Reloader" and ship nothing.
- **Maintenance**: you own K8s API version churn (CRD apiextensions is stable; controller-runtime bumps are routine), one small Helm chart/manifest. This is the smallest maintenance surface of any operator-shaped option.
- **Security posture**: values land in native Secrets → **persisted in etcd/SQLite datastore**. On K3s that store is *plaintext by default*; mitigate by documenting `--secrets-encryption` (below). In exchange you get the whole native ecosystem: `envFrom`, RBAC on Secrets, namespace isolation for free (Secret created in the CR's namespace, ownerReference-bound). RBAC for the controller: needs get/create/update on Secrets — scope it to namespaces or label-selected Secrets rather than cluster-wide `secrets: *` where possible.
- **Workload identity**: two tiers. (a) Static Hikyo token in a bootstrap Secret — simple, works everywhere, but a long-lived credential at rest. (b) Kubernetes-native auth: the operator sends its **projected ServiceAccount token** (TokenRequest, audience-bound, short-lived — [K8s SA docs](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)) and Hikyo validates it via the **TokenReview API** (needs an Hikyo-side kubeconfig/reviewer token per cluster) or, cleaner for a server outside the cluster, via **OIDC service-account issuer discovery** (`/.well-known/openid-configuration` on the API server) — validate the JWT offline against the cluster's JWKS, no callback into the cluster needed. Infisical ships exactly this pair (native auth + token reviewer). OIDC federation is the right long-term answer; static token is an acceptable v1 floor.
- **Refresh & rollout**: poll on `resyncInterval`; on change, patch Secret + bump hash annotation on opted-in workloads → rolling restart. This matches Hikyo's changes-apply-on-restart model exactly — no sidecar needed.
- **Failure modes**: Hikyo unreachable → last-synced Secret **remains in the cluster**; pods keep starting with stale-but-valid values (this is the big resilience win of the sync-to-Secret model). Controller down → same, no refresh but no outage. Token expiry → CR status condition + event, secrets stay stale; needs loud status reporting, not silent.
- **Offline/air-gap**: excellent — cluster works indefinitely from last-synced Secrets; Hikyo itself is self-hosted so "air gap" just means Hikyo lives inside the gap.

## Option 2 — Ship an External Secrets Operator provider

### What implementing a provider entails

A provider is a Go package implementing the `Provider` interface (validate store config, `NewClient()`) returning a `SecretsClient` with `GetSecret`, `GetSecretMap`, `GetAllSecrets`, `Validate`, `Close` ([e.g. the IBM provider](https://github.com/external-secrets/external-secrets/blob/main/pkg/provider/ibm/provider.go), [v1beta1 API types](https://pkg.go.dev/github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1)). Newer layout puts each provider in an independent module under `providers/v1/<name>` with build tags. Upstreaming means: SecretStore spec change (API PR), provider implementation, e2e tests (ESO runs real-API e2e suites), docs page, conventional commits, 1–2 approvers for large PRs ([contributing process](https://external-secrets.io/latest/contributing/process/)) — and an implicit ongoing commitment: ESO's own stability page notes providers are individually maintained by assigned community contributors, many at alpha/beta. There's no formal "certification"; stability level is assigned per provider.

### Project health 2025–2026 (verified)

The prior finding is correct but outdated. On **2025-07-30** maintainer Gustavo Carvalho opened [issue #5084 "Health of External Secrets project"](https://github.com/external-secrets/external-secrets/issues/5084) declaring the project unhealthy and **pausing releases** (burnout; effectively one active maintainer), formally announced ~Aug 13, 2025 (widely covered, e.g. [HN](https://news.ycombinator.com/item?id=44889991), [Infisical's writeup](https://infisical.com/blog/external-secrets-operator-paused)). Resolution: 300+ contributor signups, a contribution ladder, interim maintainers, and a [vote to resume releases](https://github.com/external-secrets/external-secrets/issues/5293) (resumed ~Sept 22, 2025). As of now the project ships roughly **monthly minors, latest 2.7 (2026-06-26)**, supports K8s 1.34–1.35, and — the catch — **only the latest minor is supported**; older minors are auto-deprecated immediately ([stability & support](https://external-secrets.io/latest/introduction/stability-support/)).

### Assessment

- **Build cost**: the interface itself is small (a read-only client — Hikyo API → bytes). Real cost is the upstream process: e2e infra against a self-hostable server, review latency, and tracking ESO's monthly release train forever. A fork/out-of-tree provider avoids upstreaming but then you maintain an ESO fork — worst of both.
- **Risk**: health restored but recent; single-supported-minor policy means users must upgrade ESO monthly-ish to stay supported. For Hikyo this is a fine *second* integration (meets users where they already are — many K3s users run ESO) but a poor *only* integration: your delivery story would depend on a third-party project's cadence and review queue.
- Security/identity/refresh/failure modes: inherits everything from Option 1's sync-to-Secret model (etcd persistence, stale-Secret resilience, `refreshInterval`), since ESO *is* that model. Workload identity = whatever auth the SecretStore spec defines (you'd design token + K8s-native auth into the spec, same as Option 1).

## Option 3 — Secrets Store CSI driver + custom Hikyo provider

The [Secrets Store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/introduction) mounts secrets into pods as **tmpfs volumes — nothing persisted in etcd**. Providers are separate gRPC plugins running as a DaemonSet (7 official: AWS, Azure, GCP, Vault, …).

- **Build cost**: a gRPC provider server (implement the provider proto: `Mount`/`Version`), packaged as a DaemonSet with a hostPath Unix socket, plus the driver itself as a dependency. More moving parts than Option 1: driver DaemonSet + provider DaemonSet on every node, `SecretProviderClass` CRD, per-node debugging.
- **Rotation**: auto-rotation is **alpha** (opt-in `--enable-secret-rotation`, polling); sync-as-K8s-Secret is also **alpha**. Files update in place, but env-var consumption still requires pod restart — so under Hikyo's restart-to-apply model the CSI driver's one unique advantage (live file updates) is unused.
- **Security**: best-in-class at-rest story (no etcd persistence; secret exists only in pod tmpfs), but secrets are only fetchable **at pod start** — Hikyo unreachable = **pod fails to mount = pod fails to start**. That is the opposite failure mode of Option 1 and a bad fit for homelab clusters where the secrets server may live on the same flaky hardware.
- **Footprint**: two DaemonSets on every node — meaningful on Pi-class K3s nodes.
- Verdict: high cost, alpha-status features for the parts Hikyo needs, worse availability behaviour. Only worth it for a hard "never in etcd" compliance requirement, which is not the target user.

## Option 4 — Init container / sidecar injection (Vault Agent pattern)

[Vault Agent Injector](https://developer.hashicorp.com/vault/docs/deploy/kubernetes/injector): a **mutating admission webhook** watches for `vault.hashicorp.com/agent-inject: true` annotations and injects an init container (pre-populate before app start) and optionally a sidecar (keep renewing) that render secrets into a shared memory volume (`/vault/secrets`), authenticating with the pod's ServiceAccount, templating via Consul Template.

- **Build cost**: the highest here — a webhook server (TLS cert lifecycle, failurePolicy decisions), an agent binary, annotation config surface, per-pod injection debugging. Webhooks are the classic "cluster won't schedule pods because the webhook is down" foot-gun.
- **Security**: no etcd persistence (memory volume), per-pod ServiceAccount identity — genuinely strong. But sidecar-per-pod memory cost multiplies across a homelab cluster, and the sidecar's continuous-renewal capability is again wasted under restart-to-apply.
- **Failure modes**: Hikyo down at pod start → init container blocks → pod never starts. Webhook down → depending on failurePolicy, either pods start without secrets or nothing schedules.
- Verdict: prior art worth citing, wrong tool for Hikyo v1. A plain *user-authored* init container using the Hikyo CLI (`hikyo export > /shared/env`) gets 80% of this with zero Hikyo-side code — document it as a pattern instead of building an injector.

## Option 5 — CLI-in-pipeline (render at deploy time)

`hikyo run`/`hikyo export` in CI, or a template step that renders Secret manifests (or SOPS-free literal values) at deploy time and `kubectl apply`s them.

- **Build cost**: ~zero if the CLI exists — a docs page and maybe an `hikyo k8s secret <name>` subcommand emitting a Secret manifest.
- **Security**: values transit the CI runner and land in etcd like any Secret; **must not** land in the GitOps repo (render-and-apply, never render-and-commit). No in-cluster credentials at all — the credential lives in CI.
- **Refresh**: none — values update on next deploy only. Under restart-to-apply that's semantically fine but operationally manual; no drift detection, no rotation without a pipeline run.
- **Failure modes**: Hikyo down → deploys fail, running workloads unaffected. Air-gap: fine.
- Verdict: not the integration, but the **day-0 escape hatch** — works before any operator exists and for non-GitOps users. Ship the docs page regardless of which operator path is chosen.

## K3s specifics

- **Datastore**: K3s defaults to SQLite (single server) or embedded etcd (HA); Secrets are **plaintext at rest by default**. Encryption is opt-in: `--secrets-encryption` auto-generates an AES-CBC key and config at `/var/lib/rancher/k3s/server/cred/encryption-config.json`; `secretbox` (XSalsa20-Poly1305) selectable; rotation/re-encryption via the `k3s secrets-encrypt` CLI; cannot be enabled on a running server without restart ([K3s docs](https://docs.k3s.io/security/secrets-encryption)). Any sync-to-Secret option (1, 2, 5) should carry a docs callout: "on K3s, enable `--secrets-encryption`". K3s wraps what vanilla K8s makes you hand-write as `EncryptionConfiguration` — simpler, same primitive.
- **Footprint expectations** (homelab, Pi-class nodes): own operator = 1 small Deployment (tens of MiB, comparable to Reloader's 10m/128Mi requests). ESO = 3 Deployments (controller, webhook, cert-controller). CSI = 2 DaemonSets × every node. Injector = webhook + per-pod sidecars. Option 1 is the lightest by a wide margin after the CLI.
- OIDC issuer discovery works on K3s (standard kube-apiserver flags), but for a homelab the TokenReview path or static token is less setup; the API server's OIDC discovery endpoint needs to be reachable by the Hikyo server (fine when Hikyo runs in/next to the cluster).

## Recommendation (ranked)

1. **v1: own minimal operator (Option 1)** — `HikyoSecret` CRD → owned native Secret, Infisical-shaped: auth ref + selector + managed-secret ref + `resyncInterval`, `creationPolicy` Owner/Orphan, opt-in auto-restart annotation via pod-template hash (or "use Reloader" in docs to ship even less). Smallest build, smallest footprint, best failure mode (stale-Secret resilience, air-gap-clean), matches restart-to-apply exactly. Document K3s `--secrets-encryption` alongside.
2. **Ship with v1 at ~zero cost: CLI-in-pipeline docs (Option 5)** as the pre-operator/escape-hatch path, plus the user-authored init-container pattern (Option 4 lite) for the operator-averse.
3. **Extension path: ESO provider (Option 2)** once the Hikyo API is stable — meets existing ESO users; project health verified as restored (releases resumed Sept 2025, monthly cadence, v2.7 June 2026) but note the latest-minor-only support policy. Out-of-tree first is not viable long-term; plan to upstream.
4. **Not planned: CSI provider (Option 3)** and **agent injector (Option 4 full)** — alpha rotation/sync, DaemonSet/webhook cost, and pod-start hard dependency on Hikyo; their unique benefits (no etcd persistence, live updates) are respectively niche for the target user and unused under restart-to-apply. Revisit only on a concrete "never in etcd" demand.

## Open decisions for the Kubernetes-integration grilling ticket

- **CRD shape**: single CRD carrying connection+mapping (Infisical style) vs split Store/Secret CRDs (ESO style). Single is less YAML for homelab; split scales to multi-tenant. Recommendation leans single-with-auth-ref, but this needs grilling.
- **Workload identity for v1**: static Hikyo token in a bootstrap Secret vs K8s-native auth (TokenReview) vs OIDC issuer federation — and whether native auth is v1 or v1.x. Also: per-namespace identity scoping model on the Hikyo side.
- **Rollout triggering ownership**: build the auto-restart annotation into the operator vs document Reloader. (Building it is ~100 lines but adds a write-to-Deployments RBAC grant — security-relevant.)
- **Refresh semantics**: default `resyncInterval` value; whether to offer push/webhook-based instant sync later (Infisical gates this as enterprise; Hikyo could differentiate by shipping it free).
- **ESO provider timing**: upstream after API freeze — which release, and who owns tracking ESO's monthly train.
- **Secret deletion policy default**: Retain (ESO default, safer) vs Owner-cascade — data-loss vs dead-secret trade-off.
