# Envweave Kubernetes integration (ADR, draft)

Context: the v1 persona ([#3](https://github.com/Dunky13/envweave/issues/3)) self-hosts on a single box first and on K3s second, and Kubernetes/K3s support is part of the wedge. The K8s research ([#5](https://github.com/Dunky13/envweave/issues/5), [k8s-delivery.md](../research/k8s-delivery.md)) compared five mechanisms and ranked an own minimal operator first; the machine-identity ADR ([#17](https://github.com/Dunky13/envweave/issues/17)) already delegates the CRD shape, resync semantics and rollout triggering here, and fixes the credential kinds, the federation trust model and the conditional-fetch obligation. The Compose ADR ([#18](https://github.com/Dunky13/envweave/issues/18)) fixes the stamp concept this ADR must share one explanation with, and propagates its integrity amendment and loader-control baseline for environment-variable delivery. This ADR fixes **which Kubernetes integration ships in v1, its CRD and identity model, how a publish reaches running workloads, what happens to the managed Secret across failure modes, and the documented paths beside and beyond the operator**.

Granularity note: this is the wayfinding-level Kubernetes ADR. It fixes the mechanism, the API objects and where authority lives, the rollout trigger, the Secret lifecycle, the loader-control posture and the extension paths. Mechanism-level detail is delegated: concrete API group, kind and field spellings, CLI verbs and their authorization formulas → API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25)); event shapes → audit ([#24](https://github.com/Dunky13/envweave/issues/24)); default resync interval, retry/backoff curves, JWKS bounds as applied per cluster, and every other concrete duration or quota → operations spec (fog); the operator's build/runtime stack → architecture ([#22](https://github.com/Dunky13/envweave/issues/22)). Each delegated ticket MUST satisfy the constraints stated here; a delegation satisfied in letter but violating an intent stated here reopens this ADR.

## The mechanism: an own minimal operator

**v1 ships one in-cluster integration: a minimal Envweave-owned operator.** It watches a namespaced `EnvweaveSecret` custom resource, performs a conditional authorized fetch against the Envweave server, and writes the result into a native Kubernetes `Secret` it owns. Workloads consume that Secret however Kubernetes lets them — `envFrom`, `valueFrom`, volume mount. The operator is the smallest thing that closes the loop: one CRD kind pair, one reconcile loop, one HTTP client, one small Deployment (Pi-class footprint, comparable to Reloader's ~10m CPU / 128Mi).

**Values land in native Secrets and therefore persist in the cluster datastore.** Stated plainly, not buried: on K3s that store (SQLite or embedded etcd) is **plaintext at rest by default**. The documentation MUST carry the K3s callout — enable `--secrets-encryption` (AES-CBC default, `secretbox` selectable, `k3s secrets-encrypt` for rotation) — adjacent to every sync-to-Secret instruction, per #17's propagation. In exchange the integration gets the entire native ecosystem for free: namespace isolation, RBAC on Secrets, `envFrom`, GC by ownership. The alternatives that avoid the datastore (CSI provider, webhook injector) were rejected in research on grounds this ADR adopts (§ *Beside and beyond the operator*).

*Rejected: ESO provider as the only v1 integration.* The delivery story would ride a third-party project's monthly release train and review queue. It returns as the named extension path.

## The API objects — authority never lives cluster-scoped

Two kinds, split on the **authority boundary**, not on ESO's connection/mapping boundary:

- **`EnvweaveInstance` (cluster-scoped)** — non-secret connection configuration only: server URL, CA bundle, TLS expectations. **It never carries a credential, and the spec has no field that could hold one.** Creation and mutation are RBAC-gated to the cluster admin.
- **`EnvweaveSecret` (namespaced)** — everything with authority or effect: the auth ref, the instance ref, the project/environment selector, the key mapping, the managed Secret reference and policies, the delivery projection, the loader-control acknowledgement, the rollout opt-in list.

The rule that generalizes: **a cluster-scoped Envweave object may never carry authority.**

The split is a security decision, not an ergonomic one. If the server URL were a per-CR field, a principal holding only `create envweavesecret` in one namespace could point the CR at a **hostile Envweave server** and needs no Envweave authorization at all — the fake server answers every fetch. The resulting Secret is consumed by that namespace's workloads, and where consumption is environment variables, #18's amendment 1 makes delivery an **integrity capability**: `LD_PRELOAD`, `NODE_OPTIONS`, `PATH` in a hostile response is code execution in every consuming pod. Creating a CR is a far smaller right than editing Deployments, so this would be privilege escalation, not a no-op. Pinning the endpoint in a cluster-scoped, admin-gated object closes it.

Accepted consequence, stated: a namespace tenant cannot bring their own Envweave instance without the cluster admin creating an `EnvweaveInstance`. For the target persona that is the right trade; it is a real limitation.

*Rejected: single CRD carrying connection + auth + mapping (Infisical shape).* Least YAML, and it is exactly the hostile-server hole above.

*Rejected: ESO-shaped namespaced store.* A namespaced connection object is creatable by the same tenant it is supposed to constrain — same hole, one indirection later.

Names here are illustrative; #25 fixes the API group and spellings.

## Identity — the operator holds no Envweave credential

**Every reconcile fetch runs under the identity the `EnvweaveSecret` names, and the operator itself holds none.** The operator is pure mechanism: it can move ciphertext and Secrets around, but it can authorize nothing of its own.

Two auth-ref forms, matching #17's two credential kinds:

1. **Bootstrap Secret** — a Kubernetes Secret in the **same namespace as the CR**, holding an `envweave-token`. Simple, works everywhere, and is the at-rest credential #17 already prices honestly.
2. **ServiceAccount federation** — the CR names a ServiceAccount in its **own namespace**; the operator obtains a short-lived, **audience-bound** projected token via the TokenRequest API and presents it under #17's `oidc-federation` kind. No credential at rest anywhere. This is the recommended form wherever the cluster's OIDC discovery endpoint is reachable by the Envweave server.

Same-namespace is load-bearing in both forms: a CR that could name a Secret or ServiceAccount in another namespace would convert `create envweavesecret` into cross-namespace credential theft.

**The confused deputy this design exists to avoid, named:** an operator holding one operator-wide Envweave credential turns anyone with `create envweavesecret` in any watched namespace into a reader of everything that credential reaches. Namespace isolation collapses into a single cluster-wide principal — contradicting #17 (service accounts project-owned, grants confined to the project subtree) and pre-breaking tenant isolation ([#23](https://github.com/Dunky13/envweave/issues/23)). *Rejected: operator-wide credential; rejected: a hybrid with an optional cluster-default credential*, which is the same hole behind a convenience flag.

Inherited from #17 verbatim, restated because it is load-bearing on Kubernetes: federation bindings match **byte-exact `(issuer, subject)`** with a **mandatory, non-default audience**; a namespace-pattern binding is forbidden, because *any ServiceAccount in namespace `prod`* hands an Envweave principal to anyone holding `create serviceaccount` there. Envweave-side caps on token age and `exp - iat`, the bounded JWKS staleness window, static JWKS for air-gap, and finite binding lifetimes all apply unchanged. TokenReview remains rejected (a per-cluster reviewer credential is a long-lived credential added to avoid one).

**Operator RBAC for TokenRequest, honestly:** `create` on `serviceaccounts/token` is the power to mint tokens for any SA it reaches. It MUST be granted per-namespace and SHOULD be restricted by `resourceNames` to the ServiceAccounts CRs actually name, re-narrowed as CRs change; where the set is volatile the namespace boundary is the real control and the docs say so.

## Change propagation — one stamp story, annotation edition

**The operator owns rollout triggering.** Workloads opt in — an annotation on the workload or an explicit list in the `EnvweaveSecret` — and on a delivered change the operator patches an annotation into the opted-in workloads' **pod templates**, forcing a rolling restart under Kubernetes' own semantics. Changes apply on restart; nothing mutates a running process.

**The annotation value is the same construction as Compose's stamp, and deliberately so** (#18 requires one explanation for both): `HMAC(operator-local stamp key, versioned canonical encoding of that target's delivered content)`, 128 bits, version-prefixed. Per **target**, not per environment, so blast radius follows consumption: rotating one API key restarts the workloads that consume it and never the database beside them.

- **Never a bare content digest.** The revision ADR ([#11](https://github.com/Dunky13/envweave/issues/11)) fixed the change token as keyed precisely because a bare digest over content is brute-forceable offline for a low-entropy secret — and it fixed that *for the Kubernetes annotation case*. A pod-template annotation is readable by anyone with `get deployments`; an unkeyed hash there is the oracle, published.
- **The stamp key is operator-local**: 256-bit random, generated on first use, held in an operator-owned Secret in the operator's namespace. The server's change token cannot be sliced per render target (#11 defines it per `(org, project, environment)`), which is #18's reasoning transferred intact. Blast radius of the key is nil for confidentiality — whoever reads the operator's namespace Secrets can read the managed Secrets directly — the key exists so the *annotation* is not an oracle for principals who can read workloads but not Secrets.
- The server's change token, where it appears in operator state, is cursor material and never written to any workload-visible object.

**RBAC cost, stated rather than papered over:** the trigger needs `patch` on `deployments`, `statefulsets` and `daemonsets` in bound namespaces, and Kubernetes RBAC **cannot scope a write by label or annotation selector**. "Only opted-in workloads" is therefore enforced by operator code, not by RBAC: a compromised operator can patch any workload in its bound namespaces, including images. The namespace binding (§ *Scoping*) is the only real boundary, and the docs MUST present it as such. Operators unwilling to grant workload-patch rights run with triggering disabled — delivery still works; restarts become the user's job.

*Rejected: ship nothing and document Reloader.* Reloader's **default** strategy injects an env var whose value is a hash of the changed resource — a bare content digest over secret material in a workload-readable field, i.e. the exact oracle #11 forbids, as a third-party default. Documenting Reloader honestly would mean mandating its non-default `annotations` strategy forever, resting a correctness property on someone else's default not changing. And it saves nothing: Reloader needs the same `patch` grant. Reloader is documented only as prior art with this caveat.

*Rejected: per-Secret hash annotation on the Secret only (no workload patch).* Does not restart anything; a Secret change is invisible to running pods.

## Managed Secret lifecycle — three events, three different answers

The trap is treating these alike; they are distinct and the CR status names which one is in effect.

1. **CR deletion.** Default `creationPolicy: Owner`: the managed Secret carries an ownerReference and is garbage-collected with its CR. `Orphan` is the explicit opt-in for GitOps handover. (ESO/Infisical shape; no surprises.)
2. **Server unreachable, 5xx, or expired/invalid credential.** The operator **retains** the last-synced Secret unchanged, sets a loud status condition, emits an event, and keeps retrying. **No staleness bound.** Pods keep starting with stale-but-valid values — the sync-to-Secret model's central resilience property, and the stance #17 already locks (*failing closed on a refresh blip would stop every workload fetch cluster-wide*). Credential expiry is additionally surfaced ahead of time as a CR condition and event per #17.
3. **Authoritative refusal.** The server is reachable and answers that this principal no longer holds `read` on the environment, or the authorized manifest no longer contains keys the mapping names: the operator **converges the managed Secret to what is now authorized** — for a full revocation, that is scrubbing it. Revocation is a server-side fact acted on at the next successful contact.

**Honest bound, stated as Compose's amendment 2 is stated:** during a partition, revocation cannot bite in-cluster — the operator cannot learn of a revocation it cannot fetch, and the stale Secret sits in the datastore meanwhile. The guarantee is *revocation converges the cluster at the next successful contact*; there is no timer pretending otherwise. A Compose-style hard maximum age was **rejected**: #18's snapshot can enforce expiry client-side against its own ciphertext, but an operator scrubbing Secrets it merely cannot confirm converts every network partition into a cluster-wide outage — the self-inflicted failure #17 rejects. The residual after a scrub is also stated: running pods keep their environment until restarted, exactly as Compose's running containers do.

**Delivery is all-or-nothing against the resolved manifest** (#18, transferred): if the manifest contains secret occurrences the principal cannot reveal, nothing syncs, and the condition names the undelivered keys and the required per-project machine-`reveal` opt-in. A fresh workload principal therefore delivers config and secret-presence only — the five-step journey from #18 appears in the K8s docs too, with the CR condition as the failing step's voice. Partial sync is rejected for #18's reason: the symptom would otherwise surface as the application's own crash three layers away.

## Loader-control keys — same rule, consumption-agnostic, and honest about why

#18 propagates its loader-control baseline (`LD_*`, `PATH`, `NODE_OPTIONS`, …) to this ADR **for environment-variable delivery**. The operator, though, writes a Secret without knowing how it will be consumed — `envFrom` (the integrity risk) or a volume mount (a narrower risk: the content is data unless the application executes it). Inspecting referencing workloads at sync time was considered and rejected as TOCTOU theatre — a reference can appear one second after delivery, and coupling refusal to trigger opt-in state couples two unrelated machines.

**Therefore: the refusal is enforced at delivery, consumption-agnostic.** A sync whose mapping delivers a key on the baseline fails with a condition naming the keys, unless the `EnvweaveSecret` carries an explicit acknowledgement listing exactly those keys. The acknowledgement is the same recorded operator act as Compose's per-target acknowledgement — it lives in an RBAC-gated, API-server-audited object — and it is per-CR, never global. The cost is stated: a Secret destined only for file mounts still needs the acknowledgement for a key named `PATH`. That is the price of not pretending to know what cannot be known at delivery time. Baseline inheritance rules are #18's: #25 may extend, never silently shrink; declaration-time warning stays a UI affordance (#12 is locked and declaring such a key is legitimate).

**File projection is the narrower risk #18 told this ADR to state separately, stated:** a file-projected Secret does not reach the loader; the risk is the application treating file content as executable configuration (a sourced shell fragment, an interpreted config). That is an application property Envweave cannot see, and no name list addresses it; it belongs with the workload-integrity residual the permission model already carries.

**The delivery projection is a server-side authorized term, never a client-side filter** (#18, transferred): an `EnvweaveSecret` declaring config-only receives the config projection as its authorized manifest, the request is recorded as such in the fetch audit, and the projection is bound into the conditional-fetch cursor. The operator filters nothing.

## Refresh — conditional fetch is mandatory, not an optimization

Locked by #17 and restated: the reconcile loop's periodic resync presents the **authorization-bound cursor** — bound to credential identity, environment, pin generation, authorized delivery projection and the mapping's key-id set — so a resync interval in seconds does not become a per-key disclosure rate. A cursor-less fetch is never a normal resync; repeated cursor-less fetching by one credential is the signal #17 says the server surfaces. A "current" answer delivers no plaintext and writes nothing. Cursor invalidation follows #18's rules where they transfer: any change to credential, projection, mapping or pin invalidates; a cursor is never advanced after a rejected or failed sync (all-or-nothing refusal, loader-control refusal, write failure). Per-key disclosure events are never aggregated (#17); the audit cost of a short interval is priced by conditional fetch, not by collapsing events.

Default `resyncInterval` and backoff curves are operations-spec values. Push/webhook-based instant sync is deferred, recorded not dropped — it would ride the same conditional-fetch machinery and is a differentiator Infisical paywalls — but a push channel is new attack surface and new availability coupling, and v1's restart-to-apply semantics make polling latency acceptable.

## Scoping — RBAC is the boundary, and there is no second one

**One operator install per cluster; the admin chooses its reach at install time purely through RBAC**: a ClusterRoleBinding for cluster-wide, or RoleBindings in an explicit namespace set for scoped installs. The operator acts exactly where its bindings let it. A CR in an unbound namespace stays unreconciled with a visible event saying so.

**There is no namespace allowlist in Envweave configuration.** A config list beside RBAC is a second authority language that can disagree with the first — #15's argument, landing here. When the effective boundary is a config file while RBAC over-grants, an auditor reading RBAC reads a lie. The Helm chart's namespace values exist only to *generate* the RoleBindings; the bindings are the truth.

Verb surface, per bound namespace: get/list/watch on `EnvweaveSecret`; get/create/update/patch on Secrets; patch on Deployments/StatefulSets/DaemonSets (trigger only — omitted entirely when triggering is disabled); get on ServiceAccounts and create on `serviceaccounts/token` (federation path only, `resourceNames`-restricted where practical). Cluster-scoped: read on `EnvweaveInstance` and the CRDs. Nothing touches Secrets cluster-wide unless the admin chose the cluster-wide binding.

*Rejected: config allowlist with broad RBAC* (the common operator shape) — above. *Rejected: per-namespace operator instances* — N× footprint on Pi-class nodes, and the one thing needing centralization (the connection endpoint) is already the cluster-scoped `EnvweaveInstance`.

## Beside and beyond the operator

Ships with v1 at documentation cost only:

- **CLI-in-pipeline**: render at deploy time and `kubectl apply` — **render-and-apply, never render-and-commit**; the GitOps repo holds no values (#13's boundary, transferred). The docs page MUST state that this path is a `values export` under #15's full formula — granting CI `reveal` is the explicit opt-in #13 fixes, never implied by pipeline convenience.
- **User-authored init container**: `envweave run`/export in an initContainer writing to a shared volume, for the operator-averse. A pattern page, zero Envweave-side code. Its failure mode is stated with it: Envweave unreachable at pod start blocks the pod — the inverse of the operator's stale-but-valid stance, chosen knowingly by whoever picks this pattern.

**Named extension path: an upstream ESO provider, post-API-freeze.** Committed as direction, not as a versioned deliverable: ESO supports only its latest minor, so shipping a provider means adopting a monthly upstream train, and that ongoing cost is recorded here rather than discovered later. Out-of-tree/forked providers are rejected as worst-of-both.

**Expansion-ready, as a binding constraint rather than a hope:** the fetch/manifest/cursor/projection API the operator consumes MUST be integration-neutral — no operator-special server endpoints — so an ESO provider, a future push channel, or any later mechanism is purely an additional client of the same surface. Binds #25.

**Recorded rejections** (research grounds, adopted): CSI provider — alpha rotation/sync, two DaemonSets on every Pi-class node, pod-start hard dependency on Envweave, and its unique no-datastore-persistence property serves a compliance demand the target persona has not made. Webhook injector — highest build cost, webhook-down failure couples pod scheduling to Envweave, sidecar renewal has no job under restart-to-apply. Revisit either only on a concrete never-in-etcd demand.

## Reconciliation with upstream ADRs

- **Threat model ([#8](https://github.com/Dunky13/envweave/issues/8))** — workload credentials scoped `(project, environment)`, read-only allowlist; per-fetch audit with credential identity. The managed Secret is plaintext at rest *in the cluster's trust domain*, stated honestly with the K3s encryption callout; nothing here weakens the stolen-DB/backup headline, which concerns Envweave's own store.
- **Revisions ([#11](https://github.com/Dunky13/envweave/issues/11))** — the annotation honours the keyed-token rule; no bare digest reaches any workload-visible field. Changes apply on restart via Kubernetes' own rollout, never live mutation.
- **Permissions ([#15](https://github.com/Dunky13/envweave/issues/15))** — every fetch is a `values export` carrying the full formula; machine-`reveal` stays the explicit per-project opt-in; the operator holds no authority of its own, so no new authorization path exists to audit.
- **Human auth ([#16](https://github.com/Dunky13/envweave/issues/16))** — nothing in-cluster ever uses a human session; bootstrap-token display rules apply to the CLI mint that produces the bootstrap Secret's content.
- **Machine identities ([#17](https://github.com/Dunky13/envweave/issues/17))** — both credential kinds; conditional fetch with the authorization-bound cursor; expiry as CR condition and event; byte-exact bindings, mandatory audience, K3s callout: all satisfied above.
- **Compose ([#18](https://github.com/Dunky13/envweave/issues/18))** — one stamp explanation across both integrations (keyed HMAC, per-target, local key, version-prefixed; label there, pod-template annotation here); integrity amendment inherited for env delivery with file projection stated separately; loader-control baseline inherited with the per-CR acknowledgement; all-or-nothing and the projection-as-authorized-term rules transferred.

## Propagations (binding on downstream tickets)

- **Architecture ([#22](https://github.com/Dunky13/envweave/issues/22))** — the operator is a separate deployable, not a server mode; MUST fix its stack (controller-runtime is the presumption) and the operator's stamp-key custody model.
- **Tenant isolation ([#23](https://github.com/Dunky13/envweave/issues/23))** — per-CR identity means cross-tenant reach in-cluster reduces to Envweave-side grants; #23 owns proving the server never lets one project's credential resolve another's material, and inherits "no operator-wide principal" as a standing constraint.
- **Audit ([#24](https://github.com/Dunky13/envweave/issues/24))** — event shapes for: operator delivering fetch, conditional fetch answering "current", all-or-nothing refusal naming keys, loader-control refusal, authoritative-refusal convergence (scrub), config-only projection fetch.
- **API & CLI ([#25](https://github.com/Dunky13/envweave/issues/25))** — integration-neutral fetch/manifest/cursor/projection surface (no operator-special endpoints); API group/kind/field spellings; the CLI verb that mints a bootstrap Secret's token honouring #17's display rules; MAY extend, never silently shrink, the loader-control baseline.
- **MVP boundary ([#26](https://github.com/Dunky13/envweave/issues/26))** — explicit in/out for: rollout triggering in v1 (presumed in), federation path in v1 (presumed in, it is #17's recommendation), ESO provider timing, push-based sync (presumed out).
- **Operations spec (fog)** — default `resyncInterval`; retry/backoff and rate limits as they apply to operator fetch; JWKS bounds per cluster; operator resource requests/limits; stamp-key rotation guidance; the K3s `--secrets-encryption` runbook.
- **UI (fog)** — the service-account and credential surfaces already carry the K8s-relevant affordances (#17); add the CR-condition vocabulary to the workload-integration setup screens so the five-step journey reads the same in `kubectl` and in the UI.

## Deferred (recorded, not dropped)

- **Push/webhook-based instant sync** — differentiator potential (Infisical paywalls it), same conditional-fetch machinery, new attack surface; nothing about restart-to-apply needs it.
- **ESO provider** — post-API-freeze, monthly-train cost stated above.
- **CSI provider / webhook injector** — revisit on a concrete never-in-etcd demand.
- **Per-namespace operator instances** — revisit only if a multi-tenant install demands hard operator-level isolation that RoleBindings cannot express.
