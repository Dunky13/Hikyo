# Envweave MVP boundary & acceptance criteria (ADR, locked 2026-08-06)

Context: this ADR fixes what the first stable release (1.0) contains, what is explicitly out, how "done" is verified, and in what order the implementing team should build ([#26](https://github.com/Dunky13/envweave/issues/26)). Per the [OSS mechanics ADR](./oss-mechanics.md), **1.0 is defined by this document's criteria and is the same act as the API/CLI freeze** ([api-cli-surface.md](./api-cli-surface.md)): prerelease `0.x` tags freeze nothing and ship throughout development; the freeze happens once, at 1.0, as late as possible.

This ADR decides scope and verification. It re-derives no mechanism: where a capability is named, its locked ADR or prototype governs. Contradictions found downstream reopen the owning ticket ([synthesis rule, #27](https://github.com/Dunky13/envweave/issues/27)).

## Declared amendments (per the [oss-mechanics](./oss-mechanics.md) amendment procedure)

1. **[human-auth.md](./human-auth.md)** — its "LDAP and SAML are out of v1" decision is **amended for SAML only**: SAML membership in 1.0 is decided here (§2.2); the *design* amendment (library, policy, identity mapping) is [#37](https://github.com/Dunky13/envweave/issues/37)'s to lock under this ADR's boundary conditions. SCIM (§2.3, [#38](https://github.com/Dunky13/envweave/issues/38)) likewise amends human-auth/permission-model as its ticket determines. LDAP stays out (§4.2). Until #37/#38 lock, human-auth's locked text governs everything except the membership decision itself — there are never two active designs.
2. **[inheritance-model.md](./inheritance-model.md)** — this ADR records what [#20](https://github.com/Dunky13/envweave/issues/20)/[#30](https://github.com/Dunky13/envweave/issues/30)/[#32](https://github.com/Dunky13/envweave/issues/32) already reference: the flat-model amendment ADR ([#40](https://github.com/Dunky13/envweave/issues/40)) **supersedes the inheritance model**. Until #40 locks, C1/C2 below are placeholders bound to its lock (§1.1). The in-list baseline rule reads the locked corpus **as modified by the five tickets blocking synthesis** (#36–#40). **Interim state accepted and stated**: inheritance-model.md remains the only locked semantics until #40 locks; no implementation work exists yet (the map is planning-only) and the complete gate precedes any build (§1.1), so the two-texts window closes before it can bite.

Procedure execution at this ADR's lock (the [import-paths](./import-paths.md)/#25 precedent): amendment banners land in [human-auth.md](./human-auth.md) and [inheritance-model.md](./inheritance-model.md); [#16](https://github.com/Dunky13/envweave/issues/16) is reopened, the SAML-membership amendment recorded in a comment, and re-closed — covered by this ADR's own cross-model review. #40 is itself the reopened-ticket mechanism for the inheritance supersession.

## 1. The 1.0 in-list

**Baseline rule: everything a locked ADR or locked prototype marks v1 is 1.0 scope — as modified by the five synthesis-blocking tickets (#36–#40). Nothing is silently dropped.** The subsystem inventory below is exhaustive at capability granularity; the owning document is the spec for each.

Four capabilities are **promoted into 1.0 by this ADR** beyond the locked baseline: the **GitHub Actions deployment adapter**, **SAML**, **SCIM**, and **secret scanning** (§2). Their in-list membership is decided here; their designs are decided in their own tickets, which block synthesis.

### 1.1 Acceptance criterion format (normative)

Every acceptance criterion is **executable** — one of three check classes:

- **[E2E]** — scripted flows against a real server and real CLI, run on the full engine matrix (sqlite **and** postgres). No mocked server components.
- **[UI]** — Playwright flows against the embedded SPA, both viewport classes (desktop + mobile), assertions on computed state, not screenshots alone.
- **[CI]** — the invariants the locked ADRs already mandate, referenced by their owning ADR — never duplicated, never re-enumerated here. The inventory below cites specific invariant sets where a capability's proof *is* the invariant set.

**The 1.0 gate is: every criterion in §1.2 green, plus every criterion locked by the five synthesis-blocking tickets (#36–#40), all three classes, both engines.** The gate's full enumeration exists once those five tickets lock — all five block synthesis, so the complete criteria set precedes the spec handoff and no 1.0 work starts against a partial gate. A capability without a green criterion does not ship; a criterion that cannot be made executable is a spec defect and reopens this ticket. Granularity is per capability, each criterion cross-referencing the ADR clauses it proves. Prose Given/When/Then without an executable check is not an acceptance criterion.

Two rows below (C1, C2) are **placeholders bound to #40's lock**, marked ⧗. The promoted capabilities (§2) receive their rows from their tickets in this same format.

### 1.2 Capability inventory & acceptance criteria

#### Core domain

| # | Capability | Owning doc | Acceptance criterion |
|---|---|---|---|
| C1 ⧗ | Hierarchy: Instance→Org→Project→Environment→Folder→Key/Value; key defined once per project; secret/config classification on the key | [domain model (#7)](https://github.com/Dunky13/envweave/issues/7) as modified by [#40](https://github.com/Dunky13/envweave/issues/40) | [E2E] criterion text finalized at #40's lock; must cover: full hierarchy CRUD via CLI and API, classification change only via the reclassification ceremony, unauthorized access at each level returns the uniform nonexistent shape |
| C2 ⧗ | Flat value model per the env-matrix 31 adoption | [#40](https://github.com/Dunky13/envweave/issues/40) | [E2E] criterion text finalized at #40's lock; must cover: set/clear semantics per its resolution table, matrix signal recompute on publish, disposition of `masked` state and project-defaults |
| C3 | Schema & validation: six types + `any_of`, whole-value-anchored patterns (RE2), JSON Schema 2020-12 subset on `json` keys, presence `{all\|none\|explicit}` + `forbidden_in`, key groups, closed schema, no auto-declare | [schema-model.md](./schema-model.md) | [E2E] declaration fixtures per type; **pattern matches only whole values** (anchoring is implicit semantics, not a rejection); rejections by name: NUL, unsupported/allowlisted-out keyword, `$ref` cycle, budget breach; publish blocked on validation failure; secret-key value-dependent rule change without `reveal` rejected **without evaluating**; error responses carry schema locations, never instance paths [CI] schema invariants per its ADR |
| C4 | Revisions & publishing: per-env monotonic revisions, per-user working state, selective publish, key-group auto-close, serializable publish, keyed change token | [revision-model.md](./revision-model.md) | [E2E] concurrent publish serialization; selective publish with group closure; `rotate-token-key` changes the token without touching content, revision numbers, or pinned input revisions |
| C5 | Rollback & pins: restore = normal publish, least-blast, current-schema re-validation, pins as durable quota-bounded resources with mandatory expiry, ≤1 pin per (workload, env) | [revision-model.md](./revision-model.md), [#30](https://github.com/Dunky13/envweave/issues/30), [ops-spec.md](./ops-spec.md) | [E2E] restore of a superseded secret requires `reveal-history`; schema-failing restore blocks loud; pin/re-pin/release lifecycle incl. expiry refusal and quota refusal by name [UI] restore flow from the history drawer |
| C6 | Retention & GC: payload retention org-default + project cap, lineage permanent, collected revisions fail loud | [ops-spec.md](./ops-spec.md), [#30](https://github.com/Dunky13/envweave/issues/30) | [E2E] GC run against a seeded corpus: eligible payloads (past retention, non-current, non-pinned) collected — asserted by direct DB scan showing no value-bearing copy remains; current, pinned, and last-N payloads preserved; lineage rows survive collection; collected-revision fetch fails loud with the named bound; retention change audited at both scopes |

#### AuthN, AuthZ, tenancy, audit

| # | Capability | Owning doc | Acceptance criterion |
|---|---|---|---|
| A1 | Human auth: local accounts (Argon2id, envelope-encrypted verifiers), multi-provider OIDC, WebAuthn + TOTP + recovery codes, session generations, assurance policy per provider | [human-auth.md](./human-auth.md) | [E2E] fixture families, one per locked mechanism: each login path; IdP mix-up defence (second provider's code presented on the wrong callback → refused); byte-exact `(issuer, subject)` linking (case-variant subject = distinct identity); recovery-code single-use + credential-establishment authority as a complete flow (recovery grants no session, no assurance, no window — asserted by attempting a reveal mid-reset); bootstrap first-admin flow end-to-end (root-owned file or TTY; non-TTY stdout refused); break-glass exercised on-host (local authority only — network invocation refused); byte-exact issuer handling (two providers differing only in issuer case = two distinct identities, both loginable, never merged); grant addition/widening/revocation each invalidate sessions; boot refused below the Argon2id floor; credential epoch on restore (overlaps K2, one harness) [UI] enrolment + step-up ceremonies [CI] pre-auth admission invariant |
| A2 | Permission model: `(principal, capability, scope)` grants, eight role templates expanding at grant time, protected-env flag, disclosure-by-proxy formulas, break-glass | [permission-model.md](./permission-model.md) | [E2E] per-formula matrix driven by the authorization registry (registry is the fixture generator — a formula without a fixture fails CI); revocation immediate (no cache); unauthorized≡nonexistent for content and counts, with the **structural** timing control asserted per A3 (wall-clock equality explicitly not asserted — the isolation ADR's accepted microtiming residual) |
| A3 | Tenant isolation: proof-carrying `authorize()`, operation- and transaction-bound proofs, composite ancestry FKs, single-query chain resolution | [tenant-isolation.md](./tenant-isolation.md) | [CI] all 13 invariants + 3 analyzers green [E2E] cross-org human + cross-project machine fixtures; query-count instrumentation asserts one chain-resolution query regardless of failing level |
| A4 | Audit: two append-only trails, closed `category.action` registry, per-event denials durable before response, per-key disclosure events, paged re-authorized export, retention two classes | [audit-model.md](./audit-model.md) | [E2E] denial durability under induced commit failure; export page-boundary revocation stop; INTENT/OUTCOME pairing on export [CI] registry completeness against the total probe classification; postgres durability boot refusal |
| A5 | Reveal ceremonies: purpose-bound reauth (passkey/TOTP), sliding window, protected caps at 0, clipboard = audited disclosure, one event per key | [permission-model.md](./permission-model.md), [#21](https://github.com/Dunky13/envweave/issues/21) | [UI] ceremony for reveal, publish-into-protected, copy; window countdown + remask; per-key audit rows asserted [E2E] effective window 0 forces WebAuthn per disclosure (TOTP refused) |
| A6 | Log non-disclosure: full formatting-surface guardrail on secret types, audit events never mirrored to ops logs, `ew_`-grammar redaction on attacker-influencable free text | [audit-model.md](./audit-model.md) | [CI] its ADR's redaction invariants: formatting-surface coverage test (each of `String`/`GoString`/`LogValue`/`MarshalText`/`MarshalJSON` exercised against a planted secret), free-text filter fixtures |

#### Crypto & data protection

| # | Capability | Owning doc | Acceptance criterion |
|---|---|---|---|
| K1 | Envelope encryption: root→master→{project DEKs, instance DEK, token key}, XChaCha20-Poly1305, **six per-kind AAD schemas**, five rotation ops incl. crash-safe root rotation | [encryption-model.md](./encryption-model.md) | [E2E] all five rotations on live data incl. kill -9 mid-root-rotation and reboot under either key [CI] all 16 crypto invariants |
| K2 | Backups & restore: age-encrypted, scrypt stanza exclusivity, truncation check before commit, restored verifiers never trusted, restore reconciliation per principal, root-key escrow mandatory | [encryption-model.md](./encryption-model.md), [human-auth.md](./human-auth.md), [machine-identities.md](./machine-identities.md), [ops-spec.md](./ops-spec.md) | [E2E] full backup→destroy→restore drill exercising every restore rule: bearer credentials dead **by presentation attempt**, browser/CLI sessions dead, single-use artifacts dead, federated `iat`-skew predicate enforced (issuer-ahead fixture), OIDC links re-validated not trusted, grants inert until operator commits the reconciled set, per-principal reconciliation with **no bulk-accept path in the API surface**, adapter outbound credentials require re-entry, MFA/passkey re-establishment via the credential-establishment authority; truncated backup refused before any state committed; **custody separation exercised as two distinct identities**: the age recipient private identity and the root key are held in separate custody stores per the escrow runbook, the drill fetches each from its own store, and asserts the backup is undecryptable with the root key alone and unbootable with the age identity alone |
| K3 | Headline guarantee: stolen DB + backups without root key yield no values and no replayable credentials | [threat-model.md](./threat-model.md) | [CI] planted-plaintext scan of DB dump + backup **and** [E2E] replay attempts: every credential artifact recoverable from the dump (token verifiers, session rows, recovery-code hashes) presented against a live instance and refused |

#### Surfaces

| # | Capability | Owning doc | Acceptance criterion |
|---|---|---|---|
| S1 | API `/api/v1`: spec-first OpenAPI 3.0.3, additive-only post-freeze machinery (oasdiff allowlist, minimum-revision registry, meta endpoint), SSE + polling | [api-cli-surface.md](./api-cli-surface.md), [system-architecture.md](./system-architecture.md) | [CI] oasdiff fail-closed gate + negative fixtures; HTTP contract tests validate real wire responses [E2E] skew both directions: freeze-tag client vs current server passes; current client vs sub-minimum server gets the **loud minimum-revision refusal**, not a silent misbehave |
| S2 | CLI: full noun-verb set, UI↔CLI parity, contexts with SPKI trust store, universal output triad, login transports (loopback + device + local floor), `run --` exec semantics | [api-cli-surface.md](./api-cli-surface.md) | [E2E] golden snapshots per verb; plaintext-on-stdout refusals (TTY and non-TTY); trust-store establishment + CI credential-channel import; each login transport; `run` exec exit-status passthrough incl. 126/127 [CI] parity check: every UI feature maps to a public endpoint; exemption list closed |
| S3 | Web UI: environment matrix, reveal surfaces, app chrome, history, machine access, instance administration | locked prototypes ([#20](https://github.com/Dunky13/envweave/issues/20)/[#21](https://github.com/Dunky13/envweave/issues/21)/[#29](https://github.com/Dunky13/envweave/issues/29)/[#30](https://github.com/Dunky13/envweave/issues/30)/[#31](https://github.com/Dunky13/envweave/issues/31)) | [UI] **closed flow registry, one Playwright flow each** — matrix editing incl. problems filter; row editor; reveal/copy/publish-into-protected ceremonies; history drawer + per-key filter + restore + pin lifecycle; chrome: org rail, members (grant modal incl. blast warning + staging default), project/org settings incl. retention + danger zones, account & security, instance administration; machine access: all three tabs + row expansion + display-once mint; git-mode banner + blocked-edit explanation; workspace popup ceremony + kill switch. Registry lives in CI; adding a locked surface without a flow fails. Per flow, the **pinned assertion set** (in CI beside the registry): axe-core serious/critical = 0; every error/status state communicated by text + ARIA (`role=alert`/`aria-live`), asserted with colour stripped (forced-colours emulation); visible focus indicator on every interactive element the flow touches; text contrast ≥ 4.5:1 computed; touch targets ≥ 44px on the mobile viewport; computed styles match the DESIGN.md token table for the components touched (radii scale, spacing, brand formula) |
| S4 | Definitions Git flow: `definitions export\|check\|plan\|apply`, additive bundles, `definitions_source: db\|git` | [source-of-truth.md](./source-of-truth.md) | [E2E] plan/apply digest+revision pin-and-reject-on-movement; `--allow-delete` gate; env-deletion-with-live-occurrences refusal; git-mode UI read-only |

#### Machine access & delivery

| # | Capability | Owning doc | Acceptance criterion |
|---|---|---|---|
| M1 | Machine identities: SAs, `ew_` tokens, OIDC federation (K8s, Forgejo, GitHub Actions), conditional fetch cursor | [machine-identities.md](./machine-identities.md) | [E2E] mint/rotate/revoke; display-once with **every allowed output channel positively exercised** (TTY display; `--output-file` with `O_EXCL`, `0600`, dirfd-parent check; explicit `--print-token`) plus the refusal matrix (no `--token` flag exists anywhere in the grammar; bare non-TTY stdout refused); lifetime ceiling clamp + `allow_indefinite` default-off; mint/widen gates on the post-state/delta formulas (manage-identities-without-reveal fixture from its amendment to #15); federation against a real issuer fixture per type; `pull_request`/`pull_request_target` refusal unless separately bound; JWKS staleness bound + rate-limited `kid` refresh under induced issuer outage; restore death covered in K2's drill (cross-ref, one harness); per-key disclosure event cardinality asserted (no aggregation on success); cursor bind-tuple falsification (each of the four components) forces full fetch |
| M2 | Compose delivery: `envweave run --`, rendered `env_file` (`format: raw`, 2.30 floor, `${VAR:?}` stamp), offline encrypted snapshot, per-target acknowledgement | [compose-integration.md](./compose-integration.md) | [E2E] byte-exactness round-trip over the **representable** value domain + **refusal by name for every unrepresentable class** (embedded newline et al., per its ADR); stamp-driven recreate-on-change; generation-stamp crash consistency (kill between write steps); snapshot expiry refusal + tmpfs-only plaintext; doctor floor refusal below 2.30 [CI] round-trip + refusal fixtures |
| M3 | K8s operator: `EnvweaveInstance` + `EnvweaveSecret` → owned native Secret, per-CR identity, rollout consent on workload, retain + loud condition on partition | [k8s-integration.md](./k8s-integration.md) | [E2E] kind/k3s harness: converge; rotate-token-key without restart wave; credential-designation refusal (undesignated Secret/SA refused); managed-Secret conflict refusal (existing unowned Secret); orphan-vs-scrub lifecycle incl. dead-credential retain+condition; write ordering asserted (Secret→workload patches→cursor last) |
| M4 | Deployment adapters: seam, Forgejo reference adapter; **GitHub Actions adapter (promoted, §2.1)** | [deployment-adapter.md](./deployment-adapter.md), [#36](https://github.com/Dunky13/envweave/issues/36) | [E2E] against a real Forgejo instance: claim/adopt/prune/teardown incl. crash-window replays (reserved-state crash, dispatch-window duplicate); variable-surface value-blindness asserted structurally (no GET/list code path linked — import-boundary test); canonical-name invariant via `target show --format workflow`; GitHub criteria from #36 |
| M5 | Import: K8s (file+live), SOPS (file), Vault/OpenBao (file+live), Infisical (file), two-phase invariant, occurrence tokens, secret-from-ingestion | [import-paths.md](./import-paths.md) | [E2E] per-source fixture imports incl. collision (all four provenance classes), rename, and classification matrices; phase-2 replay against moved server state rejects by occurrence token; connector subprocess sanitization asserted at the shared spawn path |
| M6 | Multi-instance: directory tier + workspace tier | [multi-instance.md](./multi-instance.md) | [E2E] its six locked criteria on a two-instance harness — with the no-proxy criterion recast per its own "vacuously testable" note: [CI] route-table/OpenAPI closure (no server-side proxy endpoint exists) + outbound-byte instrumentation in the harness (server originates no connection during workspace use) [UI] workspace popup ceremony + kill switch |

#### Operations, release & governance

| # | Capability | Owning doc | Acceptance criterion |
|---|---|---|---|
| O1 | Single multicall binary, embedded SPA, sqlite + postgres, goose migrations with fail-closed serving, upgrade protocol | [system-architecture.md](./system-architecture.md) | [E2E] upgrade path old→new incl. auto pre-migration export with recipients configured and **loud skip** without; fail-closed serving on pending migration; cross-engine conformance suite green |
| O2 | Ops conformance: calibration floor, admission limits, all ops-spec bounds loud, doctor, metrics static-series | [ops-spec.md](./ops-spec.md) | [E2E] each named bound hit → named refusal fixture (bound registry drives the fixture list); doctor full checklist on both floor deployments; Pi-class measurement pass before implementation freeze per its ADR |
| O3 | Release pipeline: signed manifest, immutable releases, DCO, fail-closed installers, SBOM | [oss-mechanics.md](./oss-mechanics.md), [system-architecture.md](./system-architecture.md) | [CI] release workflow fixture chain: manifest signature verifies against the **pinned trust root**; **image digests and chart digest cosign-verified individually** against that root, and their digests match the manifest's entries and the published artifacts; version-mapping table row asserted; installer refuses a tampered artifact **and** a valid-signature-wrong-digest artifact; **rotation fixture**: recovery-root-signed key-rotation metadata accepted, primary-signed recovery-root change refused (one-way authority), post-rotation the verifier refuses the superseded primary for releases past its cutoff (release-range validity per its ADR); **revocation fixture, distinct from rotation**: a recovery-root-signed *revocation* of a compromised primary is accepted, and an updated verifier then refuses **everything** signed by the revoked key — including releases inside its formerly valid historical range (revocation overrides release-range trust); downgrade-as-latest refused via the metadata's highest-released version; DCO gate blocks a missing sign-off in PR commit history; immutable-tag ruleset probed (tag move attempt fails) |
| O4 | Security disclosure machinery: PVR + independently-hosted fallback + security.txt | [oss-mechanics.md](./oss-mechanics.md) | [CI] release gate asserts security.txt served + fallback intake reachable + SECURITY.md present with the locked embargo terms |
| O5 | Governance & licensing artifacts: GOVERNANCE.md (BDFL + continuity + amendment procedure), TRADEMARK.md, no-`/ee` pledge in README, MPL-2.0 LICENSE, DCO | [oss-mechanics.md](./oss-mechanics.md), [license (#9)](https://github.com/Dunky13/envweave/issues/9) | [CI] file-presence + pinned-content assertions on the locked clauses (pledge text, amendment procedure section, MPL-2.0 exact text) |
| O6 | Support policy: exactly one supported version, previous minor EOL same day, no backports — published | [oss-mechanics.md](./oss-mechanics.md) | [CI] docs-site/SUPPORT.md assertion of the locked policy text at release |
| O7 | Zero unsolicited egress / air-gap posture | [ops-spec.md](./ops-spec.md), [multi-instance.md](./multi-instance.md) | [CI] its no-egress invariant: instrumented boot+idle run originates zero outbound connections with no remotes/recipients configured |

## 2. Promotions into 1.0 (decided here)

Each promotion below is **in-list as of this ADR**; each gets a dedicated grilling ticket whose lock supplies the design and the §1.1-format criteria, and each ticket **blocks synthesis (#27)**. Rationale shared by all four: SAML, SCIM, and adjacent capabilities are the classic `/ee` paywall lineup — shipping them free in core is the strongest available proof of the wedge ("fully open, no enterprise tier").

### 2.1 GitHub Actions deployment adapter ([#36](https://github.com/Dunky13/envweave/issues/36))

Second in-tree adapter over the [deployment-adapter](./deployment-adapter.md) seam — the seam is interface-neutral by design, and its ADR names a second adapter as exactly this confirmation; a sibling adapter is composition, not amendment. The **constraints** transfer: server-side ledger ownership, refuse-by-name (the `GITHUB_` prefix is already reserved), and the **no-variable-read rule** (GitHub's variables API returns stored values, same as Forgejo's — the read path must not exist). The **mechanisms** do not transfer by assumption: #36 must derive, against GitHub's actual API, a variable existence/conflict signal that never reads values (Forgejo's failed-POST-create signal verified to exist on GitHub, or an equivalent name-only oracle designed, or variable-surface adoption refused outright — an upsert-only API shape must not be papered over with a value read or a blind overwrite). Further deltas to #36: sealed-box secret writes (repo/org/environment public-key fetch), environment-level scopes beside repo/org in the target model and ledger surface naming, fine-grained PAT floor vs classic PAT refusal, rate-limit envelope under the outbox retry rules, per-surface adoption semantics. Criteria in §1.1 format at its lock.

### 2.2 SAML (SP) ([#37](https://github.com/Dunky13/envweave/issues/37))

Amends [human-auth.md](./human-auth.md) via the declared procedure (membership here, design there — see the amendment header). Boundary conditions fixed here:

- Local floor stays never-disableable; assurance policy model extends to SAML assertions.
- **Byte-exact external-identity matching transfers unweakened**: no canonicalization, uniqueness constraint on the raw pair. #37 defines *which* SAML fields constitute the identity pair (Issuer + NameID with qualifiers is the expected shape) and their uniqueness/collision handling — the matching *rule* is not its to relax.
- **"Known library means proven" gets a measurable bar** — all three: (1) actively maintained: a tagged release or substantive commit within the last 12 months; (2) a public CVE/security-response history: at least one published advisory handled with a fix release (evidence the project *responds*, not that it is flawless); (3) either a published independent security review/audit, or **named production use by ≥2 identifiable organizations in public engineering documentation or vendored inclusion in a major supported product**. XML signature wrapping is the named attack class #37's review must cover regardless.
- **Defined fallback ladder** if no Go SAML library meets the bar: (a) a narrowed SAML profile (SP-initiated only, signed assertions mandatory, no assertion encryption, single binding) — taken **iff the narrowing removes every feature whose implementation failed the bar**, mapped criterion-by-criterion in #37 (the narrowing must eliminate the unmet criteria, not merely shrink the surface); else (b) demotion to post-v1 — a **declared amendment to this ADR**, reopening [#26](https://github.com/Dunky13/envweave/issues/26) per procedure, never a silent drop. Membership is decided; the escape hatch is defined and procedural, not discretionary.

### 2.3 SCIM provisioning ([#38](https://github.com/Dunky13/envweave/issues/38))

Amends [human-auth.md](./human-auth.md)/[permission-model.md](./permission-model.md) as its ticket determines. The structural obstacle is named here so #38 cannot inherit it silently: **role templates expand at grant time into independent, provenance-free grants** — nothing records that a grant came from a template or from SCIM. Group-driven provisioning needs reconciliation (group removal, overlap between SCIM-managed and hand-issued grants, scope mapping), which requires either a grant-provenance mechanism (a declared #15 amendment) or a SCIM-side reconciliation model that works without one. #38 resolves this explicitly; "mapping onto the eight templates" is not an answer until removal and overlap are. No-self-registration stands: SCIM is provisioning by an authorized IdP, not open signup. Criteria in §1.1 format at its lock.

### 2.4 Secret scanning ([#39](https://github.com/Dunky13/envweave/issues/39))

New subsystem; shape decided in its ticket. **Minimum bar fixed here so a no-op cannot satisfy the promotion**: 1.0 ships at least scan-on-value-entry (pasted foreign credentials detected at save) backed by a normative ruleset whose provenance #39 decides (own patterns vs vendored gitleaks-class rules), with a true-positive/false-positive fixture corpus in CI as its acceptance criterion. Constraints: must not weaken `ew_` scannability-by-third-parties ([machine-identities](./machine-identities.md)); must not create a new plaintext disclosure path (scanning runs where plaintext already legitimately exists under the locked formulas — at value entry, never as a background decrypt-and-scan job with new authority); performance envelope fits the calibration floor. Additional shapes (leaked-`ew_`-token intake, push-protection API) are #39's to include or defer with triggers.

## 3. Hosted SaaS & billing — committed follow-on, not 1.0

**Decision: hosted SaaS (with billing for the hosted service only) is upgraded from "not precluded" ([#3](https://github.com/Dunky13/envweave/issues/3)) to a named, committed follow-on effort — its own wayfinder map, started after 1.0 ships.** It is not 1.0 scope: it collides with locked no-self-registration ([human-auth](./human-auth.md)), the self-hosted trust boundary ([threat-model](./threat-model.md)), and this map's own destination.

**Binding constraint on 1.0, with a conformance gate (normative for synthesis):** the [oss-mechanics](./oss-mechanics.md) **decidable self-hoster test is the instrument** — it is already locked; this section binds 1.0 to pass it wholesale. Concretely, at synthesis: **every capability in the spec document set is run through the self-hoster test as a checklist**, and any capability that a self-hoster cannot fully exercise — policy, API shape, recovery path, tenancy behavior, data transformation — is a synthesis-blocking defect, not a roadmap note. Named instances of the rule (not a substitute for it): operator ≡ org-admin assumptions must not harden into API shape; multi-tenancy invariants stay strict (they are the SaaS foundation); billing hooks are absent, not stubbed. The no-`/ee` pledge is unaffected: the hosted offering charges for hosting, never for capability. Self-hosted Envweave remains feature-complete forever.

## 4. Post-v1 register (explicit dispositions)

**Reading rule: every row records a disposition.** Out-items carry a trigger or an honest "no trigger" (returns only via a redrawn destination — a new map — never by silent scope creep). Rows marked **Promoted** point into §2 and are listed so the original presumptive-out list stays auditable. §4.4 records the IN-confirmations upstream ADRs demanded. This register is the spec's roadmap appendix; silence elsewhere in the spec is not a decision.

### 4.1 The presumptively-out list (from the map brief)

| Item | Disposition | Trigger to revisit |
|---|---|---|
| Dynamic DB credentials | Out — Vault/OpenBao territory; wedge is static config done right | Repeated user demand naming a concrete engine set |
| PKI / CA | Out — different product | No trigger; new map only |
| SSH certificates | Out — different product | No trigger; new map only |
| Encryption-as-a-service API | Out — explicit non-goal | No trigger; new map only |
| HSM management | Out — envelope 1–3 orgs; root-key file/env + escrow suffices | Demand from a user with an actual HSM |
| Cloud secret-manager sync | Out — ESO provider path covers K8s; direct sync = new outbound trust surface | Post-ESO demand for non-K8s cloud sync |
| SAML | **Promoted** → §2.2 | — |
| SCIM | **Promoted** → §2.3 | — |
| Approval workflows | Out — edit≠publish gives propose-review free | Compliance-driven demand; pairs with reason-for-access (§4.2) |
| Secret scanning | **Promoted** → §2.4 | — |
| Plugin marketplace | Out — plugins confirmed no ([oss-mechanics](./oss-mechanics.md)); seam + ESO are the only extension points | Only via an oss-mechanics amendment |
| Multi-region active-active | Out — no HA in v1 | HA demand post-1.0; single-region HA first (see §4.2 scale-out) |
| Billing | **Follow-on map** (§3), hosted service only | 1.0 ships |
| Hosted SaaS control plane | **Follow-on map** (§3) | 1.0 ships |
| Arbitrary third-party rotation | Out — adapter seam exists; arbitrary rotation = unbounded scope | Per-provider demand, one adapter at a time |
| Replacing Vault/OpenBao as crypto backend | Out — named non-goal | No trigger; new map only |

### 4.2 Dispositions demanded by locked ADRs

Every "recorded here as deliberate exclusion needing explicit in/out confirmation" from the locked corpus, confirmed:

| Candidate | Source | Disposition & trigger |
|---|---|---|
| ESO provider | [k8s-integration](./k8s-integration.md) | Out of 1.0. Trigger: API freeze (structural precondition) + demand; monthly-train maintenance cost re-priced then |
| FIDO2-in-terminal | [api-cli-surface](./api-cli-surface.md) | Out. Trigger: demand from terminal-primary users stuck on browser-handoff reauth |
| LDAP | [human-auth](./human-auth.md) | Out. Trigger: demand from directory shops without an OIDC-speaking IdP bridge |
| Per-project reauthentication-factor policy | [human-auth](./human-auth.md) | Out — protected flag + window cap cover the need. Trigger: demand |
| General WebAuthn-only reveal enforcement | [human-auth](./human-auth.md) | Out — the effective-window-0 rule already forces WebAuthn where it matters. Trigger: compliance demand |
| Local agent daemon / resident watcher (Compose or otherwise) | [machine-identities](./machine-identities.md), [compose-integration](./compose-integration.md) | Out. Trigger: dynamic secrets only — revisit against the agent prohibition |
| `--watch` auto-restart | [compose-integration](./compose-integration.md) | Out (withdrawn there). Same trigger as the agent |
| Short-lived exchanged tokens / JIT deploy-time tokens | [machine-identities](./machine-identities.md), [compose-integration](./compose-integration.md) | Out. Trigger: demand, on top of the locked lifetime rules |
| Enrolment tokens | [machine-identities](./machine-identities.md) | Out permanently — the honest version is federation, which ships. No trigger |
| Machine attestation on Compose hosts | [machine-identities](./machine-identities.md) | Out. Trigger: demand |
| Pattern-based federated binding | [machine-identities](./machine-identities.md) | Out — byte-exact rule governs. Trigger: demand with a design preserving exactness |
| ESO provider auth surface | [machine-identities](./machine-identities.md) | Rides with the ESO row above |
| Swarm secrets | [compose-integration](./compose-integration.md) | Out — wrong persona. No trigger; new map only |
| CI deploy-time injection | [compose-integration](./compose-integration.md) | Documented recipe (same CLI, same token), not a 1.0 deliverable |
| Compose-native `secrets:` `file:` source | [compose-integration](./compose-integration.md) | Out — degenerates to the rendered path. No trigger |
| Server-issued per-key delivery tokens | [compose-integration](./compose-integration.md) | Out. Trigger: only via a #11 change-token model extension |
| Push-based K8s sync | [k8s-integration](./k8s-integration.md) | Out. Trigger: demand; re-argued against the no-poller/no-agent stances |
| GitLab deployment adapter | [deployment-adapter](./deployment-adapter.md) | Out (GitHub promoted instead, §2.1). Trigger: demand — same seam, same #36-class delta ticket |
| User-level adapter destinations | [deployment-adapter](./deployment-adapter.md) | Out. Trigger: demand |
| Value-drift detection | [deployment-adapter](./deployment-adapter.md) | Out by that ADR's own argument (no read-back). Trigger: provider-side conditional-write primitives appearing |
| Adapter-initiated preview-env provisioning | [deployment-adapter](./deployment-adapter.md) | Out — previews stay one shared environment, per-PR uniqueness is CI's. Trigger: demand with a design that keeps per-PR values CI-computed |
| Audit hash chain + external sink | [audit-model](./audit-model.md) | Out. Trigger: first compliance-driven request; operator-equivalence boundary re-argued then |
| HA / scale-out | [ops-spec](./ops-spec.md), [#3](https://github.com/Dunky13/envweave/issues/3) | Out. Trigger: post-1.0 demand; single-region HA first |
| Custom role templates | [permission-model](./permission-model.md) fog | Out. Trigger: demand + template-editor UX answerable (rename-migration + lockout invariant named there). Note: #38 may surface grant provenance — that work is SCIM's, not a template editor |
| Key/folder-scoped reveal | [permission-model](./permission-model.md) fog | Out. Trigger: first real DBA-style demand; needs resolver UI |
| Reason-for-access strings | [permission-model](./permission-model.md) fog | Out. Trigger: only with approval-to-reveal (alone = compliance theatre) |
| Approval-to-reveal | [permission-model](./permission-model.md) fog | Out. Trigger: compliance demand |
| Infisical live-connector mode | [import-paths](./import-paths.md) | Out (file mode ships). Trigger: demand |
| Phase import connector | [import-paths](./import-paths.md) | Out. Trigger: Phase gains structured export + demand |
| Non-interactive `remote add` | [multi-instance](./multi-instance.md) | Out. Trigger: fleet/IaC demand, gated on a design preserving pin-confirmation + no-argv-secret rules |
| Compose GitOps reconciliation | [source-of-truth](./source-of-truth.md), [compose-integration](./compose-integration.md) | Out (non-goal inherited unchanged). Trigger: re-argue only against the agent prohibition — high bar |
| FIDO2 hardware-key reveal in CI contexts | — | Not a thing; listed to kill it: machine paths never carry human ceremonies |

### 4.3 Added here

| Candidate | Shape | Trigger |
|---|---|---|
| Password-manager integration (1Password, Bitwarden/Vaultwarden, Keeper, LastPass, …) | Import connectors under the [import-paths](./import-paths.md) seam; env-shaped products first (Bitwarden Secrets Manager, 1Password Connect/Service Accounts); file-export modes for personal-vault formats (login-shaped, lossier mapping) | Demand; Bitwarden SM / 1Password Connect first. LastPass file-only (no sane API) |

### 4.4 IN-confirmations demanded by locked ADRs

| Item | Source | Confirmation |
|---|---|---|
| Rollout triggering (K8s) | [k8s-integration](./k8s-integration.md) | **In**, as locked (workload-consent model) |
| Federation path | [k8s-integration](./k8s-integration.md), [machine-identities](./machine-identities.md) | **In** — federation ships in v1, as locked |
| Import per-source v1 set | [import-paths](./import-paths.md) | **Confirmed**: K8s file+live, SOPS file, Vault/OpenBao file+live, Infisical file-only |
| CLI parity exemption list | [api-cli-surface](./api-cli-surface.md) | **Confirmed** at its locked width; no additions here |
| Multi-instance both tiers | [multi-instance](./multi-instance.md) | **In**, both tiers, per its lock; its six criteria are M6 |
| Docs site with 1.0 | [oss-mechanics](./oss-mechanics.md) | **In** (O3–O6 assert its load-bearing pages) |

## 5. Implementation sequencing (recommendation)

Rationale spine: **anything with a CI invariant attached is foundation** — crypto, isolation chokepoint, audit registry, API diff gate — because the invariants make retrofit impossible by design. Everything user-visible rides on API slices. Integrations follow a stable core. Promotion **designs lock before synthesis** (all block #27); their **build** lands late against a stable auth core — design-early/build-late is the retrofit protection, not a contradiction.

1. **Foundations** — module layout + multicall binary ([system-architecture](./system-architecture.md)), transaction package, goose, crypto core ([encryption-model](./encryption-model.md)), proof-carrying `authorize()` + analyzers ([tenant-isolation](./tenant-isolation.md)) from day one, audit registry + completeness invariant ([audit-model](./audit-model.md)) from the first mutating endpoint, release/signing pipeline ([oss-mechanics](./oss-mechanics.md)).
2. **Domain core** — keys/schema ([schema-model](./schema-model.md)), flat value model ([#40](https://github.com/Dunky13/envweave/issues/40)), revisions/publish ([revision-model](./revision-model.md)).
3. **Auth core** — human auth in full ([human-auth](./human-auth.md): local + OIDC + WebAuthn/TOTP/recovery + sessions + assurance) and the permission model's grant surfaces ([permission-model](./permission-model.md)). Explicitly its own phase: the UI, every ceremony, machine identities, SAML, and SCIM all stand on it.
4. **API/CLI + audit, growing per domain slice** ([api-cli-surface](./api-cli-surface.md)) — spec-first, golden snapshots from the first verb.
5. **UI** — matrix, reveal ceremony, chrome, history (locked prototypes are the reference).
6. **Machine identities + federation** ([machine-identities](./machine-identities.md)), then delivery: Compose ([compose-integration](./compose-integration.md)) → K8s operator ([k8s-integration](./k8s-integration.md)) → adapters: Forgejo ([deployment-adapter](./deployment-adapter.md)) + GitHub ([#36](https://github.com/Dunky13/envweave/issues/36)).
7. **Import family** ([import-paths](./import-paths.md)), **multi-instance** ([multi-instance](./multi-instance.md)), machine-access UI.
8. **Promotions build** — SAML + SCIM (extend the phase-3 auth core; their locked designs have been waiting since synthesis), secret scanning ([#39](https://github.com/Dunky13/envweave/issues/39)).
9. **Ops closure** — backup/restore drills, doctor, ops-spec conformance incl. Pi-class measurement, docs site, full acceptance run. **API freeze = the 1.0 release act.**

Milestones ship as `0.x` prereleases throughout; nothing freezes before 1.0.

## 6. Done-verification

1.0 ships when, and only when:

1. Every §1.2 criterion green on both engines, **plus every criterion locked by #36–#40** (the complete gate exists before implementation starts — §1.1).
2. The [ops-spec](./ops-spec.md) full fail-closed checklist passes, including one complete backup→restore drill on a floor deployment (K2's drill, all restore rules exercised).
3. The oasdiff gate, golden CLI snapshots, and parity check are green against the release candidate — then the freeze tag is cut.
4. The §3 self-hoster checklist passed at synthesis and re-asserted against the release candidate's capability list.
5. Docs site live with the O4–O6 artifacts asserted.

No criterion may be satisfied by deleting or weakening its check (adversarial-review standing rule).

## Cross-model review

- **R1 (Codex, gpt-5.6-sol, high)**: 25 findings — 2 critical, 19 high, 4 medium. All accepted; fixes applied throughout (declared-amendment header for the SAML/flat-model contradictions; gate completeness rule; criterion strengthening across C3/C6/K1–K3/A1–A3/S1–S3/M1/M2/M6/O3; O4–O7 + A6 rows added; SaaS constraint bound to the self-hoster test as a synthesis gate; §4 register restructured with the full demanded-disposition sweep; sequencing gained the auth-core phase and the design-early/build-late statement; GitHub variable-oracle question made explicit in §2.1; SAML proven-bar + fallback ladder; SCIM provenance obstacle named; scanning minimum bar).
- **R2**: 16 fixed / 9 partial / 0 not fixed, **no new criticals**. All nine partials amended: interim-state acceptance + procedure-execution paragraph (findings 1/4); K2 custody as two distinct identities each fetched from its own store (7); A1 recovery/bootstrap/break-glass/issuer-case complete flows (10); S3 assertion set pinned in CI (12); M1 positive exercise of all three output channels (13); SAML bar made three-criteria measurable + narrowing must map removed features to failed criteria (18); O3 per-artifact cosign verification + rotation/compromise fixture (21); preview-env provisioning row added (25).
- **R3 (final)**: 8/9 amendments verified; **one blocking item** — O3 tested rotation but not the revocation path (revocation must override the revoked primary's historical release-range trust, per oss-mechanics' "refuses everything signed by the revoked key"). **Dispositioned by applying the prescribed fix**: O3 gained a distinct revocation fixture (recovery-root-signed revocation accepted → revoked primary refused everywhere, incl. its formerly valid range; downgrade-as-latest refused). Verified against the locked oss-mechanics text. **Locked.**

## Consequences

- Synthesis (#27) is blocked by five tickets: [#36](https://github.com/Dunky13/envweave/issues/36) GitHub adapter, [#37](https://github.com/Dunky13/envweave/issues/37) SAML, [#38](https://github.com/Dunky13/envweave/issues/38) SCIM, [#39](https://github.com/Dunky13/envweave/issues/39) secret scanning, [#40](https://github.com/Dunky13/envweave/issues/40) flat-model amendment.
- The spec's roadmap appendix is §4 verbatim; the sequencing section is §5; the self-hoster checklist (§3) is a synthesis deliverable.
- The hosted-SaaS follow-on map inherits §3's binding constraint as its opening brief.
- Amendment banners: human-auth.md and inheritance-model.md at this ADR's lock (see header).
