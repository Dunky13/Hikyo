# Handoff: #73 SCIM provisioning

Issue: https://github.com/Dunky13/hikyo/issues/73. Governing spec:
`docs/adr/scim-provisioning.md` (locked 2026-08-06), with endpoint and CLI
spellings in `docs/adr/api-cli-spellings.md` §1. Builds directly on #55
(permission model, `docs/handoff/55-permission-model.md`) and #54/#72 (human
auth, SAML SP).

**State: complete, green on both engines.** Schema, release engine, service,
SCIM protocol, HTTP transport (admin REST + the identity provider's wire), the
`hikyo scim` CLI family, and every acceptance fixture the ADR names except one
clause that is structurally blocked on #76 — see
[Blocked on #76](#blocked-on-76), which ships with a tripwire rather than a
silent gap.

## What exists

### Vocabulary (`internal/domain`)

- `scim.go` — the closed sets this ticket adds: `ProviderKind` (oidc/saml),
  `SCIMAttention` (the six §9 states), `SCIMCause` (the six §10 causes),
  `MappableTemplates()` (the seven org/project/environment-applicable ones;
  `operator` is instance-scoped and structurally out of an org binding's
  reach), and `CheckSubjectSource` — which refuses `userName` BY NAME, because
  RFC 7643 defines it `caseExact: false` and server-unique and that contradicts
  byte-exact identity material.
- **`IsSystemOrigin` is a SECOND predicate, not a widening of
  `IsMintableOrigin`.** This is the single most load-bearing decision in the
  slice. `Grants.Revoke` uses `IsMintableOrigin` as its RELEASE gate — a human
  revoke releases every origin kind that set contains — so widening it to admit
  `scim` would have made an administrator's revoke tear out SCIM origins, which
  is exactly the hand-mutation §4 refuses. The store's write gate became
  "either predicate"; the human surface's release gate is unchanged.
- `SCIMRetentionKey` owns the `lockout-retention` origin's subject encoding,
  `<binding>/<cause>`. The binding is RECORDED rather than joined because a
  retention origin outlives its binding (§6 step 2) — by the time it is cured
  the binding row may be gone, and §10 requires the cure event to name it.
- `SCIMOriginKey` owns the `scim` origin's subject encoding,
  `<binding>/<mapping_row>/<group>`. All three parts are encoded even though
  the mapping row id determines the other two: the origin CHIP must be readable
  on the membership line without a join into the SCIM tables, and those tables
  answer to `scim-provision` while the membership surface answers to
  `manage-members` — different proofs, different operations.

### Schema (migration `00018_scim.sql`, both dialects)

Seven tables. Six are `class=org chain=org_id` and ride the proof-carrying
repository surface; `scim_credentials` is `class=authn chain=-` and rides the
resolution surface, for the same reason `sessions` does — it is what
AUTHENTICATES a wire request, so it is resolved before there is a proof to bind
it to.

| Table | Notes |
|---|---|
| `scim_bindings` | `UNIQUE (org_id, provider_kind, provider_slug)` IS §1's "at most one binding per (org, provider)": the concurrent-create race resolves to one row in the database, and the loser fails closed with the named conflict rather than being reconciled in application code. `provider_issuer` is FROZEN at creation — a provider whose issuer moved under a binding is a rebinding hazard, not a rename to follow. The four `nameid_*` columns carry PRESENCE separately from value, because an absent qualifier and an empty one are different inputs to the injective encoder. |
| `scim_mappings` | `group_id` is the server-minted SCIM id, never displayName. **The FK to `scim_groups` is deliberately ABSENT**: a mapping row must SURVIVE the deletion of the group it names, flipping to `inert` with an attention state (§5.4), and a row the database tidied away is a row the human never got to decide about. Scope columns are `''` rather than NULL, because UNIQUE treats NULLs as distinct and the key would mean different things on the two engines. |
| `scim_users` | `user_name_lower` is a stored column rather than a `LOWER()` in the predicate: RFC 7643 makes `userName` `caseExact: false`, and a function in a WHERE clause defeats both the index and the SQL predicate analyzer. `subject` is unique per binding and write-once. |
| `scim_groups` | `display_name_lower` for the same reason — `displayName eq` is the probe both Okta and Entra issue before creating or updating a group. It is **deliberately NOT unique**: RFC 7643 does not make it so, real directories hold same-named groups in different organisational units, and the ADR's closed uniqueness mapping names only duplicate `userName` and a subject-source collision. A `displayName eq` probe matching two groups is answered with two, which is what a ListResponse is for. |
| `scim_group_members` | FK to both groups and users, which makes "a member reference resolving to no provisioned user is refused" structural rather than hopeful. There is no group-member column, so nested groups cannot accidentally start working. |
| `scim_attention` | STORED, not derived. Each state is audited on entry AND exit, and a state computed at read time cannot emit a transition. |
| `scim_credentials` | Unsalted SHA-256 verifier under a UNIQUE index, `credential_epoch` carried so a restored verifier is permanently dead, `revoked_at` marked rather than deleted so revocation bites at the next request while the id keeps naming a real thing. |

### Store

- `internal/store/scim.go` — 41 proof-carrying methods, every one binding
  `org_id` from the verified proof's resolved chain. **One implementation
  struct with two query handles** (the `authn.Resolver` shape) rather than
  repos.go's one-struct-per-engine: 41 methods x 2 engines is 82 bodies that
  must never drift, and the drift is what the shared body removes. The proof
  verification — the security property — happens once per method either way.
- `internal/store/authn/scim.go` — credentials, the provisioning principal's
  create/delete, and `GrantOriginsForPrincipal` (the release algorithm's
  single-instant read of both grant tables).
- `internal/store/queries/{sqlite,postgres}/scim.sql` + `scimauthn.sql`. Every
  `scim_credentials` query and every grant-table query is
  `hikyo:authn-resolution`-annotated and content-pinned.

### The §2.4 universal release algorithm (`internal/service/scim_release.go`)

One algorithm governs EVERY SCIM-side origin release. The six triggers differ
only in a predicate over the origin key (`matchBinding`, `matchGroup`,
`matchMappingRows`) plus an optional grant filter for the one case that is not
"release everything this key holds" — narrowing a mapping row releases the
no-longer-covered part. Expressing narrowing as a filter INSIDE the algorithm
rather than as a second release path is deliberate: a second path is where a
missing lockout conversion would hide.

Three things it deliberately does not do:

- **It never advances a session generation itself.** Deprovision and DELETE
  advance UNCONDITIONALLY (§5.3 — "even when no grant row changes"); every
  other trigger advances only when a row actually died. Folding the advance
  into the algorithm would force one of the two to be wrong.
- **It converts rather than refusing on lockout.** The locked refusal binds
  HUMAN revocation unchanged. Here the `scim` origin is released — origin truth
  stays honest, the IdP did withdraw it — and a `lockout-retention(cause)`
  origin is minted on the same row in the same transaction.
- **It never guesses.** An origin subject this package did not write fails the
  whole transaction loudly, because releasing the wrong origin removes
  somebody's access.

`cureLockoutRetentions` is the deterministic-release half, hooked into
`Grants.Create`, `Grants.ApplyTemplate`, `Grants.BreakGlassGrant` AND the
sync's own `applyMappings` — because §2.4 says "the moment a transaction leaves
the org with another manage-members holder", and a sync is a granter. It walks
every retention in the instance rather than the addressed org, because an
INSTANCE-scope `manage-members` grant cures every org at once.

### Changes to #55's grant surface

- `Grants.Revoke` no longer falls through to `ErrNoSuchGrant` when the row
  exists but this surface owns no origin on it. Three new sentinels name the
  actual lever: `ErrSCIMOriginOnly` (remove the user from the group at the IdP,
  or edit/delete the mapping row), `ErrLockoutRetained` (the cure is adding
  another holder), `ErrStructuralGrant` (delete the binding). Telling an
  administrator "no such grant" about a grant visible on the membership line in
  front of them is a different, wrong statement.
- `remainingMemberManagers` was extracted from `checkLockout` so the human
  refusal and the SCIM conversion/cure compute the census from one body. If
  they diverged, "the org would lose its last holder" and "the org has gained
  another holder" could disagree.
- `grantSchema` gained three optional origin fields (`origin_binding`,
  `origin_mapping_row`, `origin_group`), so `grant.modified` on a surviving row
  says WHICH binding, mapping row and group moved.

### Transport

| Surface | Where |
|---|---|
| OpenAPI | `api/openapi.yaml` — **33 operations**: 14 administration (`/api/v1/orgs/{org}/scim-bindings…`, verbatim from spellings §1) and 19 wire (`/api/v1/orgs/{org}/scim/v2/{binding}/…`), including the four named 501 routes |
| Generated | `api/apigen/apigen.gen.go`, `clients/ts/src/generated/*` |
| Handlers | `internal/server/scim_admin.go` (Hikyo envelope, human sessions), `internal/server/scim_handlers.go` + `scim_wire.go` (RFC 7644 shapes, provisioning credential) |
| Registries | `internal/authz/classify.go` — 33 `wireRegistry` + `wireRoutes` rows, `cli:scim` |
| CLI | `internal/cli/scim.go`, dispatch in `verbs.go`, `Verbs` in `exit.go`, help golden re-pinned |

Three transport facts worth carrying forward, each of which cost a debugging
cycle here:

1. **`application/scim+json` needs a kin-openapi body decoder** (`api/spec.go`,
   `scimJSONDecoder`). Without it the validator refuses every SCIM request as
   an unsupported content type BEFORE consulting its schema — a 400 that looks
   like the identity provider's fault and is not.
2. **SCIM error responses are declared INLINE per operation, not as shared
   `components/responses` `$ref`s.** oapi-codegen embeds a shared map-typed
   response as a NAMED struct field, so the wire body came out as
   `{"ScimBadRequestApplicationScimPlusJSONResponse": {...}}` — valid Go,
   wrong protocol. Inlining yields a direct map type and the RFC body.
3. **Regenerating apigen renamed `apigen.Manual` to
   `apigen.GrantOriginKindManual`** (a new enum value collided), which is why
   `internal/cli/access.go` appears in this diff.

The wire routes ARE in `openapi.yaml`, following the SAML ACS / OIDC callback
precedent: everything under `/api/v1` passes the contract validator, and
`TestContractRoutesMatchTheRouter` fails in both directions otherwise. They are
parity-exempt as protocol paths, which is a statement about UI↔CLI parity, not
about being undescribed.

### Registries

- **27 authz operations** (`internal/authz/registry.go`), all ClassTenant at org
  depth. Two formulas: `manage-members@org` for administration —
  at ORG SCOPE EXACTLY, because a mapping row causes grants its author need not
  hold and that is an org/instance power — and `scim-provision@org` for the
  wire. Their `storeOps` are COMPOSED from named groups (`scimBase`,
  `scimWireBase`, `scimDirectoryOps`, …) rather than enumerated per row: one
  SCIM operation touches a dozen store methods, and per-row enumeration is how
  a row silently ends up narrower than the code it authorizes.
- **41 StoreOps**, one per `store.SCIMRepo` method, as invariant 6's reflection
  requires.
- **21 `scim.*` audit types** with v1 payload schemas, plus the closed
  `filter_shape`/`state`/`cause`/`disposition` enums and the
  never-in-plaintext `subject_digest`.
  **Stated limit:** the registry validates a field's PRESENCE and KIND, not the
  UUIDv7 SHAPE §10's typing rules describe. Tightening it is not free — it is a
  cross-cutting change to `internal/audit/schema.go` affecting every registered
  type, and several existing fixtures carry deliberately readable non-UUID ids
  (`org_a`, `usr_alice`) that a strict validator would reject. Carried as a
  known gap rather than a half-applied rule that holds for `scim.*` and nothing
  else.

### Protocol (`internal/scimproto`)

Pure, storage-free, authorization-free: the closed PATCH operation x path
matrix as a literal table, the closed filter recognizer, RFC 7644 error bodies,
1-based paging with server-bounded `count`, and the named refusals with their
exact codes. It is a hand-written recognizer rather than a general SCIM filter
parser on purpose — a general parser accepts expressions the storage layer
cannot answer, and every one of those is a filter silently returning the wrong
set.

### Service

| File | What |
|---|---|
| `scim.go` | binding loading + fail-closed provider check, protocol-specific subject derivation, mapping->grant materialisation, attention-state bookkeeping, credential minting |
| `scim_admin.go` | binding create/get/list, §6's teardown state machine, the structural grant writer |
| `scim_mapping.go` | mapping create/update/delete/list, the blast warnings, the narrowing release |
| `scim_credential.go` | mint/list/get/revoke, directory views |
| `scim_wire.go` | credential authentication, Users, §5.4's transitions, attach-or-create |
| `scim_wire_groups.go` | Groups, membership reconciliation, discovery |

**The SAML subject derivation calls `samlSubject` — the SAME function the ACS
path calls.** It is not a second implementation of the encoder; if the two ever
diverged, the provisioned identity would stop matching the login path, which is
the exact failure the ADR's E2E criteria exist to catch.

## Fixture -> criteria map

| ADR clause | Test |
|---|---|
| §1 one binding per (org, provider), concurrent create resolves to one row | `isolation.TestSCIMBindingLifecycle{SQLite,Postgres}` |
| §1 provider disabled -> the ENTIRE wire surface fails closed, reads included; state preserved; attention state raised and cleared | `isolation.TestSCIMProviderFailClosed{SQLite,Postgres}` |
| §2 overlap: hand + SCIM = one row two origins; revoke removes the manual origin only | `isolation.TestSCIMMappingReconciliation{SQLite,Postgres}` |
| §2.4 lockout conversion: `scim` origin released, retention minted, attention raised; cure releases it | `isolation.TestSCIMLockoutRetention{SQLite,Postgres}` |
| §3 mapping create applies to an ALREADY-POPULATED group in the authoring transaction; server-authored blast warnings | `isolation.TestSCIMMappingReconciliation` |
| §4 hand-revoke of a SCIM-only grant refused naming both levers | `isolation.TestSCIMMappingReconciliation` |
| §5.1 `userName` refused as subject source, at config time | `isolation.TestSCIMBindingLifecycle` |
| §5.1 subject write-once | `isolation.TestSCIMUserLifecycle{SQLite,Postgres}` |
| §5.2 create = pre-linked account, ZERO grants | `isolation.TestSCIMUserLifecycle` |
| §5.2 idempotent attach + response-shape equality (#23 oracle) | `isolation.TestSCIMUserLifecycle` (`sameUserShape`) |
| §5.4 every transition row: create / update / deactivate / reactivate / delete / re-create | `isolation.TestSCIMUserLifecycle` |
| §5.3 deprovision advances the generation UNCONDITIONALLY — the zero-grant-delta case, asserted on `principals.session_generation` with the grant delta pinned at zero | `isolation.TestSCIMUserLifecycle` |
| §9 per-binding writes serialize: the wire transaction's first act after loading the binding is the `TouchBinding` UPDATE, which takes and holds the binding row's write lock | `internal/service/scim_wire.go` `wireTx` (argued, not race-fixtured — see disposition) |
| §5.4 member add/remove releases exactly that group's origins; group DELETE flips mapping rows inert + attention | `isolation.TestSCIMMappingReconciliation` |
| §6 teardown order; identity links and accounts survive; structural grant retired | `isolation.TestSCIMBindingLifecycle`, `TestSCIMUserLifecycle` |
| §7 `hik_<v>_scim_` grammar; credential vs wrong binding path = authentication failure | `isolation.TestSCIMBindingLifecycle` |
| §8 the closed PATCH matrix, ONE fixture per cell incl. every cross-resource refusal | `scimproto.TestPatchMatrixCells` (18 cells) |
| §8 whole-PATCH atomicity on one invalid op | `scimproto.TestPatchIsAtomicOnOneInvalidOperation` |
| §8 Entra's stringified booleans, a NAMED tolerance | `scimproto.TestNormalizeActiveTolerance` |
| §8 the closed filter grammar incl. `displayName eq` and the cross-resource refusals | `scimproto.TestFilterGrammarIsClosed` |
| §8 1-based paging, bound clamping, out-of-range page with truthful total | `scimproto.TestPagingIsOneBasedAndBounded` |
| §8 named refusals with exact codes; 501s carry NO scimType; 401 never a 400 | `scimproto.TestNamedRefusalsCarryTheirExactCodes` |
| §8 IdP strings bounded and UTF-8-checked at the trust boundary | `scimproto.TestIdPStringsAreBounded` |
| §10 every registered `scim.*` type has a real emitter | `isolation.TestAuditCore{SQLite,Postgres}/every_registered_type_is_actually_emitted` via `runSCIMLifecycle` |
| §10 payload-schema validation on write | inherited: the audit writer validates every payload against its registered schema |
| **SC2 named fixture**: Okta-shaped OIDC provision-then-login — same fixture IdP for both halves; case-variant subject is a DISTINCT identity; zero grants, no credential | `isolation.TestSCIMProvisionThenLoginOIDC{SQLite,Postgres}` |
| **SC2 named fixture**: Entra-shaped SAML provision-then-login — the binding's NameID profile must reproduce the login path's encoder exactly, or the subjects differ and the login finds nothing | `isolation.TestSCIMProvisionThenLoginSAML{SQLite,Postgres}` |
| **SC3 named fixture**: two-binding race on one shared grant row — no lost origin, no premature revocation | `isolation.TestSCIMTwoBindingRace{SQLite,Postgres}` |
| **SC4**: per-binding serialization under concurrent pushes — no lost write | `isolation.TestSCIMPerBindingSerialization{SQLite,Postgres}` |
| **SC4 restore drill**: dead credential by epoch; re-mint + re-assertion rebuilds exactly current IdP truth; a post-backup-deprovisioned user is never authorized after restore; restored identity links stay inert and re-assertion does NOT re-bless one | `isolation.TestSCIMRestoreDrill{SQLite,Postgres}` |
| **SC1 [CI]**: every SCIM operation's formula, class and addressed depth; `scim-provision` not MFA-mandatory | `isolation.TestSCIMOperationsCarryTheirFormula`, `TestSCIMWireIsNotMFAMandatory` |
| **SC1 [CI]**: the `scim` credential type is rejected on every non-SCIM operation, uniformly | `isolation.TestSCIMCredentialIsRejectedOnNonSCIMOperations{SQLite,Postgres}` |
| **SC1 [CI]**: `scim-provision` refused to every other principal class and to humans | `isolation.TestSCIMProvisionIsUngrantableThroughTheAPI` + `grants_e2e`'s `scim_provision_machine` / `scim_provision_human` |
| **SC1 [CI]**: the `hik_<v>_scim_` scanner/redaction fixture | `audit.TestRedaction` (`scim type (amended grammar)`) |
| The origin-kind predicate split (`IsMintableOrigin` vs `IsSystemOrigin`) | `isolation.TestSCIMOriginKindsAreNotHumanReleasable` |
| **SC1 [E2E]**: the ACCEPTED PATCH cells over the wire — `active` with Entra's `"False"`/`"True"`, the pathless value-object merge round-tripping on GET, `add` on `members` UNIONing with the stored set, `members[value eq "…"]` dropping exactly one reference | `isolation.runSCIMDemo` |
| **SC1 [E2E]**: PUT replacement — omitted mutables clear, an omitted `active` reactivates, the subject source is EXEMPT (both an `externalId`-source and an extension-path binding), an explicit different subject still refuses `mutability`, `groups` ignored on input, `ReplaceGroup` replaces the member set wholesale | `isolation.TestSCIMPutReplacementSemantics{SQLite,Postgres}` + a PUT leg in `runSCIMDemo` |
| **SC2**: a pushed email equal to an existing unrelated account's email does NOT attach; the email still round-trips as display metadata | `isolation.TestSCIMEmailNeverLinks{SQLite,Postgres}` |
| **SC2**: single-query-path equality by ORDERED query identity — an invited attach, a prior-other-org attach and a fresh create; the two attach legs identical, the branch point at the same index behind an identical prefix, the fresh leg the attach leg plus one contiguous run of the account-creation queries | `isolation.TestSCIMCreateIsOneQueryPath{SQLite,Postgres}` |
| **SC4**: no aggregation — a 3-user push emits 3 `scim.user_provisioned` events and 3 `grant.created` events | `isolation.TestSCIMPushEmitsPerEvent{SQLite,Postgres}` |
| §5.3's flag means MANUAL: another binding's surviving `scim` origin does not raise it; a surviving hand grant does | `isolation.TestSCIMManualRemainsMeansManual{SQLite,Postgres}` |
| Two same-named groups coexist and `displayName eq` answers with both, including a value containing `and` | `isolation.TestSCIMGroupDisplayNameIsNotUnique{SQLite,Postgres}` |
| §8's filter grammar is quote-aware: values containing `and`/`or`/`not`/parens/escaped quotes parse; genuine compound filters and unterminated literals still refuse | `scimproto.TestFilterGrammarIsClosed` |
| **The whole stack** — CLI → HTTP → service → store, plus the IdP's raw wire: binding create, display-once mint, discovery, user/group CRUD, `displayName eq`, the closed filter/sort/PATCH refusals, the accepted PATCH cells, mapping + blast warnings, origin chips, hand-revoke refusal, teardown | `isolation.runSCIMDemo` inside `TestDemoFlow{SQLite,Postgres}` |
| **SC1 [E2E]**: the captured Okta and Entra request sequences over raw HTTP — discovery trio against implemented truth, probe-then-write, all four filters (and `externalId` NOT folding case while `userName` does), the RFC ListResponse envelope by name, 1-based paging, a partial last page, an out-of-range page with a truthful total, a filtered total, `startIndex=0` refused | `isolation.TestSCIMOktaSequence{SQLite,Postgres}`, `TestSCIMEntraSequence{SQLite,Postgres}` |
| **SC1 [E2E]**: §8's whole op×path PATCH matrix over the wire, both resources, every refusal with its exact status and `scimType`; atomicity in both orders; `/Me`, both `.search` routes and `Bulk` as 501s with no `scimType` | `isolation.TestSCIMPatchMatrixOverTheWire{SQLite,Postgres}` |
| **SC2**: create and attach render byte-shape-identical wire responses, with a control proving the two legs genuinely branched | `isolation.TestSCIMWireAttachIsIndistinguishable{SQLite,Postgres}` |
| **SC4**: per-binding serialization by instrumented transaction ORDER — two overlapping PATCHes on one group, strict enter/exit alternation, both adds surviving | `isolation.TestSCIMPerBindingSerializationOrder{SQLite,Postgres}` |
| **SC1 [E2E]**: a credential presented against another binding's DISCOVERY route — 401, no `scimType`, exactly one instance-trail `scim.credential_refused`, and both correct pairings still working | `isolation.TestSCIMWireMismatchOverDiscovery{SQLite,Postgres}` |
| **SC4 [CI]**: the discovery probe class is annotated audited-none-equivalent — the registry declares no event, the annotation is name-pinned with its reason, three real probes emit nothing, and a `/Users` list still emits exactly one `scim.directory_read` naming its resource type | `isolation.TestSCIMDiscoveryIsAnnotatedNotSilent{SQLite,Postgres}` |

## Deviations from the ADR letter, stated

1. **`scim.binding_updated` is NOT registered.** The ADR's §10 table names it,
   but the locked administration surface (spellings §1) fixes no
   binding-mutation verb: the subject source and NameID profile are immutable
   at creation (§5.1) and the provider reference is read-only (§1), so the
   binding row has no field a human can address. The registry-closure invariant
   forbids a type with no emitter, so registering it would have failed CI for a
   promise nothing keeps. **If a binding-mutation verb is ever spelled, this
   event comes back with it.**
2. **`scim.credential_rotated` is not a second verb.** Overlap rotation IS
   mint-new-then-revoke-old, so a mint that joins an already-live credential
   emits `rotated` and a binding's first mint emits `minted`. This is a reading
   of the ADR's own credential model, not an addition to it.
3. **The mapping CLI/API address gains a scope.** Spellings §1 spells
   `hikyo scim mapping add <binding> --group <g> --template <t>` with NO scope
   flag, while §3 defines a mapping row as `(group -> template @ scope)` and
   allows multiple rows per group. As written, `update`/`remove` cannot address
   one row among several and `add` cannot express the scope the ADR requires.
   Implemented: the row is addressed by `(group, scope)` and the template is
   what an update CHANGES. **#27/freeze must confirm or rename.**
4. **`x-hikyo-artifacts: [scim-credential]`, not `machine-credential`.**
   `isolation.TestContractSecuredOperationsTakeAnArtifact` hard-bans the latter
   until #61 because nothing serves it. This ticket serves the former. (Recorded
   here for the transport slice; no contract change has landed yet.)
5. **Two ops-spec fog values were chosen in code** because the code needed
   non-zero ones to be correct at all — same disposition shape as #55's
   `DefaultReauthHardCap`: `DefaultSCIMStaleness = 3h` (below one full IdP
   reconciliation cycle would flag every healthy binding; the ADR itself notes
   Entra at ~40 min) and `DefaultSCIMPageSize = 200`, plus
   `DefaultSCIMCredentialTTL = 365d`. Each is applied through a
   `if configured <= 0 { use the default }` accessor rather than failing loud,
   which is #55's `DefaultReauthHardCap` precedent: a zero page bound or a zero
   TTL is not a configuration a caller meant, and the code needs a non-zero one
   to be correct at all. **The ops spec owns these numbers.**
6. **§4's refusal names both levers at the SERVICE layer, not on the wire.**
   `service.ErrSCIMOriginOnly` states both remediations verbatim and is
   asserted in `TestSCIMMappingReconciliation`. It cannot ride the HTTP
   response body: the locked wire rule is a FIXED message per error code, and
   only `bad_request` — decided before any tenant resolution — may carry a
   detail. What the wire DOES give an administrator is the origin chip on the
   membership line, which is the ADR's own answer to "why can they?"; the demo
   asserts the refusal and the chip together.
7. **Per-binding serialization is a row lock, not a mutex.** `wireTx` performs
   the `TouchBinding` UPDATE immediately after loading the binding, before the
   operation body: the UPDATE takes the binding row's write lock and holds it to
   commit, so two concurrent wire transactions on one binding serialize behind
   it. sqlite serializes on its single writer regardless. It is **lock-argued,
   not race-fixtured** — same disposition shape as #55's item 7.
8. **Two blast-warning codes beyond the ADR's examples are emitted**:
   `populated_group` and `production_environment`, beside `org_scope` and
   `reveal_expanding`. §3 fixes WHEN the warning fires and requires the same
   consequence language the grant modal uses; it does not close the code set.
   Both are additive server-authored content about facts the operator cannot
   otherwise see — how many people are being granted right now, and that a
   named environment was targeted rather than preselected.
9. **`ErrSCIMProviderUnavailable` renders as 404 on the wire, not as a named
   status.** §1 asks for "a named error"; the wire collapses it onto the
   not-found shape. That is deliberate and not an anti-probe argument: the
   error is reachable only AFTER the credential authenticated for that
   binding, so the caller already knows the binding exists. What is traded away
   is the name on the wire — kept where a human can act on it (the service
   sentinel, and the `provider_unavailable` attention state with its
   server-authored remediation on the administration surface) — for the reason
   that the identity provider's remediation is identical either way: retry
   while an administrator repairs the provider. A distinct status would mean
   declaring a new response on all 19 wire operations to say something no
   connector would behave differently about.
10. **A brand-new binding enters the `stale` attention state immediately.** It
   has never been contacted, so it IS stale; the state clears at the IdP's first
   push. Saying so is the honest state, and the alternative — treating "never
   contacted" as fresh — would hide a binding whose credential was never
   installed.

## Fixed while here, not filed

`internal/conformance/conformance_test.go`'s postgres drop list was missing the
four SAML tables that `internal/isolation/harness_test.go` already carried, so a
second postgres conformance run against the same database re-created tables
migration 00010 had left behind and died with "relation already exists". Found
while adding the SCIM block; fixed rather than filed, because a drop list that
is right in one harness and wrong in the other is a trap for whoever adds the
next migration.

## Blocked on #76

Exactly one §9.1 clause has no seam in this tree: *"restored `scim` origins are
dropped at reconciliation commit, not committed — the operator's commit covers
`manual` origins only; a row whose only restored origins were `scim` is not
re-activated."* The operator's quarantine/commit flow is #76's and does not
exist, so there is nothing to hook the drop into.

It ships as a **tripwire, not a gap**:
`isolation.TestSCIMRestoreOriginDropIsBlockedOn76` fails the day a
`restore.commit` / `recovery.commit` / `restore.reconcile` operation appears,
naming the clause that must be implemented with it. Everything else §9.1 asks
for IS implemented and fixtured (see the criteria map): the credential verifier
is permanently dead by the epoch comparison in `resolveSCIMCredential`,
re-assertion rebuilds exactly current IdP truth, a post-backup-deprovisioned
user is never authorized at any point after restore, and restored identity
links stay inert under #54's own rule — re-assertion does not re-bless one.

## Disposition items (human)

All five were carried to the orchestrator and ACCEPTED; they are recorded here
because a merge gate reads this file, not the progress notes.

1. **Mapping rows are addressed by `(group, scope)`**, with the template as
   what an update changes, because spellings §1's `--group`-only address cannot
   pick one row among several (deviation 3). **#27/freeze must confirm or
   rename.**
2. **`scim.binding_updated` is not registered** — no emitter exists, and the
   registry-closure invariant forbids a declaration without one (deviation 1).
   It returns if a binding-mutation verb is ever spelled.
3. **`scim-credential` is a new artifact eligibility class** (deviation 4),
   added to `api/spec_test.go`'s valid set. It is deliberately NOT
   `machine-credential`, which stays banned until #61.
4. **Three ops-spec fog values decided in code** (deviation 5): staleness 3h,
   page bound 200, credential TTL 365d. Same disposition shape as #55's
   `DefaultReauthHardCap`. **The ops spec owns the numbers.**
5. **§4's two-lever refusal text is service-layer, not wire-layer**
   (deviation 6), because the locked fixed-message-per-code rule forbids a
   request-derived detail on a `conflict` body.
6. **`ErrSCIMProviderUnavailable` is a 404 on the wire** (deviation 8), named
   only at the service layer and on the attention state. Reachable only
   post-authentication, so nothing is disclosed; the trade is the name, not an
   oracle.

## Cross-model review (Codex, R1)

86 findings. 57 fixed, 1 refuted with evidence, 28 carried to R2. The full
per-finding table is in `.specs/73-progress.md` § Round 3; the four changes
that were REDESIGNS rather than patches are worth restating here because they
moved architecture:

1. **Credential administration is proof-carrying.** `scim_credentials` gained
   `org_id`; mint/show/list/revoke/delete are `SCIMRepo` methods binding it
   from the verified proof. The proof-free resolver keeps only the pre-auth
   verifier lookup and the last-used touch — the two operations that genuinely
   cannot hold a proof.
2. **Tenancy is structural.** Composite `(org_id, binding_id)` foreign keys on
   every child table, plus `(binding_id, group_id)` and `(binding_id, user_id)`
   on memberships: a membership pairing one binding's group with another's user
   cannot be written, rather than being refused by a check somebody may forget.
3. **The provider is referenced by its immutable row id**, not its slug. A
   provider deleted and recreated under the same slug is a different provider,
   and the binding no longer follows the name.
4. **Minting a credential requires reauthentication.**
   `Auth.VerifyReauthProof` is the account-security-mutation pattern extracted
   for reuse; the environment-keyed reauth window has no environment to key on
   for an org-scoped act, so it is deliberately NOT what gates this.

One finding was refuted: p7#3 claimed origin arithmetic runs outside the
serializable transaction. It does not — `authz.TxAuthorizer` wraps the
per-transaction `authn.Resolver`, and `releaseSCIMOrigins` takes the principal
row lock as its first statement.

## Pickup notes

- **Adding a SCIM store method**: add it to `store.SCIMRepo`, add a
  `StoreSCIM<Method> StoreOp = "scim.<Method>"` constant, and put it in
  whichever named group in `internal/authz/registry.go` the operations that
  reach it already compose. Invariant 6 fails in BOTH directions.
- **A new `scim.*` event** needs a registry entry AND a real emitter reached by
  `runSCIMLifecycle`, or `every_registered_type_is_actually_emitted` fails.
- **The lockout pair is registered on BOTH trails**, unlike every other
  `scim.*` entry: a retention survives its binding and its cure can arrive from
  break-glass under local host authority, which has no tenant proof to bind to.
- **Postgres harness**: the seven SCIM tables drop before
  `accounts`/`principals`/`orgs`, with `scim_group_members` first. Missing
  entries fail only on postgres, on the NEXT run.
- **sqlite query files must be ASCII.** A multibyte character in a comment
  shifts sqlc's statement offsets and silently generates a truncated query —
  this cost a debugging cycle here; the header comment says so, and it is true.
- **Adding a SCIM wire route**: the path, an operation, a `wireRegistry` +
  `wireRoutes` row, and an OpenAPI operation with all five `x-hikyo-*`
  extensions must land together, or `TestInvariant01ClassificationTotality` and
  `TestContractRoutesMatchTheRouter` fail in opposite directions. Declare SCIM
  error responses INLINE, never as a shared `$ref` (see Transport, note 2).
- **Adding a CLI verb family**: `cli/exit.go`'s `Verbs`, `cli/verbs.go`'s
  dispatch AND `Usage`, `authz/classify.go`'s `cli:` entry, and a row in
  `internal/isolation/testdata/audited_exemptions.json`. Then
  `go test ./internal/cli -update`.
- **Run the postgres leg.**
  `HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:wenv@127.0.0.1:5432/wenv_test go test ./... -count=1`.

## Verification record

- `gofmt -l .` clean; `go build ./...` and `go vet ./...` clean.
- `go test ./... -count=1` on **sqlite**: **919 passed, 0 failed, 33 packages**.
- `go test ./... -count=1` with `HIKYO_TEST_POSTGRES_DSN` (**both engines**):
  **1422 passed, 0 failed, 33 packages**. The `wenv_test*` databases were
  dropped and recreated first, because this branch adds migrations.
- `go tool sqlc generate` idempotent.
- `internal/isolation/testdata/annotated_queries.json` and
  `operation_formulas.json` re-pinned; the diffs are the review artifact.
- `go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml`
  regenerated; TS client `pnpm run generate && pnpm run typecheck && pnpm run
  test` on Node 24 — 4/4 contract fixtures.
- CLI goldens re-pinned with `go test ./internal/cli -update`; the diff is 12
  added help lines and nothing else.

## The acceptance-criteria matrix

`internal/isolation/scim_criteria_test.go` is the entry point for anyone
asking "is clause X proved?". The ADR states SC1–SC4 as four prose rows;
that file decomposes them into 58 stable clause IDs (`SC1.a` … `SC4.n`), each
naming the fixtures that prove it, and `TestSCIMCriteriaMatrixIsComplete`
fails if a clause has no fixture OR a named fixture does not exist. The
matrix size is floored, so a clause cannot be deleted to make the check pass.

Two consequences for anyone extending this ticket:

- **Adding a clause is fine; removing one fails the build.** If you prove
  something new, add the row. If you believe a row is wrong, that is an ADR
  change, not a test edit.
- **A fixture living in another package** (`internal/scimproto`,
  `internal/server`, `internal/cli`) must be listed in
  `crossPackageFixtures`, so the matrix stays honest about WHERE the proof
  lives instead of quietly accepting a name it cannot see.

Observation seams used by the matrix's fixtures — `authn.SetQueryObserver`
and `service.SetSCIMPhaseObserver` — are both pinned test-only by
`TestQueryObserverIsTestOnly`. Adding a third means adding it to that map.

### Modelling note: which lockout causes are reachable by whom

`scimAdminFormula` is `manage-members` at org level, and the lockout census
counts holders at-or-above the org. So for the two admin-authored release
causes (`mapping_deleted`, `binding_deleted`) any third-party admin
authorized to perform the delete is, by construction, a census holder — and
no retention can arise. The only shape that reaches those causes is the
PROVISIONED HUMAN acting on their own behalf, deleting the very row that
grants them `manage-members`. `runSCIMLockoutAcrossEveryReleasePath` models
exactly that; a future change that appears to make those causes unreachable
should be checked against this note before the causes are deleted as dead.

## Known-remaining test-layer work

**None.** The five items the previous round carried are built and green on both
engines; `.specs/73-progress.md` carries the per-finding disposition table. What
landed, and where to look:

- **Captured provider sequences** — `internal/isolation/scim_provider_sequence_test.go`.
  `runSCIMOktaSequence` and `runSCIMEntraSequence` are ordered raw-HTTP step
  tables against the real mount, shaped as the conversations the two connectors
  actually hold (probe-then-write, `userName eq` for Okta and `externalId eq`
  for Entra, stringified booleans, pathless value objects). `assertDiscoveryTrio`
  checks the three documents against implemented truth rather than against
  themselves: every advertised absence is paired with the live 501 that makes it
  true, and every endpoint `ResourceTypes` names is asked to answer.
- **The PATCH matrix over the wire** — `runSCIMPatchMatrixOverTheWire`, same
  file: every op×path cell against both resources, each refusal with its exact
  status and `scimType`, atomicity in BOTH orders with a follow-up GET proving
  nothing committed, and `/Me`, both `.search` routes and `Bulk` as 501s with
  the Error schema and no `scimType`.
- **Instrumented per-binding serialization** —
  `runSCIMPerBindingSerializationOrder` in `scim_concurrency_test.go`. The wire
  transaction marks `wire-enter` (immediately after the binding-row lock) and
  `wire-exit` (last act before commit) through `service.SetSCIMPhaseObserver`;
  the fixture overlaps two PATCHes on ONE group behind a barrier and asserts
  strict alternation. The observer sleeps on the first entry so an unserialized
  second transaction has a wide window to be caught rather than needing to lose
  a coin flip.
- **Ordered query-identity traces** — `authn.SetQueryObserver` now reports the
  SQL text, whose sqlc `-- name:` header is the query identity.
  `runSCIMCreateIsOneQueryPath` compares three ordered traces (invited attach,
  prior-other-org attach through a real second binding in org B, fresh create):
  the attach legs must be identical, the branch point must sit at the same index
  behind an identical prefix, and the fresh leg must be the attach leg plus one
  contiguous run of the four account-creation queries. `sameUserShape` became
  `userShape` (a canonical rendered string naming every attribute key), and
  `runSCIMWireAttachIsIndistinguishable` compares the canonicalized response
  BYTES over the wire.
- **The discovery annotation** — `runSCIMDiscoveryIsAnnotatedNotSilent`. See the
  behaviour change below. `runSCIMWireMismatchOverDiscovery` is its companion:
  `scim.credential_refused` is now discovery's ENTIRE audit linkage, so the
  mismatch refusal is proved over a discovery route rather than only over
  `CreateUser`.

### Declared deviations added in the R2 disposition round

- **`scim.admin_read` is outside §10's closed `scim.*` registry.** It is kept,
  as a declared deviation flagged for amendment at freeze. The alternative
  readings are worse: folding administration reads into `scim.directory_read`
  breaks that event's closed `resource_type` enum (`user|group|discovery`,
  the identity provider's own wire), and `audited: none` is refused by the
  default-deny permit rule, which admits only tenant-class bare-`read`
  non-mutating operations. The repo's own precedent is a per-surface read
  event — `grant.membership_read`, `settings.org_read`, `auth.provider_read` —
  and this is that shape, in the same `access` retention class.
- **Cure events for an INSTANCE-scope curing grant land on the instance trail.**
  An org-scope cure sweeps one org and its events therefore ride that org's
  tenant trail already. An instance-scope `manage-members` grant cures every
  org at once, and routing each cure into its own tenant's trail would need a
  proof per affected org — proofs come only from `authorize()`, and an
  instance proof carries no chain. Each event names its `binding`, and the
  affected binding's attention state is reconciled on its own org's next
  administration read through the audited exit path.
- **SCIM wire PATH parameters keep the contract-wide ID pattern.** Query
  parameters lost every contract-layer constraint so that nothing about a
  request's validity is answered before the credential authenticates; `{org}`
  and `{binding}` still carry the shared prefixed-UUID pattern, so a malformed
  id answers 400 pre-authentication. It reveals only that the caller's own
  identifier is malformed — never whether a tenant exists — and the pattern is
  one shared component used by every route in the contract.
- **SC4.h is declared NOT COVERED** in the criteria matrix (`Blocked: "#76"`),
  not covered-by-tripwire. `TestSCIMRestoreOriginDropIsBlockedOn76` asserts the
  behaviour is ABSENT and fires the day #76's quarantine/commit flow lands; a
  passing test whose subject is "this does not work yet" is not evidence the
  clause holds.

### Two behaviour changes these fixtures forced

1. **Discovery emits nothing.** §10 makes the discovery endpoints the one SCIM
   surface annotated `audited: none`-equivalent "by explicit registry annotation
   on their probe class, not silence". The implementation was emitting a
   `scim.directory_read` per probe. `SCIM.Discovery` now runs the wire preamble
   only — authenticate, authorize, load the binding, take the serialization
   lock, record contact — and returns; `OpSCIMDiscovery` declares no event types
   and a narrowed store-op set. It cannot take the registry's `auditedNone` flag
   (the default-deny permit rule admits only bare-`read`, non-mutating,
   tenant-class operations, and this one authenticates a provisioning credential
   and records last-contact), so the ADR's demanded annotation is the name-pinned
   `scim-discovery.read` entry in `internal/isolation/testdata/audited_exemptions.json`,
   with the three routes declaring `scim.credential_refused` at the mount.
   Discovery also no longer reconciles attention: a configuration fetch is not a
   re-assertion cycle, so it must not clear the post-restore state (§9.1's exit
   is re-mint PLUS a completed cycle) and must not lower a staleness warning no
   directory traffic has earned.
2. **`noTarget` renders as 400, not 404.** `service.ErrSCIMNoTarget` wraps
   `domain.ErrNotFound`, so it fell through `scimError`'s `ErrNotFound` arm and
   told the identity provider the GROUP was missing rather than that its member
   filter matched nothing. §8's closed mapping names `noTarget` for a PATCH path
   that resolves to nothing, and RFC 7644 §3.5.2 makes that a 400. The new case
   must stay ABOVE the `ErrNotFound` arm.
