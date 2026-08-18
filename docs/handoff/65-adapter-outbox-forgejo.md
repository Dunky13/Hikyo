# Handoff: #65 deployment adapter outbox and Forgejo reference adapter

Issue: https://github.com/Hikyo-Org/Hikyo/issues/65. Canonical contract:
`refs/remotes/spec/wayfinder-docs` at `86f81b8`, especially
`docs/adr/deployment-adapter.md`, the Jobs section of
`docs/adr/system-architecture.md`, the adapter section of
`docs/adr/ops-spec.md`, and M4 in `docs/adr/mvp-boundary.md`.

This handoff records the Forgejo portion only. The GitHub adapter remains #66.

## Implemented locally

- **Closed four-operation seam** — `ValidateConfig`, `TestConnection`, `Plan`,
  and `Sync`, with an exact reflection assertion. Active sync always owns both
  sentinels; teardown is an explicit fail-closed mode. Manifest validation
  covers canonical names, CR refusal, post-prefix 128-byte limits, and the
  prefixed sentinel collision. Workflow rendering produces the canonical
  names-only `${{ secrets.* }}` / `${{ vars.* }}` mapping.
- **Forgejo v1.21+ reference module** — repository and organization Actions
  secret/variable create/update/delete, destination numeric-ID verification,
  secret-name-only listing, provider version-floor probe, no variable GET/list
  path, 4xx definite versus 5xx/network indeterminate outcomes, and reserved /
  dispatched crash replay. The client uses 15-second deadlines (strictly less
  than the two-minute provider lease), response caps, no redirects, sanitized
  errors, DNS-rebinding-safe public-address dialing, and no ambient proxy.
- **Durable adapter outbox and custody ledger** — SQLite/Postgres migration
  `00024_adapter_outbox.sql`; full org/project/environment composite FKs;
  one active target job, four running jobs per org, queue/ledger bounds,
  30-second exponential retry through a one-hour cap, forever retry with loud
  target names after one hour, exact provider-effect INTENT/OUTCOME linkage,
  provider request fencing, generation fencing, atomic claim/confirm/refuse,
  and exact-row stale-worker refusal. Released custody remains historical but
  is excluded from execution/plan/orphan reads and from the partial global
  active-name uniqueness constraint.
- **Lifecycle integration** — service/store Plan artifacts and artifact-bound
  adoption; target inspect plus canonical workflow; all-publish and schema
  fan-out enqueue under recorded authority (`on-publish`), newest-wins without
  stealing an in-flight provider fence; manual target sync with all-adapter-env
  reveal/reauth; target connection test with a fresh authorization before each
  provider request; sealed write-only credential replace/revoke with generation
  fencing and no implicit converge; proof-gated target/adapter teardown. Default
  teardown tombstones and queues one scrub per target. Keep-remote immediately
  releases and loudly enumerates names. Dead credentials complete scrub
  Wenv-side with released custody and an orphan warning. Adapter credentials
  survive until every target scrub is terminal.
- **Authorization, audit, crypto, and restore boundaries** — closed adapter
  authz/store-op mappings; all 14 adapter audit actions and exact outcome sets;
  distinct `PurposeAdapter`; loader gate before manifest assembly and before
  every plaintext open; fresh gate before every provider HTTP request; buffer
  zeroing on mid-manifest authority loss; worker wired to the server lifecycle;
  restored adapter PATs cleared on both engines before restore completion.
  Targeted keys refuse rename/reclassification with adapter/target names and
  the narrow → edit → re-add path.
- **Pinned public lifecycle** — atomic adapter + credential + first-target
  bootstrap; project adapter collection/item/credential/nested-target APIs;
  directly addressed target inspect/update/remove/plan/sync/test/adoption APIs;
  generated Go and TypeScript clients; and the matching `hikyo adapter` CLI.
  Credential input is limited to no-echo TTY, `--stdin`, and `--value-file`.
  Target updates replace the complete key subset and refuse mixed
  adapter/target fields. Adoption resolves an exact eligible artifact, with
  optional explicit `--artifact`, then sends and revalidates its concrete id,
  generation, destination, and pairs.
- **Origin-scoped private egress** — startup-only
  `HIKYO_ADAPTER_EGRESS_POLICY_FILE` parses an exact canonical HTTPS
  origin-to-CIDR JSON map. Exceptions are selected by exact origin and only
  permit matching dialed IPs; TLS verification, rebinding-safe resolution,
  no redirects, and public-only defaults remain unchanged.
- **Configure-time namespace safety** — target creation and update validate
  the full post-prefix effective-name set, including the sentinel, and refuse
  overlap with another active target on the same Forgejo origin/destination.
- **Durable route moves** — origin and destination updates create a scrub-first
  `AdapterMove`, block new pushes, reserve the pending namespace, preserve old
  credentials only through scrub, then activate/test/converge the new route.
  Keep-remote and dead-old-credential paths release custody and retain loud
  orphan names. Invalid pending credentials/collisions enter
  `attention_required`; pending data can be replaced and resumed, while cancel
  restores and reconverges the old route. Target environments remain immutable.
  Initial PATCH responses and the project-scoped move GET are in OpenAPI,
  generated clients, server handlers, and CLI move rendering. The same move
  resource now has PATCH for the closed pending-origin/pending-target union and
  DELETE for atomic cancellation plus old-route reconvergence. CLI recovery is
  explicitly `--move`-bound, including pending credential replacement.
- **Purpose-aware CLI reauthentication protocol** — additive adapter-bound TOTP
  and WebAuthn windows carry exact purpose, operation, and full environment set.
  Durable `/auth/cli-reauth/start`, `/approve`, and `/redeem` transactions use
  PKCE, verifier-only state/code storage, same-principal browser approval,
  single-use redemption, and bearer rotation. The CLI binds an ephemeral
  `127.0.0.1` callback and opens `/reauth/cli?transaction=<opaque-state>`; the
  SPA loads display-only policy, performs mixed TOTP/WebAuthn proofs, and
  redirects only code plus the exact state to the server-bound callback.
  Start/metadata/approve never disclose a bearer; redemption silently replaces
  the mode-0600 local session artifact.

## Local evidence

Focused implementation gate:

```text
rtk go test ./internal/adapter/... ./internal/service ./internal/store \
  ./internal/store/migrate ./internal/app ./internal/authz ./internal/audit \
  ./internal/conformance -count=1
Go test: 227 passed in 9 packages
```

Additional named evidence in that gate includes:

- `TestPublishedGenerationSupersedesWithoutStealingLiveProviderFence`
- `TestAdapterFinishPreservesConcurrentReleasedCustody`
- `TestAdapterTargetKeepRemoteReleasesAndEnumeratesCustodyWithoutReveal`
- `TestAdapterDeleteQueuesEveryScrubAndRetainsCredentialUntilLastTerminal`
- `TestAdapterCredentialReplaceAndRevokeFenceWithoutAutoConverge`
- `TestAdapterManualSyncRequiresTargetRevealAndSupersedesNewest`
- `TestAdapterTargetConnectionReauthorizesEveryProviderRequest`
- `TestAdapterLoaderGatesBeforeLoadAndEveryPlaintextOpen`
- cross-engine migration corpus for environment-chain refusal and released-name
  reuse (the Postgres leg is CI-gated as described below)
- conformance scenario
  `publish_enqueues_adapter_sync_with_recorded_authority`, covering ordinary
  publish and semantic-schema fan-out through the shared transaction helper.

Latest focused async-move and CLI-reauth additions (no full-suite rerun):

```text
rtk go test ./api ./internal/cli ./internal/server ./internal/service \
  ./internal/store ./internal/isolation \
  -run 'Test(Adapter|CLI|Cli|Reauth|NoServerSideProxyEndpointExists|RemoteContractSurfaceIsPinned)' \
  -count=1
Go test: 56 passed in 6 packages

rtk go test ./internal/authz ./internal/audit ./internal/conformance \
  ./internal/store/migrate \
  -run 'Test(Adapter|CLI|Cli|Reauth|Audit|Auth|Contract|Migration|Conformance)' \
  -count=1
Go test: 59 passed in 4 packages

cd clients/ts
rtk fnm exec --using=24 -- pnpm typecheck
TypeScript typecheck succeeded.

cd docs/site
rtk fnm exec --using=24 -- pnpm check
Astro: 0 errors, 0 warnings, 0 hints.
```

Named new proofs include `TestCLIAdapterReauthHandoffSQLite`,
`TestCLIReauthOnlyRedeemDisclosesRotatedBearer`,
`TestRedeemCLIReauthSilentlyReplacesStoredBearer`,
`TestAdapterMoveCredentialFailureRequiresAttentionAndCancelReconvergesOldRoute`,
`TestAdapterAttentionTargetReplacementResumesActivation`, and
`TestAdapterMoveOutputEnumeratesPendingRouteJobsAndOrphansWithoutCredential`.
The Postgres CLI-reauth leg is present but was not rerun in this last pass
because `HIKYO_TEST_POSTGRES_DSN` was absent; the earlier real-Postgres evidence
below predates that new handoff table.

Approved move-recovery wire focused proof:

```text
rtk go test ./internal/cli \
  -run 'TestAdapter(CancelMove|MoveResume|MoveOutput|Credential|Help)' -count=1
Go test: 5 passed in 1 package

rtk go test ./internal/service \
  -run 'TestAdapter(MoveCredentialFailureRequiresAttentionAndCancelReconvergesOldRoute|AttentionTargetReplacementResumesActivation)' \
  -count=1
Go test: 2 passed in 1 package

rtk go test ./api ./internal/conformance ./internal/authz \
  -run 'Test(ContractRouteSurfaceIsExhaustivelyPinned|Contract|Adapter|Class|NoServerSideProxyEndpointExists|RemoteContractSurfaceIsPinned)' \
  -count=1
Go test: 3 passed in 3 packages

cd clients/ts
rtk fnm exec --using=24 -- pnpm generate
rtk fnm exec --using=24 -- pnpm typecheck
Generation and TypeScript typecheck succeeded.
```

Public-surface focused gate after the pinned contract landed:

```text
rtk go test ./api ./internal/cli ./internal/config ./internal/app \
  ./internal/authz ./internal/store ./internal/service ./internal/server -count=1
Go test: 462 passed in 8 packages

rtk go test ./internal/adapter/... ./internal/store/migrate \
  ./internal/audit ./internal/conformance -count=1
Go test: 112 passed in 5 packages

cd clients/ts
rtk fnm exec --using 24 -- corepack pnpm run generate
rtk fnm exec --using 24 -- corepack pnpm run typecheck
rtk fnm exec --using 24 -- corepack pnpm test
4 TypeScript tests passed; generation and typecheck succeeded.

cd docs/site
rtk fnm exec --using 24 -- corepack pnpm run check
Astro: 0 errors, 0 warnings, 0 hints.
```

Final browser handoff and loopback slice (local evidence only; no full-suite
rerun):

```text
rtk go tool sqlc generate
rtk go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml
rtk go test ./api ./internal/cli ./internal/server ./internal/service \
  ./internal/isolation \
  -run 'Test(Adapter|CLI|Cli|Reauth|ContractRouteSurfaceIsExhaustivelyPinned|NoServerSideProxyEndpointExists)' \
  -count=1
Go test: 42 passed in 5 packages

cd web
rtk fnm exec --using=24 -- pnpm exec vitest run \
  src/api/cliReauth.test.ts e2e/registry.test.ts
14 tests passed in 2 files.
rtk fnm exec --using=24 -- pnpm typecheck
rtk fnm exec --using=24 -- pnpm build
Typecheck and production build succeeded (Vite emitted its existing chunk-size warning).

cd clients/ts
rtk fnm exec --using=24 -- pnpm typecheck
TypeScript typecheck succeeded.

cd docs/site
rtk fnm exec --using=24 -- pnpm check
Astro: 0 errors, 0 warnings, 0 hints.

rtk git diff --check
Clean.
```

The new proofs include
`TestRunCLIAdapterReauthBindsExactLoopbackStateAndSilentlyRotatesBearer`,
`TestCLIReauthCallbackQueryIsClosedAndExact`,
`TestAdapterCreateCeremonyPrecedesSecretInputAndMutationDispatch`, and
`TestCLIRedirectIsExactEphemeralLoopbackCallback`. Together they pin the
ephemeral loopback URI, opaque state-only browser URL, closed callback query,
PKCE redemption, silent bearer rotation, and ordering before credential input
and adapter mutation dispatch. The SPA callback helper separately refuses
state or redirect substitution. The real-Forgejo evidence below predates this
browser-only transport slice; it remains provider evidence, not proof of the
new browser handoff.

## Review round 1 fixes

The first implementation review produced seven valid findings. They are fixed
with focused local regressions:

- Forgejo secret-name enumeration now paginates repository and organization
  routes to exhaustion with the response cap applied independently to every
  page. A second-page unowned name is observed as a conflict.
- An owned/dispatched variable whose provider-side PUT returns 404 is treated
  as absence-proven. Round 2 below records the corrected split-effect retry.
- Adapter creation and target addition consume the exact PurposeAdapter
  ceremony before credential plaintext is read or any provider request occurs;
  failed ceremony tests observe zero provider calls.
- Target PATCH classifies same-route narrowing separately from widening,
  prefix change, and destination moves. In-place updates atomically supersede
  and enqueue replacement converge, returning `200 AdapterTarget`; moves use
  scrub-first semantics and return `202 AdapterMove`. The CLI fetches current
  detail before deciding whether to open the browser ceremony.
- Target reads now carry `converged_revision`; adapter show includes target
  status, revision, and failure names. Retry-visible failures union failed and
  conflict changes. The docs explain organization storage scope and repository
  shadowing.
- Adapter and move response builders reject malformed stored timestamps.
- Header-authenticated TOTP returns the rotated bearer as `session_token`;
  cookie-authenticated TOTP omits it and rotates the HttpOnly cookie. Adapter
  responses list only windows actually opened and use their earliest expiry.

Focused evidence after Go and TypeScript regeneration:

```text
rtk go test ./api ./internal/server ./internal/service ./internal/store \
  ./internal/adapter ./internal/cli
Go test: 458 passed in 6 packages

rtk fnm exec --using=22.22.2 -- corepack pnpm --dir clients/ts exec tsc --noEmit
Passed.

rtk git diff --check
Passed.
```

This is local review-fix evidence only. It does not replace the external
Forgejo and Postgres prerequisites below, and no full suite was run.

## Review round 2 fixes

- A variable PUT 404 now finishes its update effect with a definite failure
  OUTCOME, releases the stale claim, and returns to the outbox retry path. The
  next converge reserves the absent name and performs POST-create only after a
  fresh Prepare/INTENT. Module and durable AdapterRuntime regressions prove no
  attempt sends two requests under one effect, replay records two independent
  INTENT/OUTCOME pairs, and the final ledger state is owned. A worker regression
  proves the absence result queues a retry instead of terminalizing the job.
- Adapter responses now carry every target's pending conflict artifacts using
  the same closed artifact representation as target show. JSON preserves the
  artifact id, destination, generation, entries, and timestamp; table output
  includes pending `surface:name` pairs beside status, converged revision, and
  failure names. Service coverage proves plan-created conflicts are visible
  from adapter show, and OpenAPI/Go/TypeScript clients were regenerated.

Focused evidence:

```text
rtk go test ./api ./internal/server ./internal/service ./internal/store \
  ./internal/adapter ./internal/adapter/forgejo ./internal/cli
Go test: 480 passed in 7 packages

rtk fnm exec --using=22.22.2 -- corepack pnpm --dir clients/ts exec tsc --noEmit
Passed.
```

No full suite or external provider/database rerun was performed for round 2.

## OpenRouter review 2 of 6 fixes

- Every authorization/generation Gate after a durable Prepare now records a
  definite failure OUTCOME and restores the exact pre-request custody state
  before returning the Gate error. A failing Finish takes precedence. Module
  tests cover reserved, owned, dispatched, and prune states with zero provider
  requests; real AdapterRuntime tests prove no dangling INTENT/provider fence
  and preserve both authority and generation `adapter.abort` audits.
- Secret-name pagination is bounded at 10,000 returned names (200 full
  50-name pages), matching the per-target ledger bound. A provider that never
  returns a short terminal page gets the named `ErrSecretListLimit` refusal;
  the per-response byte cap remains in force.
- Variable-conflict and prune-provider-error paths now propagate a journal
  Finish failure instead of discarding it. The obsolete absence-proven branch
  in conflict classification was removed.
- CLI reauthentication approval recomputes every environment's current
  effective policy. If policy drifted to effective zero after a TOTP window was
  opened, approval requires a WebAuthn, single-decision window and rolls back
  otherwise. The shared SQLite/Postgres scenario carries the negative check;
  the local SQLite leg passed.

Focused evidence:

```text
rtk go test ./internal/adapter/forgejo ./internal/adapter ./internal/store \
  ./internal/service ./internal/isolation \
  -run 'Test(PostPrepareGateFailure|PrunePostPrepareGateFailure|FinishErrorsOverride|SecretPaginationRefuses|AdapterJournalFinishesUnsent|CLIAdapterReauthHandoffSQLite|WorkerProviderAuth|WorkerDefinite)'
Go test: 22 passed in 5 packages

rtk go test ./internal/adapter/forgejo ./internal/adapter ./internal/store \
  ./internal/service ./internal/isolation -count=1
Passed.

rtk git diff --check
Passed.
```

No generated contract changed in this review, and no full suite, external
provider/database run, or commit was performed.

## OpenRouter review 4 of 6 guard fixes

The behavior review was clean, but its broader command exposed two repository
guard pins that the new adapter tests/restore writer had not joined:

- `internal/store_test` is now named in the exact raw-engine-handle harness
  allowlist. This follows the existing conformance/isolation external-harness
  pattern and admits only that package; the negative driver-handle fixture
  remains green, so ordinary packages still cannot name or obtain raw handles.
- `InvalidateRestoredAdapterCredentials` is now in the resolution surface's
  pinned proof-free writer list. This is the already-implemented local-host
  restore rule: remote Forgejo PATs have no Hikyo epoch the provider can check,
  so `CompleteRestore` must erase them before restored state is published.
  `TestCompleteRestoreClearsRestoredAdapterCredential` proves the resulting
  ciphertext and set timestamp are both absent.

Red reproduction and focused evidence:

```text
rtk go test ./internal/lint -run '^TestDriverHandlesRepo$' -count=1
FAIL: internal/store/adapter_runtime_test.go raw SQLiteRead/SQLiteWrite handles.

rtk go test ./internal/lint -run '^TestDenialWriterIsSoleWriter$' -count=1
FAIL: InvalidateRestoredAdapterCredentials absent from pinned writer list.

rtk go test ./internal/lint -run \
  'Test(DriverHandlesRepo|DriverHandlesCatchesViolations|DenialWriterIsSoleWriter|DenialWriter)' \
  -count=1
Go test: 4 passed in 1 package.

rtk go test ./internal/lint ./internal/store ./internal/service \
  -run 'Test(DriverHandles|DenialWriter|Adapter|CompleteRestore)' -count=1
Go test: 53 passed in 3 packages.

rtk git diff --check
Passed.
```

No product contract or generated artifact changed, and no full suite, external
provider/database run, or commit was performed.

## OpenRouter review 5 of 6 reservation-leak fix

- The review's request to block publish while an old provider request is live
  was rejected: `TestPublishedGenerationSupersedesWithoutStealingLiveProviderFence`
  remains unchanged and green. Publish may install the newest generation while
  preserving the old request's exact provider lease; the old effect can still
  terminalize and release that fence before the new job writes.
- A crash after `Reserve` but before `Prepare` no longer leaves an undesired
  name permanently claimed. The journal now exposes one narrow local
  `ReleaseReservation` operation. Forgejo Sync uses it for an undesired
  `reserved` ledger entry in both converge and scrub, without a provider
  delete, conflict artifact, INTENT, or OUTCOME.
- The store delete is constrained by the full org/project/environment/target
  chain, exact normalized name and surface, `reserved` state, current target
  generation, exact running outbox job/lease owner, and live lease. Tests prove
  an old generation is refused, another target is untouched, and owned or
  dispatched custody cannot be released through this path.
- A shared SQLite/Postgres conformance scenario reconstructs the crash,
  supersedes the generation, refuses the stale journal, and releases from the
  new journal with no conflict/effect row. Its SQLite leg passed locally; the
  Postgres leg is present but was not rerun because
  `HIKYO_TEST_POSTGRES_DSN` is absent in this environment.

Focused evidence:

```text
rtk go test ./internal/adapter/... -count=1
Go test: 59 passed in 2 packages

rtk go test ./internal/store -run 'Adapter|PublishedGeneration|Reservation' -count=1
Go test: 27 passed in 1 package

rtk go test ./internal/service -run 'Adapter' -count=1
Go test: 27 passed in 1 package

rtk go test ./internal/store/migrate -run 'Adapter' -count=1
Go test: 1 passed in 1 package

rtk go test ./internal/conformance -run \
  'TestConformanceSQLite/(adapter_crash_reservation_release_is_generation_fenced|publish_enqueues_adapter_sync_with_recorded_authority)$' \
  -count=1
Go test: 3 passed in 1 package

rtk git diff --check
Passed.
```

No full suite, external provider/Postgres rerun, or commit was performed.

## OpenRouter review 6 of 6 validated fixes

- Deleting a targeted key now cascades only its live target-membership and
  pending route-move snapshot rows in both SQLite and Postgres. This implements
  the ADR's narrowing rule without weakening the target/move/environment
  ancestry FKs. A real `Keys.Delete` regression proves schema fan-out queues a
  converge whose loaded manifest omits the key while the prior owned ledger
  slot remains present for the adapter's established prune path. Pending move
  claims now carry a nullable key id: key claims are composite-FK-linked to the
  move snapshot and cascade with it, while the two sentinel claims remain
  keyless. The production MoveTarget regression proves the writer emits that
  exact 2+1 shape. Migration coverage proves deletion retains exactly the two
  sentinels and lets another pending target reserve the freed effective name.
- `adapter.credential_replace` now carries the exact locked mutation's
  `previous_authority` and `authority`; credential revoke remains unchanged
  because it destroys custody without reassigning authority.
- Every configure operation that actually reassigns routing authority now
  emits the transactionally observed old and new principals: target add, full
  target update, move cancel, pending-target replacement, and pending-origin
  replacement. Store mutation results carry the transition so service events
  do not depend on stale pre-reads. Create, narrowing, delete, and remove retain
  their existing shapes; narrowing explicitly omits `previous_authority`.

Focused evidence:

```text
rtk go test ./internal/service ./internal/store ./internal/audit \
  ./internal/store/migrate ./internal/conformance ./internal/lint \
  -run 'Test(Adapter|TargetedKey|Registry|Conformance|SQLiteActiveDomain|ProofSignaturesRepo|SQLPredicatesRepo|DriverHandlesRepo|AuditAppendOnlyRepo|DenialWriterIsSoleWriter)' \
  -count=1
Go test: 122 passed in 6 packages.

rtk go test ./internal/store/migrate \
  -run TestAdapterEnvironmentChainRefusalPostgres -count=1
No tests found (the Postgres scenario skipped because HIKYO_TEST_POSTGRES_DSN is absent).
```

No generated contract changed. No full suite, external provider/Postgres
rerun, or commit was performed.

Stale pending-claim follow-up evidence:

```text
rtk go test ./internal/service ./internal/store ./internal/store/migrate \
  ./internal/conformance \
  -run 'Test(Adapter|TargetedKey|Conformance|SQLiteActiveDomain)' -count=1
Go test: 112 passed in 4 packages.

rtk go test ./internal/lint \
  -run 'Test(SQLPredicatesRepo|ProofSignaturesRepo|DriverHandlesRepo|AuditAppendOnlyRepo|DenialWriterIsSoleWriter)' \
  -count=1
Go test: 5 passed in 1 package.

Combined final rerun: 117 passed in 5 packages.
```

## External evidence

On 2026-08-17 the real-provider lifecycle passed against a disposable Forgejo
16.0.2 instance over TLS. Its repository-target flow exercised real provider
requests plus durable AdapterRuntime journals for reserved and dispatched crash
reconstruction, real Plan conflict observation, the service/store adoption
transition, outbox converge, and service RemoveTarget scrub:

```text
go test ./internal/isolation -run '^TestForgejoRealLifecycle$' -count=1 -v
--- PASS: TestForgejoRealLifecycle (0.64s)
```

That run exposed an IPv4-mapped IPv6 resolver result (`::ffff:x.x.x.x`) that
did not match an explicitly allowed IPv4 CIDR. The policy now canonicalizes
addresses with `netip.Addr.Unmap()` before special-use and CIDR checks, with a
focused regression test.

The real Postgres 17 migration and shared conformance corpus also passed:

```text
HIKYO_TEST_POSTGRES_DSN=... go test ./internal/store/migrate \
  ./internal/conformance \
  -run '^(TestAdapterEnvironmentChainRefusalPostgres|TestConformancePostgres)$' \
  -count=1 -v
Go test: 58 passed in 2 packages
```

The first Postgres run found two dialect-only test defects (an integer boolean
fixture and a JSON operator used directly on a TEXT audit payload) plus a
missing #65 table group in the reusable conformance reset order. Those defects
are fixed; a repeat run on the same database passed, proving reset/re-migration
as well as the new adapter scenario. A post-fix focused gate passed 82 tests in
the Forgejo, migration, and conformance packages. Disposable containers were
removed and their certificate/token directory was moved to Trash after proof.

## External rerun prerequisites

Run the provider lifecycle against a disposable Forgejo v1.21+ repository:

```text
HIKYO_TEST_FORGEJO_URL=... \
HIKYO_TEST_FORGEJO_TOKEN=... \
HIKYO_TEST_FORGEJO_OWNER=... \
HIKYO_TEST_FORGEJO_REPOSITORY=... \
HIKYO_TEST_FORGEJO_ALLOWED_CIDR=... \
go test ./internal/isolation -run TestForgejoRealLifecycle -count=1 -v
```

`HIKYO_TEST_FORGEJO_ALLOWED_CIDR` is needed only for an operator-approved
private test endpoint. The PAT must carry Forgejo's minimal applicable scope:
`write:repository` for repository targets or `write:organization` for org
targets. The test creates temporary prefixed secrets/variables and scrubs them.

Run the focused corpus with `HIKYO_TEST_POSTGRES_DSN` set to exercise the real
Postgres migration/store leg. CI deliberately fails rather than silently skips
that leg when `CI` is set and the DSN is absent.

## Review/merge notes

- Final boundary repair keeps HTTP and provider packages above the datastore:
  adapter records, conflict artifacts, and moves cross the server seam through
  service facade aliases; the service fixture constructs sessions through
  `authz.NewSession`; and the external-gated Forgejo lifecycle now lives in
  the allowed `internal/isolation` harness. Its throwaway initial/scrub names
  use a minimal local Journal, while reserved/dispatched crash replay continues
  to use the real durable AdapterRuntime journal and datastore.

  ```text
  rtk go test ./internal/boundary ./internal/lint ./internal/adapter/forgejo \
    ./internal/server ./internal/service ./internal/isolation \
    -run 'Test(StoreImportAllowlist|ForbiddenImports|EngineHandleBoundary|Adapter|ForgejoRealLifecycle)' \
    -count=1
  Go test: 37 passed in 6 packages.

  rtk go test ./internal/boundary ./internal/adapter/forgejo \
    ./internal/server ./internal/service -count=1
  Go test: 261 passed in 4 packages.

  rtk go test ./internal/isolation -run '^TestForgejoRealLifecycle$' -count=1
  No tests found (external Forgejo variables absent; package compiled and the
  gated lifecycle skipped).
  ```

  The seven isolation findings exposed by that exploratory run were narrowed
  and repaired without weakening the invariants: all adapter routes now map to
  their real operations, `cli:adapter` is tenant-classified, dynamic full-formula
  refusals are pinned as reviewed post-grant 403s, and the exact operation/query
  pins were refreshed. The audit-core lifecycle now drives configuration,
  inspection, connection test, provider conflict planning, artifact-bound
  adoption, manual supersede, durable converge, authority abort, credential
  replace/revoke, and keep-remote scrub through real service/runtime paths; all
  14 registered `adapter.*` event types are observed.

  ```text
  rtk go test ./internal/isolation \
    -run '^(TestInvariant13AllowlistPinning|TestInvariant06aFormulaPinning|TestTenantRoutesDeclareForbiddenOnlyForMFA|TestInvariant01ClassificationTotality)$' \
    -count=1
  Go test: 4 passed in 1 package.

  rtk go test ./internal/isolation -run '^TestAuditCoreSQLite$' -count=1
  Go test: 15 passed in 1 package.
  ```

  The subsequently approved closed `auth.cli_reauth_handoff` event now covers
  all four unauthenticated handoff routes. Its phase is exactly
  `start|inspect|approve|redeem`; outcomes are exactly `success|failure`; and
  its closed failure cause is
  `invalid_request|unauthenticated|unauthorized|invalid_or_expired|reauth_required|pkce_mismatch|already_consumed`.
  Success records commit with the handoff/session mutation. Failure records use
  the rollback-surviving settlement path, so policy, PKCE and spent-artifact
  refusals are durable while the attempted mutation remains rolled back.
  Payloads contain only the internal handoff id, operation, and environment set
  when known—never state, code, verifier, bearer, or credential material. All
  four wires map directly to this event and the registry emitter lifecycle is
  closed.

  ```text
  rtk go test ./internal/audit -count=1
  Go test: 12 passed in 1 package.

  rtk go test ./internal/service ./internal/isolation \
    -run '^(TestCLI|TestCLIAdapterReauthHandoffSQLite|TestAuditCoreSQLite|TestInvariantAuditCompleteness|TestInvariant01ClassificationTotality)$' \
    -count=1
  Go test: 18 passed in 2 packages.
  ```

  `rtk git diff --check` remains clean.

  The parent full-suite Postgres pass then exposed two harness-only #65 reset
  defects. `resetPostgres` now drops `cli_reauth_handoffs` before sessions and
  every migration 00024 adapter table in complete FK child-to-parent order:
  effects/conflicts, outbox, route-move claims/keys/targets/moves, target
  keys/ledger, targets, adapters. A second consecutive conformance run proves
  the reusable database no longer inherits stale #65 relations. Three adapter
  reauthentication Postgres tests were rerun independently; their failures
  were real dialect fixture defects (`1/0` written to BOOLEAN columns), not
  reset collateral. The shared fixtures now use `TRUE/FALSE`, which SQLite
  accepts too.

  ```text
  HIKYO_TEST_POSTGRES_DSN=... go test ./internal/conformance \
    -run '^TestConformancePostgres$' -count=1
  ok (repeat run: 8.965s)

  HIKYO_TEST_POSTGRES_DSN=... go test ./internal/isolation \
    -run '^(TestAdapterReauthTOTPMixedPolicy|TestAdapterReauthWebAuthnBindsFullEnvironmentSet|TestCLIAdapterReauthHandoff)(SQLite|Postgres)$' \
    -count=1
  ok (six top-level tests, 3.988s)
  ```

  The CLI reauthentication visual matrix now intercepts only the exact
  display-policy read for its addressed opaque state. The schema-valid fixture
  contains operation, environment policy, bound loopback redirect, and expiry
  only—no internal id, bearer, verifier, code, or credential. The test asserts
  the exact GET path and state, then exercises the real `CLIReauth` component's
  TOTP input and Authorize/Cancel controls. All other workspace requests and
  surfaces remain backed by the real two-instance harness.

  ```text
  pnpm exec playwright test e2e/flows/workspace.spec.ts \
    --grep 'pinned assertion set on Authorize CLI'
  Playwright: 4 passed. The filtered process then reports the expected
  repository-wide execution-closure error because unrelated flow specs were
  intentionally excluded.

  pnpm exec playwright test e2e/flows/workspace.spec.ts
  Playwright: 22 passed. The workspace-only process then reports the expected
  repository-wide execution-closure error for the seven surfaces owned by
  other spec files; no workspace test failed.

  pnpm run typecheck
  TypeScript: passed.
  ```

  Final parent-owned local verification is green:

  ```text
  Build + vet: passed.
  Full Go suite with Postgres: passed (3005/44).
  Full web E2E: 128/128 passed.
  GoReleaser v2.17.1 snapshot: passed; 6 targets built in 4m46s.
  Snapshot-manifest classifier: passed.
  ```

  These results prove the local build, both-database Go paths exercised by the
  final suite, complete browser matrix, and release packaging/classification.
  They do not replace the separately gated real-Forgejo lifecycle proof above;
  that remains an external prerequisite requiring the Forgejo URL, scoped PAT,
  owner/repository, and any operator-approved private endpoint policy.
- The worktree is intentionally uncommitted for the parent lifecycle owner.
- Generated sqlc/OpenAPI output is included alongside source changes.
- The public grammar, atomic first-target bootstrap, adoption selection,
  origin-scoped egress policy, scrub-first move semantics, and purpose-aware
  reauthentication semantics are resolved and implemented to the extent noted
  above. Do not restore the superseded routing/ceremony design questions.
- The parent-owned final broad suite and release snapshot have run successfully;
  do not rerun them before commit without a new code change.
- Postgres acceptance is covered by the final parent-owned suite. Do not claim
  real-Forgejo acceptance until the external command above runs successfully.
