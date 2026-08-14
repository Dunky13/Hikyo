# Handoff: #44 authorize chokepoint

Issue: https://github.com/Hikyo-Org/hikyo/issues/44 (parent #41). Spec:
`docs/adr/tenant-isolation.md` and `docs/adr/permission-model.md` on
`wayfinder-docs`.

## What exists

Proof-carrying authorization, end to end, with a demonstration operation set
(the real surfaces land in #47/#48/#54/#55 against the same registries):

- `internal/domain` — leaf vocabulary: tenant id types (`OrgID`,
  `ProjectID`, `EnvID` — the types the proof-signature analyzer bans from
  store signatures), `Capability` atoms used by the demo formulas, `Scope`
  (+ gap-refusing `Level()`), `Grant`, and the two uniform sentinels:
  `ErrNotFound` (unauthorized ≡ nonexistent, tenant class) and
  `ErrUnauthorized` (grant refusal, instance class).
- `internal/authz` — the chokepoint. `Proof` is an interface with an
  unexported method, one unexported concrete type for all three kinds
  (tenant / instance / system); the only forgeable value is `nil`, rejected
  at the boundary. `TxAuthorizer.Authorize(principal, op, scope)` resolves
  the addressed chain in **one query** (denormalized chain columns +
  composite FKs make the addressed row's chain authoritative), skips the
  grant lookup entirely on a miss (so a probe counts 1 query regardless of
  failing level), evaluates the operation's formula (conjunction of
  capability atoms; grants additive, inheriting downward, no deny rules),
  and mints a proof bound to (operation, transaction token, resolved
  chain). `Verify(proof, storeOp, token)` is the store boundary: nil /
  foreign-tx / ended-tx / op-mismatched proofs die before any query, and it
  returns the resolved chain the binding layer must use.
  `SystemAuthority(site, tok)` mints the no-principal proofs against the
  closed 4-site registry (all per-site operation sets empty today —
  fail-closed; recovery/break-glass arrive with #54/#55). The operation
  registry, system-site registry and wire classification live here;
  `RegistryFacts` exposes them read-only to the invariant tests.
- `internal/store/authn` — the enumerated resolution surface (the bootstrap
  carve-out): chain resolution + grant lookup, built directly on the
  generated queries, importable only by `authz` and `tx` (boundary test).
  Deliberately a **concrete type**: an interface could be satisfied
  structurally by a fake resolver returning attacker-chosen chains — a
  proof forgery no import test would see.
- `internal/store` — every repository method takes `(ctx, proof, ...)`,
  verifies at the boundary first, and binds chain columns exclusively from
  the verified proof (`repos.go` is the binding layer). Tenant-owned
  aggregates take no identifiers at all — addressing comes from the proof.
  `NewProject`/`NewEnvironment` insert carriers have no chain fields.
  Autocommit reads are gone: there is no proof-free path to tenant data.
- `internal/store/tx` — `Write` and now `Read` (pg read-only tx / sqlite
  read-pool tx): each **attempt** mints a fresh `TxToken`, builds the
  resolver on the attempt's own transaction, hands the closure a
  `TxAuthorizer`, and invalidates the token on commit *and* rollback — a
  proof cannot outlive its transaction or leak into a retry attempt. The
  sqlite read pool got its own DSN **without** `_txlock=immediate`: with
  the write DSN a held read transaction would open BEGIN IMMEDIATE and
  starve the single writer (`tx.TestReadTransactionDoesNotBlockWriter`
  holds a read open across a write to keep this true).
- `internal/service` — demonstration services: Orgs (instance-scoped
  scaffolding: `org.create/get/list` under `instance-config`), Projects
  (`project.create` = `manage-projects(O)`), Environments
  (`environment.create` = `definitions-edit(P)`, `environment.read` =
  `read(E)`, `environment.update-note` = `edit(E)`). One tenant operation
  per chain depth, using only atoms the permission ADR fixes.
- Migrations `00002` (both engines): `projects`, `environments` with
  **composite ancestry FKs** (`(org_id, id)` / `(org_id, project_id, id)`
  unique keys, children reference the composite), `principals`, `grants`
  (scope triple, gap-refusing CHECK, composite FKs per scope class; no
  uniqueness over the triple — NULL-scope UNIQUE semantics diverge between
  engines, dedup is #55's grant API). Scope-class directives
  (`-- hikyo:table <t> class=<c> chain=<cols>`) declare every table; the
  derived registry is total or the build fails.
- `internal/lint` — the analyzers, run as build-failing tests against
  the real repo, each with negative fixtures proving it catches what it
  claims: proof signatures (repo surface discovered from `Repos`/`ReadRepos`
  transitively; tenant-typed params banned incl. struct fields), SQL
  predicate confinement (conservative: UNION/CTE/OR/JOIN/subquery/parens
  rejected outright; per-table chain conjuncts; INSERT chain columns; no SET
  on chain/id; annotated queries exempt-but-pinned), forgery guard
  (nil-in-Proof-position across call/var/assign/return/keyed-literal;
  reflect/unsafe + Proof handling; exemption is exact-path, so a
  neighbouring `internal/authz*` package cannot inherit it). A fourth check,
  `CheckDriverHandles`, confines the two one-line bypasses of the whole
  boundary: the raw driver accessors (`DB.PG/SQLiteWrite/SQLiteRead`) and
  direct imports of the sqlc output packages, each to an exact allowlist,
  across the module including tests.
- `internal/isolation` — the probe harness + invariants (below). Fixtures:
  two orgs; human in org B probing org A (cross-org axis); machine
  principal confined to `(org A, project A1)` probing project A2
  (cross-project axis); no-grant principal (capability-denial axis);
  positive controls proving the probes fail at the boundary, not because
  the surface is broken, and that written rows carry exactly the proof's
  chain (binding provenance).

## Invariant → test map

| # | Invariant | Test |
|---|---|---|
| 1 | Classification totality (+ system network-unreachability) | `isolation.TestInvariant01ClassificationTotality` |
| 2 | Probe fixture axes self-check | `isolation.TestInvariant02ProbeFixtureAxes` (+ probe table axes) |
| 3 | Uniformity (status/body byte-shape; timing structural, not wall-clock) | `assertUniformNotFound` in every probe, `TestIsolationSQLite`/`Postgres` → `tenant_probes`; query-count: `query_count` subtests |
| 4 | No side effect (row diff; effect ports vacuously zero — registries empty) | `tenant_probes` mutation probes + `instance_probes` |
| 5 | Proof lifecycle (nil / foreign-tx / ended-tx / op-mismatch, retry invalidation) | `authz.TestVerify*` (unit) + `proof_lifecycle_e2e` (integration) |
| 6 | Operation registry completeness (+ anti-widening formula pin) | `isolation.TestInvariant06OperationRegistryCompleteness`, `isolation.TestInvariant06aFormulaPinning` (fixture `testdata/operation_formulas.json`) |
| 7 | Proof-signature analyzer | `isolation.TestInvariant07ProofSignatures`, `lint.TestProofSignatures*` |
| 8 | Predicate confinement + chain-binding provenance | `isolation.TestInvariant08PredicateConfinement`, `lint.TestSQLPredicate*`, provenance: `positive_controls` + conformance `tenant_chain_roundtrip` |
| 9 | Forgery guard | `isolation.TestInvariant09ForgeryGuard`, `lint.TestProofForgery*`, `authz.TestVerifyRejectsEmbeddedInterfaceForgery` |
| 9a | Driver-handle + generated-package confinement | `isolation.TestInvariant09aDriverHandleConfinement`, `lint.TestDriverHandles*` |
| 10 | Tenant columns / composite ancestry FKs / chain immutability | `chain_constraints` subtests (behavioral, both engines) + analyzer 2's SET ban |
| 11 | System-proof enumeration and binding | `isolation.TestInvariant11SystemProofEnumeration` + `authz.TestSystemProof*` |
| 12 | Cache discipline | `isolation.TestInvariant12CacheDiscipline` (no caches exist; heuristic forces registration) |
| 13 | Allowlist pinning (`instance-scoped` + `authn-resolution`, name + SQL hash) | `isolation.TestInvariant13AllowlistPinning`, fixture `internal/isolation/testdata/annotated_queries.json` |

Acceptance criteria: query-count instrumentation (`query_count`: exactly 1
query on a miss at any level, 2 on evaluated denial/success) runs on both
engines; handlers-cannot-import-store plus the new edges
(server↛authz, authn importable only by authz/tx, authn imports only
gen+domain) live in `internal/boundary`.

## Cross-model review (gpt-5.6-sol, high effort)

Round 1 returned 5 findings; all fixed in this branch, none deferred:

1. *(HIGH)* Raw driver handles and the generated query packages bypassed the
   chokepoint entirely — a package holding a `*store.DB` could run
   `pggen.New(db.PG()).GetEnvironment(...)` with any tenant's chain and no
   proof, with every analyzer still green. Fixed by `lint.CheckDriverHandles`
   (two exact allowlists, invariant 9a) plus forbidden service→gen edges,
   with a negative fixture. **R2 found this fix PARTIAL** — a locally
   declared structural interface (`interface{ PG() *pgxpool.Pool }`), a type
   assertion to one, or a handle simply passed in as a parameter all evade
   an accessor-call check, since the selector resolves to the local method.
   Closed by additionally refusing non-allowlisted packages the right to
   *name* a driver type at all (walk scoped to module-declared types, so the
   driver libraries' own graphs don't produce false positives); all three
   escapes are in the negative fixture.
2. *(HIGH)* Postgres read transactions ran at the server-default READ
   COMMITTED, so chain resolution, grant evaluation and the store read could
   each see a different snapshot — a proof certifying a policy no snapshot
   ever held. Fixed by `pgx.RepeatableRead` on read transactions (matching
   sqlite's WAL reader snapshot); `read_snapshot_stability` covers it and
   was confirmed to fail under the old setting.
3. *(MEDIUM)* The forgery guard exempted packages by path *prefix*, so an
   `internal/authzforge` would have been skipped. Fixed: exact-path
   exemption + a collision test.
4. *(MEDIUM)* `Proof` was satisfiable by interface embedding
   (`type forged struct{ authz.Proof }`), and `Verify` panicked on the
   promoted nil rather than failing closed. Fixed by asserting to the
   canonical concrete type; covered by
   `TestVerifyRejectsEmbeddedInterfaceForgery`.
5. *(MEDIUM)* Probes could not detect a *widened* formula, since fixture
   principals held every capability in play. Fixed by the content-pinned
   operation→formula map (invariant 6a) plus a least-privilege principal
   (`usr_reader`, exactly `read`) with denial probes on the three operations
   whose formulas demand more, and a positive control proving its one
   allowed operation still succeeds.

Round 2 verdict: findings 2–5 **FIXED**, finding 1 **PARTIAL** → closed as
above. No new criticals.

Round 3 (final, cap reached) returned **BLOCKING 2**, both against that
closure and both **dispositioned by applying the prescribed fix**: (i) the
walk had no alias case, so `type pool = pgxpool.Pool` plus
`interface{ PG() *pool }` slipped through — driver types are now keyed by
their *named* identity (not their pointer spelling) and aliases are
unwrapped; (ii) `TypesInfo.Defs` alone misses types that exist only as
expressions — a generic instantiation like `holder[*pgxpool.Pool]` carries
the concrete handle nowhere else — so expression types and generic type
arguments are walked too. Both escapes are in
`testdata/badhandle/evasions.go`, asserted at source-located positions. Remaining honest limit, stated rather than hidden:
an allowlisted package could still hand out a wrapper whose methods run
queries behind a driver-free interface. The allowlist *is* the trusted set
({store, store/tx, store/migrate, the two generated packages, the two
harnesses}), and changes to it are the highest-scrutiny diffs in the repo —
which is the ADR's own posture, not a gap this ticket introduces.

## Deviations from the ADR letter, stated

- **`authn` importable by `tx` as well as `authz`.** The ADR says
  "importable only by the authorization package", but the store imports
  authz (Proof/Verify), so authz cannot also be imported *by* store
  internals — the resolver is therefore constructed by the transaction
  package (per attempt, on the attempt's own tx) and handed to authz inside
  an opaque `TxAuthorizer`. Service code never sees the resolver; the
  boundary test pins the two importers.
- **Analyzers are go/packages passes run from tests, not go/analysis under
  a linter.** Same inputs, same build-failing effect; the repo's linter is
  `go vet` and gains nothing from the framework here.
- **`ClassStub`** for unimplemented CLI verbs: not one of the four probe
  classes — a declared not-yet-an-operation marker whose contract (no
  route, no registered operation) the totality test enforces, so an
  implementation cannot ride in on a stale class.
- **System-site operation sets are all empty**: boot pragma checks and
  migration DDL run inside the trusted set below the store-method surface,
  so no production `SystemAuthority` call site exists yet. First real mint
  sites arrive with recovery mode (#54) and break-glass (#55); invariant 11
  pins today's empty sets.
- **Uniformity is asserted at the error level, not HTTP bytes.** No tenant
  HTTP routes exist yet, so invariant 3's "byte-identical status and body
  shape" is delivered as sentinel + rendered-message equality at the service
  layer (`assertUniformNotFound`). **#47/#48 inherit the byte-shape
  obligation at the response layer** — the shared assertion helper must move
  up to real wire responses when routes land.
- **The chain-binding layer is hand-written, not generated.** The ADR says
  "the binding map … is generated"; `internal/store/repos.go` is the
  hand-written binding layer, with the intent held by analyzer 1 (no chain
  params in signatures) plus empirical provenance assertions (positive
  controls + conformance). Revisit codegen if the aggregate count makes the
  hand-written map review-heavy.
- **sqlite query files use positional `?`** — sqlc's sqlite engine
  mis-generates `sqlc.arg()` (and multibyte comment characters shift its
  statement offsets — keep query-file comments ASCII). Postgres keeps the
  named `sqlc.arg(chain_*)` reserved parameters; provenance on both engines
  is enforced by the Go binding layer + conformance/probes, not param names.

## Pickup notes

- Adding an operation: register in `authz.operations` (class, level,
  formula, storeOps) — a store method without a registered operation, or
  vice versa, fails invariant 6; a new wire entry point fails invariant 1
  until classified.
- Adding a table: declare `-- hikyo:table` in the migration (both engines,
  identical) or the derived registry totality fails; tenant-owned tables
  get chain columns + composite FKs or invariant 10's constraint probes
  won't hold.
- Annotating a query (`instance-scoped` / `authn-resolution`) requires
  re-pinning `internal/isolation/testdata/annotated_queries.json` — the
  diff is the review artifact.
- Grant writes are fixture-only raw SQL until #55 lands the grant API.
- Postgres locally: any 17/18 scratch db; harnesses drop
  grants/environments/projects/principals/orgs/goose_db_version. The
  isolation harness derives its own database (`<name>_isolation`, created
  on first run — the test user needs CREATE DATABASE, true for the CI
  service user) because `go test ./...` runs conformance and isolation in
  parallel and they must not share tables.
