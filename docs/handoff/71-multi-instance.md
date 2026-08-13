# Handoff: #71 multi-instance — directory tier + workspace tier

Issue: https://github.com/Dunky13/hikyo/issues/71. ADR: `.xreview/multi-instance-adr.md`
(locked 2026-08-06). MVP gate: M6 in `.xreview/mvp-boundary.md`.

Status: **IN PROGRESS.** Foundation, store, service, audit, API, CORS/CSP, CLI,
the Go E2E lifecycle and the two-instance harness are done and green on BOTH
engines. Criteria 1, 2, 4, 5 and 6 are met; 3 is partly met with two named
blockers. **What remains: the
web UI + Playwright flows, and the two-instance E2E harness** — plus two named
gaps (the workspace session's assurance record, and the step-up elevation path)
that need Marc. See "Session 2 progress", "Session 2, second half" and
"STILL NOT DONE".

**Read first if you are resuming:** "STILL NOT DONE" (what is left and why the
UI is atomic), then "Repo facts", then BOTH trap lists ("Traps hit while
building this" from session 1 and "More traps hit (session 2)"). Those are the
parts that cost real time and that no amount of reading the ADR would have told
you. The decision list runs 1-15 across both sessions and is the review
surface.

## Plan (as designed, before code)

### What already exists (pre-seeded by #55)

- `domain.CapInstanceDirector = "instance-directory"` — the atom, instance level
  (`internal/domain/domain.go:58,108`). Deliberately NOT in `OperatorSet`.
- `domain.ClassInstanceConn = "instance-connection"` machine class, with
  `machineAllowlists[ClassInstanceConn] = {CapInstanceDirector: true}` and
  `machineDepths[ClassInstanceConn] = LevelNone`
  (`internal/domain/permission.go:141,207,247`).

So half of the ADR's #15 amendment is already law. What #71 adds is everything
that *uses* it.

### Schema (migration 00020, both engines)

| Table | Side | Why |
|---|---|---|
| `instance_identity` | both | singleton row; server-generated opaque id, returned only in the authenticated directory listing |
| `remotes` | viewing | name (unique), url, spki pin, sealed credential, created_at |
| `remote_snapshots` | viewing | last-known listing + fetched_at + outcome; FK CASCADE off `remotes` |
| `instance_connections` | serving | binds a machine principal (class `instance-connection`) to a label |
| `workspace_origins` | serving | the origin allowlist (exact origins) |
| `workspace_handoffs` | serving | short-lived single-use handoff transactions |
| `sessions` (ALTER) | serving | + `requesting_origin`, `handoff_id` nullable columns |

**Key decision — workspace sessions reuse the `sessions` table.** The ADR says
the workspace session is "a server-side session row on the issuing instance in
every locked mechanical respect", differing only in transport plus two bound
fields. Reusing the row type inherits, for free and structurally: idle/absolute
clocks, generation invalidation, credential epoch, account disablement, restore
inertness, the active-session listing, and explicit revocation. A parallel table
would have had to re-implement all of it and would drift. Origin-atomic
revocation becomes one statement over `requesting_origin`.

### Bearer grammar (`internal/crypto/bearer.go`)

Four new closed-list artifact types: `ic` (instance connection — the #17
amendment's named row), `ws` (workspace session), and `hs`/`hc` (the handoff
state and authorization code that cross the front channel). The last two exist
for the same reason `st` does: the grammar buys the audit redaction filter and
offline checksum validation for a value that leaves the process.

Caveat that bit once already: the bearer TYPE (`ws`) and the value a session
row's `artifact` column stores (`workspace`) are different strings. See trap 4.

`hs` and `hc` are **declared ahead of their consumer** — the handoff-transaction
service (resume item 3) is what mints and redeems them. They are in the grammar
now because the closed type list is the thing the audit redaction filter and the
offline checksum validator both read, and a value that crosses a redirect
without being in it is a value that leaks unredacted. Not dead entries; unwired
ones, and the wiring is a named resume item.

### Where `ws` is admitted (deliberate)

`ws` is admitted in the session leg of `AuthenticateCaller` only, never in
`Authenticate`. `Authenticate` is the account-security mechanism (logout,
factor enrolment, passkeys, identity linking, step-up), so a workspace bearer
is refused there by construction — the same structural trick #61 used to keep
machine tokens out of the human session surface. Workspace rows carry a nil
CSRF verifier like CLI sessions: the bearer rides an `Authorization` header,
nothing is ambient, and the transport must not demand a synchronizer token on
that leg.

### CORS and CSP (criterion 3 depends on this)

- **Serving side**: CORS echoes exactly one matching allowlisted origin, in
  non-credentials mode, on `/api/v1`, on the handoff endpoints, and on the
  pre-auth meta endpoint — the version-skew check reads meta live and
  cross-origin, so meta must be CORS-readable for allowlisted origins. A
  non-allowlisted origin gets no CORS headers at all.
- **Viewing side**: the locked CSP baseline's `connect-src` is extended
  dynamically with exactly the origins of the configured remote entries — still
  a closed list, never `*`.

### Double confinement (acceptance criterion 4)

1. **Grant API**: already structural via `domain.MachineMayHold` — the
   instance-connection class admits exactly `instance-directory`.
2. **Artifact eligibility**: NEW. `internal/authz/eligibility.go` — a map from
   artifact type to the closed operation set it may reach; an artifact type
   absent from the map is unconfined (today's behaviour for `cli`/`br`/`wl`/`au`),
   an artifact type present is confined to its list. `ic` maps to exactly
   `{remote.directory-serve}`. Enforced at the top of
   `TxAuthorizer.Authorize` — the single chokepoint — so it cannot be bypassed
   by a new endpoint. CI invariant enumerates every registered operation and
   asserts `ic` is refused on all but one.

### Operations (authz registry)

Viewing side (instance class):
`remote.add`, `remote.list`, `remote.show`, `remote.rename`, `remote.remove`
(`instance-config` for mutations, `instance-directory` for reads),
`remote-credential.create|list|show|revoke` (`instance-config`).

Serving side:
`remote.directory-serve` (`instance-directory`, evaluated on the connection
principal), `workspace-origin.list|add|remove` (`instance-config`),
`workspace-session.list|revoke` (rides the existing session surface).

### Outbound client (`internal/remotefetch`)

Control set is normative (ADR § The outbound client): https-only canonical
origin; SPKI pin verified on every connection before bytes; no redirects ever;
private ranges explicitly permitted; per-remote deadline; response size cap;
length-capped ingest; fan-out cap; coalescing window; per-viewer AND
instance-wide aggregate trigger rate; explicit-config CONNECT proxy only.
Zero remotes ⇒ zero outbound connections.

Instrumented: every dial goes through one counting dialer, so the harness can
assert the server originates no connection during workspace use (M6's recast of
criterion 6).

### Audit (`remote.*`)

Viewing: `remote.added`, `remote.removed`, `remote.renamed`,
`remote.fetch_failed` (closed outcome enum), `remote.directory_viewed`.
Serving: `remote.credential_minted`, `remote.credential_revoked`,
`remote.origin_allowlist_changed`, `remote.directory_served` (access class),
`remote.auth_failed` (authn, distinct from an authz denial),
`remote.workspace_session_issued|revoked|expired`, `remote.handoff_failed`.

### CI deliverables (not manual checks)

1. `ic` artifact refused on every operation but directory-serve.
2. Route-table / OpenAPI closure: no server-side proxy endpoint exists.
3. Outbound-byte instrumentation asserting zero server-originated connections
   during workspace use.

## Repo facts a resumer needs (verified, not assumed)

- PG test DSN env var is **`HIKYO_TEST_POSTGRES_DSN`**, not `WENV_*`. Working
  value: `postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_71`. Everything below is
  verified on **both** engines. If a run hits SQLSTATE 2BP01 or "relation
  already exists", the DB is carrying another branch's schema — create a fresh
  one (`psql ... -c "CREATE DATABASE hikyo_71b OWNER hikyo"`, single statement
  per `-c`) and switch the DSN.
- Node: `.nvmrc` says 24; `eval "$(fnm env)" && fnm use 24`.
- Regeneration (no Makefile): `go tool sqlc generate` and
  `go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml`, both
  from the repo root; `cd clients/ts && pnpm run generate` for the TS client.
  CI diffs all three and fails on drift.
- Adding an operation drags a fixture cascade: `operation_formulas.json`
  (prints the corrected JSON on failure), an `events:`/`auditedNone:`/
  exemption entry, a `wireRegistry` row **if** it has an HTTP route or CLI
  verb, and a formula-matrix fixture if it mints a proof
  (`TestMatrixCoversEveryProofMintingOperation`).
- Adding an audit event: const + `TypeSpec` row in `internal/audit/registry.go`
  **and** an emitter in `authz.operations[...].events` or `classify.wireEvents`
  — the closure invariant refuses a registered type with no emitter.
- Adding a query: both engines, same `-- name:`, sqlite uses `?` and **ASCII
  comments only** (multibyte shifts sqlc's statement offsets), postgres uses
  `sqlc.arg()`. Annotated queries are content-pinned in
  `annotated_queries.json`.
- The CSP to extend for the viewing side is
  `internal/server/spa.go:42` (`connect-src 'self'`).
- `internal/authz/session.go:192` `AuthenticateCaller` is where `ws` and `ic`
  legs attach; `Authenticate` (human-only) must stay closed to both.
- `internal/service/grants.go:1103` `checkPrincipalClass` special-cases only
  `CapSCIMProvision` with `ErrSystemCreatedOnly`. **`CapInstanceDirector` needs
  the same guard** — permission.go's own comment says it is "never grantable
  through this API at all", and today it would be grantable if a principal of
  that class existed. This is a real gap #71 must close.

## Decisions taken (review these)

1. **Workspace sessions reuse the `sessions` table.** Migration 00020 rebuilds
   it on BOTH engines to widen the `artifact` CHECK to
   `('cli','browser','workspace')` and add `requesting_origin` + `handoff_id`
   with a CHECK tying them to the workspace artifact.
   - Postgres could have used three ALTERs but rebuilds too, because the
     cross-engine directive-parity lint fails on a `hikyo:table` directive
     that exists on one side only — a temporary table must exist on both.
   - The rebuild restates the shape `sessions` **has reached by 00014**
     (`csrf_verifier` from 00006, `provider_id` from 00007, `saml_provider_id`
     + the singular-provenance CHECK from 00010). A rebuild copying only
     00005's columns silently drops three. This is a one-time frozen cost:
     migrations are immutable, so 00021 alters the post-00020 table normally.
   - **In-flight `reauth_windows` rows do not survive the migration**, on both
     engines, explicitly (`DELETE FROM reauth_windows`) rather than as an
     incidental cascade only sqlite would perform.
2. **Instance identity is minted by the migration**, not by a boot mint site:
   boot's system-proof operation set is closed by invariant 11 and growing it
   would reopen the tenant-isolation ADR for a value whose only correct moment
   to exist is the moment the schema does. `randomblob`/`gen_random_uuid`.
3. **Principal + credential are one row** (`instance_connections`), because the
   ADR makes them one unit: one credential per principal ever, revoke retires
   both. Two tables would have admitted the orphan principal and the re-armed
   revoked one the lifecycle exists to prevent. It is NOT a `service_accounts`
   row — that table's kind CHECK admits only workload/automation and its
   composite FK demands a project this principal has not got.
4. **`remote.workspace_session_expired` will not be registered.** No scheduler
   exists and session-authn misses are deliberately silent, so it would have no
   honest emitter and the closure invariant would rightly refuse it. Same
   disposition #61 took for the per-key disclosure event. Flagged for Marc.
5. **`remote rename` is API + UI only, never a CLI verb.** The #25 amendment's
   closed verb list is `remote add|list|show|remove`, but the display name is
   "the one mutable field" and `remote.renamed` is a named audit event needing
   an emitter. Parity holds because the API is public surface.
6. **Grant origin for the connection principal**: the grant row is written at
   the store layer by the connection minter, not through the grants API, so
   `mintableOrigins` stays untouched.

## Progress log

- ADR + M6 read in full; three parallel maps of the codebase taken; plan above.
- **DONE — bearer grammar.** `internal/crypto/bearer.go`: added `ic`
  (instance connection), `ws` (workspace session), `hs`/`hc` (the two
  front-channel handoff values). The `hik_` audit redaction filter covers them
  for free.
- **DONE — migration 00020, both engines.**
  `internal/store/migrations/{sqlite,postgres}/00020_multi_instance.sql`.
  Tables: `instance_identity`, `remotes`, `remote_snapshots`,
  `instance_connections`, `workspace_origins`, `workspace_handoffs`, plus the
  `sessions` rebuild. `go tool sqlc generate` is clean; models regenerated in
  `internal/store/{sqlitegen,pggen}/models.go`.
  **Verified green (sqlite only):** `go test ./internal/store/...
  ./internal/lint/... ./internal/conformance/...` — 58 passed. This covers the
  scope-directive totality lint, the cross-engine parity lint, and the
  conformance corpus on sqlite.

- **DONE — artifact eligibility, the second half of the double confinement
  (acceptance criterion 4b).** `internal/authz/eligibility.go`:
  `artifactEligibility` is an ALLOWLIST OF CONFINED TYPES — absent = unconfined
  (today's behaviour for every existing artifact), present = confined to the
  listed operations. `ic` → exactly `{remote.directory-serve}`. Enforced at the
  top of `TxAuthorizer.Authorize` (`internal/authz/authorize.go`), before the
  formula and before chain resolution, so no future endpoint can bypass it; the
  refusal wears the operation class's own uniform (`ErrNotFound` for tenant,
  `ErrUnauthorized` for instance) so eligibility is not a side channel.
  CI invariant: `internal/isolation/eligibility_test.go`, three tests, all
  ranging over the LIVE operation registry rather than a restated list.
- **DONE — `remote.directory-serve` registered** in the authz operation
  registry (instance class, `instance-directory@instance`), with its
  `operation_formulas.json` repin. It is registered ahead of its serving
  surface deliberately: a confinement naming an unregistered operation confines
  nothing.
- **DEFERRED WITH A PINNED REASON — the `remote.directory_served` audit event.**
  The audit registry's closure invariant refuses a type with no emitter, and
  `TestAuditCoreSQLite/every_registered_type_is_actually_emitted` additionally
  requires the type to be emitted in the E2E run. With no serving surface yet
  there is nothing to emit it, so the operation is pinned in
  `audited_exemptions.json` with the full reasoning instead. Both the event and
  the exemption removal land with the directory service.

- **DONE — the `checkPrincipalClass` gap closed** (`internal/service/grants.go`).
  `CapInstanceDirector` on a MACHINE principal is now `ErrSystemCreatedOnly`.
  Note the asymmetry, which is the whole point and was nearly got wrong: a
  **human** must stay grantable `instance-directory` — it is the ADR's own
  grantable atom for the viewing side ("the admin grants the hop to exactly the
  humans who work across instances"), so the refusal is placed after the
  `ClassHuman` early return. The class allowlist could not carry this:
  `MachineMayHold(instance-connection, instance-directory)` has to be true or
  the chokepoint could not evaluate the formula, so the allowlist answers "may
  it HOLD this" while the API needed "may it be ATTACHED BY HAND".
- **DONE — store queries, both engines.**
  `internal/store/queries/{sqlite,postgres}/remote.sql`:
  `InstanceConnectionByVerifier`, `ListInstanceConnections`,
  `GetInstanceConnection`, `CreateInstanceConnection`,
  `RevokeInstanceConnection`, `TouchInstanceConnection`, `InstanceIdentity`.
  Liveness predicates are deliberately NOT in the `WHERE` of the authentication
  read — filtering there would make an unknown credential cost one row and a
  revoked one zero, a query-count oracle. `RevokeInstanceConnection` nulls the
  verifier in the same statement so a revoked row cannot collide with a re-mint
  in the unique index.
- **DONE — resolver.** `internal/store/authn/remote.go`, mirroring
  `machine.go`'s work-shape uniformity including the **engine-matched** decoy
  rows (`decoyConnectionRowSQLite`/`PG`) and `sinkDecoy`, so a postgres miss
  does postgres' timestamptz work rather than sqlite's string parsing — the
  exact defect #61's R3 found.
- **DONE — the `ic` and `ws` authentication legs.**
  - `authenticateInstanceConnection` (`internal/authz/machine.go`) sets
    `Artifact: string(crypto.ArtifactInstanceConn)` — **not** `conn.Kind` —
    which is the trap noted below; the confinement is live because of it.
    Two reads (connection row + epoch), not the machine leg's three, because
    the connection row holds principal and credential as one unit.
  - `Authenticate` was refactored into `authenticateSession(..., admits ...)`.
    `Authenticate` admits `cli`+`browser` only; `AuthenticateCaller` admits
    `cli`+`browser`+`workspace`. So every account-security verb (logout, factor
    enrolment, passkeys, identity linking, step-up) refuses a workspace bearer
    **by construction** — a cross-origin credential living in another origin's
    JavaScript must never be able to mutate the human's own auth factors.
- **DONE — `ResolutionSurfaceWriters` pin** extended with the three new
  proof-free writers (`internal/lint/appendonly.go`).
- **DONE — `annotated_queries.json` repinned** (306 entries).
- **DONE — criterion 4's E2E half.**
  `internal/isolation/instance_connection_e2e_test.go`, both engines. Mints a
  REAL credential (principal + `instance_connections` row + `instance-directory`
  grant, as one unit), resolves it through the REAL chokepoint, then asserts it
  reaches `remote.directory-serve` and is refused on **every other registered
  operation**, each addressed at the depth its own registry row demands so the
  refusal that fires is the confinement rather than a scope-depth bug. Also
  asserts `Identity.Artifact == "ic"` explicitly, and that revocation bites at
  the very next presentation. **Criterion 4 is now met, not inert.**

- **DONE — criterion 6's CI half: the no-proxy closure test.**
  `api/noproxy_test.go`, three tests. The criterion is "vacuously testable" per
  the ADR, and a test that asserted nothing would go green forever *including
  on the day someone adds the proxy*. So it asserts closure instead:
  (a) no contract path names relaying (`proxy`/`forward`/`relay`/`tunnel`/…);
  (b) no path takes a caller-chosen `{url}`/`{host}`/`{target}`/`{path}` — an
  endpoint whose target is named by the request is a proxy whatever it is
  called; (c) `pinnedRemoteSurface` is an explicit allowlist, empty today, so
  the first `/api/v1/remotes/...` path to appear fails until someone adds it
  **and confirms what it returns**; (d) the same refusal re-applied to the Go
  wire registry, so a route added Go-first still trips a #71 assertion.
- **DONE — the outbound client.** `internal/remotefetch/`. The ADR's seven
  normative controls: https-only canonical-origin grammar (no userinfo, path,
  query or fragment — a stored value carrying one is refused, never silently
  normalised); SPKI pin verified on every connection *before any bytes are
  written*, via `VerifyPeerCertificate`; no redirects ever (a redirect is a
  fetch failure **by name**); private ranges explicitly permitted because LAN
  remotes are the homelab's normal case and rebinding is defeated by the pin,
  not by an address filter; per-remote deadline; response cap; fan-out cap;
  CONNECT proxy under **explicit configuration only** (`http.ProxyFromEnvironment`
  is deliberately not used — a process's environment must not be able to
  redirect authenticated fleet traffic).
  - **`InsecureSkipVerify: true` is deliberate and is not a hole.** It disables
    WebPKI chain validation only, because the pin REPLACES the CA as the trust
    root — the ADR's two-trust-model split. `VerifyPeerCertificate` is
    mandatory and fails closed on an empty chain. A linter/reviewer will flag
    this line; the negative test
    (`TestPinAcceptsTheServersOwnKeyAndRefusesAnother`) is what proves it bites.
- **DONE — criterion 6's instrumentation.** `remotefetch.Dials()`, incremented
  in the transport's `DialContext` — the one place a connection is actually
  originated, so it cannot be bypassed by another call path.
  `TestDialsCountsOriginatedConnections` proves the counter is live, which is
  what stops "it did not move during workspace use" from being vacuous.
  `ponytail:` one process-wide counter, not per-remote byte accounting; it
  answers the one question the criterion asks.
- **DONE — the `ws` admission split, pinned.**
  `internal/isolation/workspace_session_test.go`. Seeds a REAL workspace
  session row (raw SQL — `authz.NewSession` has no origin/handoff fields yet)
  and asserts `AuthenticateCaller` resolves it while `Authenticate` refuses the
  same value. The seeded row is the point: against a missing row, "refused" and
  "does not exist" are indistinguishable and the assertion would pass against a
  broken split. Also asserts a CLI session still passes both, so the refusal is
  the artifact split firing rather than the surface being closed; and that the
  origin-bound sweep (`DELETE ... WHERE requesting_origin = ?`) kills it.
- **DONE — `CapInstanceDirector` added to `authz.MFAMandatory`.** The ADR's #16
  amendment restates "every instance capability is MFA-mandatory" as binding
  HUMAN SESSIONS, with the instance-connection principal as the single
  exemption — which needs no code, because `assuranceInadequate` already
  requires a non-empty `SessionID` and a machine has none. Adding it now costs
  the connection principal nothing (proven by the E2E test, which still passes)
  and stops `remote.list`/`remote.show` from landing later with no step-up gate
  for single-factor humans. `TestMFAMandatorySetMatchesTheADR` repinned to 6.

### Traps hit while building this — worth knowing before writing more queries

1. **sqlc/sqlite truncates statements when a query file's comments contain
   multibyte characters.** An em-dash in a comment produced
   `WHERE id = ? AND revoked_at IS NU` in the generated Go — a silent
   truncation that compiled fine and failed at runtime with
   `no such column: NU`. Query files must be **ASCII-only**. (Postgres' parser
   tolerates it, so this only bites one engine.)
2. **`RevokeInstanceConnection` must NOT null the verifier.** The first version
   did, and it contradicted the migration's own
   `CHECK (kind <> 'hikyo-token' OR verifier IS NOT NULL)`. Mirroring
   `machine_credentials` is correct: the row survives with its verifier so the
   audit trail's credential id keeps resolving, `Live()` already refuses a
   revoked row, and a 256-bit re-mint cannot collide.
3. **New proof-free writers must be added to `lint.ResolutionSurfaceWriters`**
   (`internal/lint/appendonly.go`) or `TestDenialWriterIsSoleWriter` fails.
4. **`Identity.Artifact` has THREE provenances, and two of them are traps.**
   Sessions carry the DATABASE string (`cli` / `browser` / **`workspace`**),
   `authenticateMachine` carries the CREDENTIAL KIND (`hikyo-token`), and
   `authenticateInstanceConnection` carries the bearer-grammar TYPE (`ic`)
   because #71 made it do so deliberately. Consequence for anyone extending the
   eligibility table: a row keyed on `crypto.ArtifactWorkspaceSession` (`"ws"`)
   **would never match**, because a workspace session's `Identity.Artifact` is
   `"workspace"`. This is the same inertness trap the `ic` row nearly fell into;
   the class key (`authz.confinedClasses`) is the defence, and it is why the
   confinement is keyed twice.

## Two forward collisions deliberately left in place

1. **`passthroughParams` in `api/noproxy_test.go` includes `"origin"`**, and the
   allowlist-removal endpoint will naturally want
   `DELETE /api/v1/workspace-origins/{origin}`. That failure is CORRECT and the
   fix is **not** to weaken the test: address allowlist rows by opaque id or by
   request body, never by a URL-shaped path parameter. A path parameter naming
   an origin is one review lapse away from a path parameter naming a target.
2. **RESOLVED IN SESSION 2 — see decision 12.** Disposed of as a KNOWING
   DEVIATION and recorded in `Resolver.RemoteOrigins`' doc comment, which
   carries the same reasoning for both reads. The original statement follows.

   **`instance_identity` is annotated `class=instance` but is read proof-free**
   by `Resolver.InstanceIdentity` on the resolution surface. Defensible —
   self-connection refusal and directory-serve are both authn-adjacent, and the
   value is neither tenant data nor secret — but it is inconsistent with the
   rule that instance-class tables ride the proof-gated repos. **Decide
   deliberately**: either re-annotate it `class=authn` with that reasoning, or
   record it as a knowing deviation. Do not leave it to be discovered by the
   adversarial review pass.

## Owner-ratified bounds (2026-08-13)

**The original gap was real and circular.** The #32 amendment header declares
that the composable-maxima catalogue gains the directory outbound client's
bounds and the workspace session's lifetimes — but the catalogue's table (rows
1-20) never gained the row, while multi-instance.md delegates the concrete
values *to* that catalogue. The two documents pointed at each other until the
owner ratified all nine bounds on 2026-08-13, with the workspace pair changed to
hard-short.

They remain pinned as named constants in **one place** —
`internal/remotefetch/bounds.go`. If a value moves, it moves there and nowhere
else.

| Bound | Value | Rhymes with |
|---|---|---|
| Per-remote deadline | 10 s | row 17, HTTP header/read timeout scale |
| Response size cap | 1 MiB | row 19, adapter response cap |
| Remote count cap | 50 | row 13, environment cap scale |
| Parallel fan-out cap | 4 | rows 17/19, 4-concurrent-per-org pattern |
| Coalescing window | 5 s | — (bounds the crowd; the per-viewer rate bounds one human) |
| Per-viewer trigger rate | 6/min | human card-refresh scale |
| Instance-wide aggregate rate | 60/min | row 17, fail-closed default budget |
| Workspace session idle / absolute | 15 min / 4 h | row 5 — reveal window/cap; a workspace is a disclosure surface |
| Handoff transaction expiry | 10 min | row 7, authorization-code analogue |

Two of these deserve a sentence in the ratified record:

- **The workspace lifetimes are HARD-SHORT, ratified by the owner on
  2026-08-13.** The header-borne bearer is extractable and replays outside the
  browser until expiry or revocation, so the pair deliberately reuses row 5's
  15-minute reveal window and 4-hour cap. The shell's current 5-second liveness
  poll keeps an open tab active; idle expiry therefore means 15 minutes after
  the tab closes.
- **The aggregate rate is the one that actually protects the fleet.** Per-viewer
  limiting alone does not bound many principals — fifty viewers each politely
  under their own limit is still fifty times the traffic at every remote.

The three session/handoff values remain colocated in `remotefetch` even though
they are not outbound-client concerns. That is on purpose: they are one ADR's
one catalogue addition, and splitting them across packages would make the
ratified set easy to drift.

**Where each constant gets consumed — read this before hunting for struct
fields.** Only three of the nine are `remotefetch.Config` fields (`Deadline`,
`ResponseCap`, `FanOut`), and `DefaultConfig()` already wires them. The other
six are **service-layer wiring and have no `Config` field, by design**:

| Constant | Consumer |
|---|---|
| `RemoteCount` | `remote add` — refuse the 51st entry |
| `CoalesceWindow` | the on-view fetch loop — `singleflight`, `golang.org/x/sync` is already in `go.mod` |
| `ViewerTriggerRate`, `AggregateTriggerRate` | the on-view fetch loop's two rate gates |
| `WorkspaceSessionIdle`, `WorkspaceSessionAbsolute` | workspace session issuance |
| `HandoffExpiry` | handoff transaction creation |

Six then-unreferenced constants could read as dead code. They were the directed
bounds table whose consumers are named resume items above; all are now wired and
owner-ratified.

### Verification at the END of session 2

```
go build ./...   # success
go vet ./...     # clean
gofmt -l .       # empty
go tool sqlc generate                                             # clean
go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml
(cd clients/ts && pnpm run generate && pnpm run typecheck && pnpm run test)  # 4 passed
(cd web && pnpm run typecheck && pnpm run test)                             # 20 passed

go test ./...                                        # 1178 passed, 35 packages
HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_71 \
  go test -count=1 ./...                             # BOTH ENGINES
```

`pnpm run e2e` (Playwright) is NOT run yet — there is no #71 flow to run.

### Verification at the end of session 1 (kept for the record)

```
go build ./...   # success
go vet ./...     # clean
gofmt -l .       # empty
go tool sqlc generate   # clean

HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_71 \
  go test -count=1 ./...
# 1620 passed, 35 packages -- BOTH ENGINES
```

The postgres leg is verified, including migration 00020 (the `sessions` rebuild
with its FK drop/restore on `reauth_windows`, and `gen_random_uuid()`).

Note: `resetPostgres` drop lists in `internal/conformance/conformance_test.go`
and `internal/isolation/harness_test.go` already teach the six 00020 tables.
**Any table a further migration adds must go into both lists** or the next PG
run fails with SQLSTATE 2BP01.

## Session 2 progress (store + service layers)

All of the below is `go build`/`go vet`/`gofmt` clean and green on the focused
packages; the FULL suite is NOT green yet — see "Known red" below.

- **DONE — the store blocker** (see 2b above).
- **DONE — session schema plumbing.** `InsertSession` on both engines gained
  `requesting_origin`/`handoff_id` (one insert for every artifact, because the
  table CHECK ties the pairing to the artifact and a second statement would be
  a second place for it to drift). `authn.NewSession` gained the two fields.
  New queries, both engines: `ListSessionsForPrincipal`,
  `DeleteSessionForPrincipal` (self-scoped, principal conjunct IN THE SQL),
  `DeleteSessionsForOrigin` (the atomic kill switch).
- **DONE — workspace queries**, both engines, in `remote.sql`:
  `ListWorkspaceOrigins`, `GetWorkspaceOrigin`, `InsertWorkspaceOrigin`,
  `DeleteWorkspaceOrigin`, `InsertWorkspaceHandoff`, `WorkspaceHandoffByState`,
  `WorkspaceHandoffByCode`, `ApproveWorkspaceHandoff`,
  `ConsumeWorkspaceHandoff`, `DeleteExpiredWorkspaceHandoffs`.
- **DONE — viewing-side queries**, both engines, same file, annotated
  `hikyo:instance-scoped` (NOT authn-resolution — these are class=instance and
  ride the proof-gated repos): `CreateRemote`, `ListRemotes`, `GetRemote`,
  `GetRemoteByName`, `SealedRemoteCredential`, `CountRemotes`, `RenameRemote`,
  `DeleteRemote`, `WriteRemoteSnapshot`, `RecordRemoteFetchFailure`,
  `ListRemoteSnapshots`, `GetRemoteSnapshot`.
- **DONE — resolver.** `internal/store/authn/workspace.go`: origins, handoffs,
  session listing and the two revokes. Types `WorkspaceOrigin`,
  `WorkspaceHandoff` (+`Live`), `NewWorkspaceHandoff`, `SessionSummary`,
  `HandoffPurpose` (closed two-member set).
- **DONE — `lint.ResolutionSurfaceWriters`** extended with the eight new
  proof-free writers.
- **DONE — proof-gated repo.** `internal/store/repos_remote.go`, both engines.
  `store.Remote`, `store.NewRemote`, `store.RemoteSnapshot`, `RemoteReader`,
  `RemoteRepo`, wired into `Repos`/`ReadRepos`. `SealedCredential` is on the
  READ side deliberately: the on-view fetch reads it in a read transaction,
  because a network fan-out must not hold the write connection.
- **DONE — 12 new StoreOps** (`remotes.*`), six in `readOnlyStoreOps`;
  `StoreRemotesSealed` deliberately NOT (that set licenses `audited: none`, and
  reading a stored credential is not something an unaudited operation may do).
- **DONE — 13 audit event types** in `internal/audit/registry.go` with full
  `TypeSpec` rows. NOTE two of them (`remote.credentials_listed`,
  `remote.origin_allowlist_read`) are **NOT in the ADR's § Audit enumeration**
  and are there because the AUDIT ADR forces them — instance-class reads cannot
  be `audited: none`. Same disposition #54 took for `auth.provider_read`.
  **Flagged for review.** `remote.auth_failed` and
  `remote.workspace_session_expired` stay deferred (no honest emitter; the
  existing registry comment covers both).
  Trap hit: a payload field named `outcome` is refused by
  `TestRegistryNoOutcomeShadow` — the fetch failure's field is `fetch_outcome`.
- **DONE — 14 operations registered** with formulas, storeOps and events;
  `operation_formulas.json` repinned (100 rows), `annotated_queries.json`
  repinned (358), the `remote.directory-serve` exemption REMOVED (it has a real
  emitter now).
- **DONE — the outbound client's fetch.** `internal/remotefetch/directory.go`:
  `Listing`/`OrgEntry`, `Client.Directory` (path is a CONSTANT, never from
  configuration), `Client.FetchAll` (semaphore at `FanOut`), ingest caps.
- **DONE — service layer, viewing side.** `internal/service/remotes.go`:
  `AddRemote` (three phases — authorize+cap+read state, fetch OUTSIDE the write
  transaction, commit with both identity checks re-run), `ListRemotes`,
  `ShowRemote`, `RenameRemote`, `RemoveRemote`, `RemoteOrigins` (the CSP input).
  Staleness is computed from the OUTCOME, not the age.
- **DONE — service layer, serving side.** `internal/service/workspace.go`:
  `Serve` (directory-serve), `MintConnection`/`List`/`Show`/`RevokeConnection`,
  `ListOrigins`/`AddOrigin`/`RemoveOrigin` (kill switch: delete + session sweep
  in ONE transaction), `OriginAllowed`, `CanonicalOrigin`, `StartHandoff`/
  `ApproveHandoff`/`RedeemHandoff` (PKCE S256, single-use atomic claim,
  uniform `ErrHandoffInvalid` with the cause on the trail only),
  `ListSessions`/`RevokeSession`.
- **DONE — TxAuthorizer passthroughs** for all of the above in
  `internal/authz/machine.go`, incl. `InstanceConnectionByPrincipal`.

### Decisions taken in session 2 (review these)

7. **The active-session listing and revoke get NO operation and NO capability.**
   They are self-scoped, so they take the shape `/api/v1/me/orgs` already takes:
   wire-classified `unauthenticated`, principal conjunct in the SQL. Requiring a
   grant to end one's own session would make incident response depend on an
   authority an attacker may have just removed.
8. **`Workspace.Version` is an injected field**, not `app.Version`: `app`
   imports `service`, and a display string is not worth an import cycle. The
   listing's version is display-only and never feeds a compatibility decision.
9. **`RemoveOrigin` emits ONE `remote.workspace_session_revoked`** for the whole
   sweep with an empty `session_id` and `cause=origin-removed`, not one per
   session: the rows are gone and their ids with them, and the count on the
   allowlist event is the fact an incident review acts on.
10. **Revoking a non-workspace session emits `auth.logout`**, not a #71 type —
   the trail already carries that fact and double-counting it would be worse
   than reusing the event.

### Session 2, second half — API, CORS/CSP, CLI, E2E (ALL GREEN)

- **DONE — fetch-loop bounds.** `internal/service/remotefetchgate.go` wires the
  last three owner-ratified constants: `CoalesceWindow` (in-flight dedup + a shared
  recent round), `ViewerTriggerRate`, `AggregateTriggerRate`. Exhausting a
  budget is **not an error** — it skips the round and serves snapshots MARKED
  STALE, because the bounds limit fetch TRIGGERS, not views, and failing the
  whole card would make a poll cadence slightly over budget look like an outage.
- **DONE — the outbound fetch itself.** `internal/remotefetch/directory.go`:
  `Directory` (path is a CONSTANT, never configuration), `FetchAll` (semaphore
  at `FanOut`), `Listing`/`OrgEntry`, ingest caps, `DisallowUnknownFields`.
- **DONE — OpenAPI, spec-first**, 16 paths, all in `pinnedRemoteSurface` with
  the per-entry confirmation the pin exists to take. `apigen` + the TS client
  regenerated; `clients/ts` typecheck + tests green on Node 24.
- **DONE — handlers** (`internal/server/remotes.go`), `API.Remotes` /
  `API.Workspace` seams, wired in `internal/app/app.go` with a real
  `remotefetch.Client` from `DefaultConfig()`.
- **DONE — CORS** (`internal/server/cors.go`): echoes exactly one allowlisted
  origin, non-credentials mode, `Vary: Origin`, and a non-allowlisted origin
  gets NO headers at all (its preflight still gets a 204, so "not allowlisted"
  and "no such path" are indistinguishable to script). Applied over the whole
  `/api/v1` group, which covers the handoff endpoints and the pre-auth meta
  read the version-skew check needs.
- **DONE — CSP** (`internal/server/spa.go`): `policyWithRemotes` extends
  `connect-src` with the configured origins, per response so an added remote
  needs no restart. Closed list, never `*`; malformed stored origins are
  DROPPED (a CSP directive is space-separated, so emitting one would be
  directive injection through a config row). Read errors answer the BASELINE —
  a hiccup tightens, never loosens.
- **DONE — wire registry**: 18 route classifications, 13 operation mappings,
  4 `wireEvents` entries, `cli:remote` + `cli:remote-credential`.
- **DONE — CLI** (`internal/cli/remotes.go`): `remote add|list|show|remove`
  (add is interactive: `FetchIdentity` -> fingerprint confirm on the TERMINAL
  -> credential read via `ReadPassword`, never argv), `remote-credential
  create|list|show|revoke` with the display-once print triad and preflight
  BEFORE the mint. NO `remote rename` (decision 5). `remove` prints the
  "this is not revocation" note every time. `cli.Verbs` extended, help golden
  regenerated.
- **DONE — E2E** (`internal/isolation/remote_e2e_test.go`): `runRemoteLifecycle`
  drives every #71 verb against a REAL `httptest.NewTLSServer` peer whose own
  SPKI fingerprint is the pin, so pin verification actually runs. Asserts the
  credential-rejected state is distinct from unreachable, that a consumed code
  is refused, and that the workspace session lists as its own artifact type and
  revokes. Runs on BOTH engines (`TestRemoteLifecycleSQLite|Postgres`) plus
  inside the audit suite's emitted-types sweep.
- **DONE — CORS/CSP unit checks** (`internal/server/cors_test.go`).
- **DONE — THE TWO-INSTANCE HARNESS** (`internal/isolation/two_instance_test.go`).
  Two datastores, two `service` stacks, two `httptest.NewTLSServer`s each
  running the REAL `server.New` router (middleware chain, CORS, strict handler).
  A adds B over a real pinned TLS connection to B's real router; the workspace
  arc (start/approve/redeem) is driven by an HTTP client that is NEITHER server;
  `remotefetch.Dials()` is asserted UNCHANGED across it — **criterion 6's
  harness half, met as a measurement rather than a claim.** Also covers
  criterion 1's self-connection and revocation legs and criterion 3's
  cross-instance kill switch (de-allowlist kills exactly the bound session, and
  a new handoff from the de-allowlisted origin gets 403 at the transaction).
  `TestZeroRemotesOriginateZeroConnections` is the air-gap statement as a
  measurement.

  **The harness immediately earned itself**: it caught that the served
  `DirectoryListing` carried `org_count`/`project_count` while
  `remotefetch.Listing` did not, so `DisallowUnknownFields` refused every real
  fetch. Fixed by putting the counts ON the wire type and having `boundListing`
  REFUSE a listing whose counts disagree with its own names — a peer that says
  "12 orgs" and sends 3 is broken or lying, and picking one number would be
  picking which lie to believe. `Listing.ProjectCount()` the method became
  `CountProjects()`; the field is `ProjectCount`.

  Trap: `server.API` with a nil `Auth` PANICS in `SlideSessionClocks` before any
  handler runs, and the symptom is an EOF at the TLS layer that looks nothing
  like a missing dependency (cost ~20 minutes).

- **DONE — error classification.** `ErrOriginNotAllowed` and `ErrHandoffInvalid`
  wrap `domain.ErrUnauthorized` (403, uniform); `ErrConnectionRevoked`,
  `ErrSelfConnected` and `ErrRemoteUnverified` wrap `domain.ErrConflict` (409);
  `ErrRemoteCap` wraps `domain.ErrLimitExceeded`. Without this a refused handoff
  answered 500, which reads as "we broke" rather than "you are refused".

### More traps hit (session 2)

5. **A payload field may not be named `outcome`** — `TestRegistryNoOutcomeShadow`
   refuses any payload key shadowing the envelope's Outcome. The fetch failure's
   field is `fetch_outcome`.
6. **`internal/service` may NOT import `internal/store/authn`.** The
   import-boundary allowlist admits only `authz` + a few store packages. Every
   resolution-surface carrier the service needs is re-exported as a type ALIAS
   in `internal/authz/machine.go`, and the transport gets service-owned shapes
   (`service.OriginView`, `service.HandoffPurpose`) — a transport that could
   name a store type could build one.
7. **`authService(t, db)` was not callable twice on one datastore** — a second
   `GenerateRootKey` fails with "root key does not match this datastore". It now
   memoizes per-`*store.DB` (`keyrings sync.Map`). Needed because
   `runRemoteLifecycle` runs beside the human-auth flow on the same db.
8. **A new OpenAPI enum can RENAME existing generated constants.** An inline
   `enum: [finite, indefinite]` made oapi-codegen prefix the pre-existing bare
   `Indefinite` into `CredentialLifetimeIndefinite`, breaking `internal/cli`.
   Reuse the existing `$ref` schemas (`CredentialLifetime`, `CredentialKind`)
   instead of restating enums inline.
9. **A schema name collision is a YAML parse error, not a codegen error.**
   `Session` already existed; the active-session row is `ActiveSession`.
10. **`commonFlags.positionals` is the field**, not `flags.Flags.Args()`.

### Decisions taken in session 2's second half (review these)

11. **The rate budget degrades to snapshots, it does not error.** See above.
12. **`RemoteOrigins` is PROOF-FREE** (`Resolver.RemoteOrigins`), because its
    only consumer is the CSP header on the pre-authentication document
    response, where no caller exists to authorize — and the value is one the
    response then publishes to every browser anyway. **This is the same knowing
    deviation as forward collision 2** (`instance_identity`, a class=instance
    table read proof-free); both are now recorded in the resolver's doc comment
    as one disposition rather than two discoveries.
13. **Redeeming a `step-up` handoff is REFUSED**, by name
    (`cause=step-up-not-redeemable`). A step-up elevates the session it bound;
    minting a second full-lifetime bearer per elevation is the opposite of an
    elevation. The elevation path itself is the open item below.
14. **Handoff failures ride `az.CaptureAudit`, not `RecordAuthEvent`.** Every
    failure path returns an error that ROLLS THE TRANSACTION BACK; an
    in-transaction insert would vanish exactly when it matters. Same reason the
    reveal gates use that path.
15. **`GET /api/v1/me/sessions` is audit-exempt** (whoami-class self read);
    the `DELETE` beside it is not, and carries its events through `wireEvents`.
16. **The directory listing carries `org_count`/`project_count` ON THE WIRE**,
    and `boundListing` REFUSES a listing whose counts disagree with its own
    names. The counts are a convenience for a client that does not want to walk
    the tree; the names remain the source of truth, and a peer that disagrees
    with itself is refused rather than half-believed. The serving side derives
    both from the names it is about to send, in one place.
17. **`remotefetch.Listing.ProjectCount` is now a FIELD**; the method that
    computed it is `CountProjects()`. Named apart on purpose — the two are
    different things (what the peer SAID, and what it SENT).

### NEEDS MARC — the workspace session's assurance record

`RedeemHandoff` mints the workspace session with `Factors: "[]"` and
`AuthMethod: "workspace-handoff"`, i.e. **permanently single-factor**. The ADR
requires the workspace session to match the locked session model "in every
locked mechanical respect", and the assurance record is named in that list — so
this is a real gap, not a simplification.

The correct fix and why it was not taken now: the factors belong to the session
that APPROVED the handoff, and `workspace_handoffs` has no column to carry them
from approval to redemption. Closing it is **migration 00021** (`factors TEXT`
on `workspace_handoffs`, written by `ApproveWorkspaceHandoff`, read by
`RedeemHandoff`) plus both PG reset drop lists. That is a schema change on a
branch that may be renumbered against parallel ticket sessions, so it is
surfaced here rather than taken unilaterally.

Consequence today: a workspace session is refused by every MFA-mandatory
operation (`assuranceInadequate` requires multi-factor and a non-empty
SessionID, and a workspace session has both a SessionID and no factors). That is
the SAFE direction — it cannot reach instance capabilities — but it also means
criterion 3's "reveal under B's ceremony" cannot complete on a
reauth-gated environment until this and decision 13 are closed together.

## STILL NOT DONE — resume here

**Everything in the numbered list at the bottom of this section is DONE except
item 9 (web UI + Playwright) and the PLAYWRIGHT LEG of item 10** — item 10's Go
half, the two-instance harness, landed and is green. The list is kept verbatim
as the original plan; read the two "Session 2" sections above for what actually
landed and how.

**One scoping note, stated so it is not read as an oversight:** the two-instance
harness runs two instances IN ONE PROCESS — two datastores, two routers, two TLS
servers, real pins, real cross-instance fetches. It is sqlite-only by
construction (`newInstance` builds its own `store.Config` with
`EngineSQLite`), because what it proves is transport and architecture, not
engine behaviour — the engine legs are covered by `TestRemoteLifecyclePostgres`
and the rest of the isolation suite. Two OS processes would prove nothing
further about the dial counter (which is process-wide, and would in fact become
UNOBSERVABLE across a process boundary) but would prove the binary boots; that
is `internal/app`'s job and it is already tested. **Flagged for Marc's
disposition** rather than presented as equivalent.

What remains, in order:

**A. Web UI + Playwright flows (M6 gate items, not polish) — THE ONLY
   SUBSTANTIAL WORK LEFT.**

   **Read this before touching `web/` — it is why the UI was NOT started
   half-way.** `web/src/app/navigation.ts` holds `SURFACES`, and
   `web/e2e/registry.ts` closes over it: adding a surface WITHOUT a Playwright
   flow that actually RUNS its pinned assertions fails the build, in both
   directions (a surface with no flow, and a flow naming a surface that does not
   exist). So the UI is atomic — surface + route + flow land together or the
   tree is red. Starting it with 20% of a context left would have left exactly
   that. The Go side is a clean, fully green boundary; take the UI as one unit.

   Concretely:
   - Two new surfaces in `SURFACES`: `remotes` (`/remotes`, section
     "Organisation") and `sessions` (`/settings/sessions` or a panel on
     `settings` — a panel avoids a third surface and a third flow, and the kill
     switch is a settings concern, so prefer the panel).
   - Directory card: reachability, version, org/project names + counts, the
     "unreachable Xh — last known" staleness sentence, and "credential
     rejected" as its own LOUD state. The API already returns everything:
     `state` (7-member enum), `stale`, `stale_for_seconds`, `orgs`,
     `org_count`, `project_count`, `identity`, `version`.
   - Polling is `refetchInterval` on the react-query already in `web/` — NOT
     EventSource. Native EventSource cannot set an Authorization header, which
     is exactly why the ADR puts the workspace tier on polling; do not "fix"
     that by weakening SSE authentication.
   - Workspace popup ceremony: `window.open(..., "noopener")` at the remote's
     origin, a SAME-ORIGIN callback page on the viewing UI, and a nonce-named
     `BroadcastChannel` to hand code+state back to the shell. The shell then
     POSTs `/api/v1/auth/workspace/redeem` CROSS-ORIGIN to the remote. The
     bearer lives in JS MEMORY ONLY — never a cookie, never localStorage or
     sessionStorage.
   - Version skew: read the remote's `/api/v1/meta` LIVE and cross-origin before
     establishing or resuming. The directory's cached `version` is DISPLAY-ONLY
     and must never feed the decision. CORS already permits this for an
     allowlisted origin.
   - Kill switch: `GET /api/v1/me/sessions` shows the workspace session as its
     own artifact type with its `requesting_origin`; `DELETE
     /api/v1/me/sessions/{session}` revokes it.
   - TS standards: no `as` casts, no `z.any`, JSON.parse through Zod. The
     generated client already ships Zod schemas
     (`clients/ts/src/generated/zod.gen.ts`) — use them, do not hand-write
     shapes.
   - Checks: `cd web && eval "$(fnm env)" && fnm use 24 && pnpm run typecheck &&
     pnpm run test && pnpm run e2e`.

**B. Two-instance E2E harness — DONE** (see above). What is left of it is only
   the PLAYWRIGHT leg, and its one undecided question, which shapes the UI code:
   whether the browser leg allowlists `http://localhost:PORT` or runs TLS with
   `ignoreHTTPSErrors`. **The Go harness has already answered half of it:**
   `service.CanonicalOrigin` deliberately accepts `http` (so a loopback origin
   is representable as an allowlist entry) while `remotefetch.ValidateRemoteURL`
   refuses plaintext (so a REMOTE URL cannot be). The ADR mandates https for
   remote URLs, not for allowlist entries, and that asymmetry is now load-bearing
   in code. The lazy Playwright leg is therefore `http://localhost:PORT` for the
   VIEWING origin with a TLS serving instance — but record the decision either
   way rather than letting it fall out.

**B2. One known wart, deliberately left rather than fixed at the end of a
   context.** `API.AddWorkspaceOrigin` calls `AddOrigin` and then `ListOrigins`
   to build its 201 body, which authorizes twice and emits a spurious
   `remote.origin_allowlist_read` per add. It is honest (the handler really did
   read the list) but wasteful. The fix is one signature change —
   `Workspace.AddOrigin` returns the `OriginView` it just wrote — and it was not
   taken here because it would have invalidated a both-engine verification run
   already in flight. ~15 lines; take it first next session.

**C. The two gaps that need Marc** (see "NEEDS MARC" above and decision 13):
   the workspace session's assurance record (migration 00021) and the step-up
   elevation path. Criterion 3 cannot fully close without them.

Original plan, kept for its reasoning. Status against the six locked criteria, AS OF THE END OF SESSION 2:

| # | State |
|---|---|
| 1 | **MET.** Proven twice: `remote_e2e_test.go` on BOTH engines against a real pinned TLS peer, and `two_instance_test.go` across two real instances with two datastores and two routers — add with the full ceremony, stop/reject the peer -> last-known + age, revoke on B -> credential-rejected as its own loud state on A, and self-connect refused BY INSTANCE IDENTITY at the authenticated fetch. The remaining gap is presentational: no UI shows it yet. |
| 2 | **Met at the service+API level.** The directory read is `instance-directory`-gated and returns names+counts only; the workspace popup lands on B's own login BY CONSTRUCTION — there is no code path by which A's server authenticates to B, and `two_instance_test.go` asserts A's server originates nothing during the workspace arc. Needs the UI to be observable. |
| 3 | **PARTLY MET, two named blockers.** Built and E2E-tested across two instances: handoff transaction (single-use, PKCE S256, origin-bound), workspace session issuance, CORS, CSP, and the atomic origin-removal kill switch (de-allowlisting killed exactly the bound session, and a new handoff then got 403 AT THE TRANSACTION). **NOT met:** (a) the UI popup ceremony; (b) "reveal under B's ceremony" — blocked on the step-up elevation path (decision 13) and the workspace session's assurance record (NEEDS MARC / migration 00021). Both are named, neither is hidden. |
| 4 | **MET.** Unchanged, and now additionally exercised by a real serve through the chokepoint in the lifecycle test. |
| 5 | **Met at the service+API level, both engines.** `GET/DELETE /api/v1/me/sessions`; a workspace session lists as its own artifact type carrying its requesting origin; revoke bites at the next request because the row is re-resolved in its own transaction. Needs the UI to be observable. |
| 6 | **MET, with one scoping caveat stated plainly.** CI half: no-proxy closure over 16 pinned paths, each with a written confirmation of what it returns, plus the wire-registry half and the live dial instrumentation. Harness half: `two_instance_test.go` asserts `remotefetch.Dials()` is UNCHANGED across a full workspace arc driven by a client that is neither server, and `TestZeroRemotesOriginateZeroConnections` measures the air-gap statement. **Caveat:** two instances in ONE PROCESS (two datastores, two routers, two TLS servers, real pins), not two OS processes — see the scoping note above for why that is the stronger test for this criterion, and for Marc's disposition. |

**Trap for the resumer, stated because it silently defeats criterion 4:**
`Identity.Artifact` has mixed provenance — sessions carry the DB artifact string
(`cli`/`browser`/`workspace`, NOT `br`/`ws`), while `authenticateMachine` sets
`Artifact: string(cred.Kind)` = `"hikyo-token"` (`machine.go:102`). A resolver
written by copying the machine leg verbatim would set the `ic` leg's Artifact to
`"hikyo-token"`, the artifact table would never match, and the confinement would
go inert while every test of the table stayed green. Two guards against that:
the `ic` leg **MUST** set `Identity.Artifact = string(crypto.ArtifactInstanceConn)`,
and the confinement is additionally keyed on `Identity.Class`
(`authz.confinedClasses`), which the Identity contract requires to be set on
every resolution path. `authz.Eligible(caller, op)` checks both; the chokepoint
calls that, not `ArtifactEligible` alone.

1. **Viewing-side store layer.** `remotes` + `remote_snapshots` queries (the
   tables exist; only `instance_connections`/`instance_identity` have queries so
   far) and their repo methods. These are `class=instance`, so unlike the
   connection tables they ride the **proof-gated repos**, not the resolution
   surface — they need `StoreOp` constants in `authz/registry.go` and entries in
   the operations' `storeOps` sets, which the connection queries did not.
1b. **Operations still to register** (the pattern is now established by
   `OpRemoteDirectoryServe` — const + opSpec + `operation_formulas.json` repin):
   `remote.add|list|show|rename|remove`,
   `remote-credential.create|list|show|revoke`,
   `workspace-origin.list|add|remove`. All instance-class; `instance-config`
   for mutations and custody, `instance-directory` for the directory reads.
   **Instance-class READS cannot use `audited: none`** — the audit ADR's
   default-deny refuses it — so each read needs its own event, following the
   `auth.provider_read` precedent #54 set for exactly this reason.

2. **Audit events.** `remote.*` per ADR § Audit. Each needs a const + `TypeSpec`
   **and a live emitter** — `remote.directory_served` is already reasoned about
   in `internal/audit/registry.go` and pinned in `audited_exemptions.json`;
   remove that exemption when its emitter lands. `workspace_session_expired`
   stays deferred (decision 4).
2b. **BLOCKER RESOLVED (DONE, both engines verified).** `ListAllProjects`
   (`-- hikyo:instance-scoped`, `SELECT org_id, name FROM projects ORDER BY
   org_id, name`) on both engines, `authz.StoreProjectsListAll` in
   `readOnlyStoreOps` and in `OpRemoteDirectoryServe.storeOps` beside
   `StoreOrgsList`, `store.ProjectReader.ListAll` returning the new
   `store.ProjectName` (org id + name only — a full `Project` would hand the
   directory an id and a creation time it has no licence to publish),
   implemented on `sqliteProjects` and `pgProjects`. `annotated_queries.json`
   repinned to 308. Counts are `len()` in the service layer: a separate COUNT
   query is a second read of the same fact that can disagree with the names
   beside it. Verified: `HIKYO_TEST_POSTGRES_DSN=... go test -count=1
   ./internal/store/... ./internal/lint/... ./internal/authz/...
   ./internal/isolation/... ./internal/conformance/...` -> 1062 passed.
   Original statement of the blocker, kept for the reasoning:

2b-orig. **the directory listing had no store path.**
   `remote.directory-serve` must return "the names and counts of orgs and
   projects" across **every** org: the ADR calls it "an instance-scope read
   crossing org boundaries by design". But `store.ProjectReader.List` returns
   "every project in the org **the proof addresses**", and an `InstanceProof`
   addresses no org — so there is currently no way to read all projects under
   one instance-scope proof. `OrgReader.List` is fine (it already serves the
   instance-class `org.list`).

   Resolution (not yet built): add ONE instance-scoped query returning
   `(org_id, name)` for all projects, plus a `StoreProjectsListAll` StoreOp and
   a reader method. Do **not** loop per-org minting a tenant proof per
   iteration — that is N proofs for one operation and would misreport the
   operation in the boundary check. Note this widens `ProjectReader`, so both
   engines' implementations change.

3. **Service layer.** Directory (`remote add/list/show/rename/remove` +
   the on-view fetch loop wiring `internal/remotefetch`), credentials
   (`remote-credential create/list/show/revoke` — mint principal + credential +
   grant in ONE transaction, display-once via `internal/disclose`), workspace
   (handoff transaction, session issuance, origin allowlist, atomic
   origin-removal revocation — one statement over `sessions.requesting_origin`).
4. **Self-connection + duplicate-identity refusal**, at the authenticated
   fetch, using `Resolver.InstanceIdentity`. Outcomes already enumerated in
   `remotefetch.Outcome`.
5. **OpenAPI (spec-first) + handlers.** Regen `apigen` and the TS client; keep
   the freeze/oasdiff gates green. **Every new remote path must also be added
   to `pinnedRemoteSurface` in `api/noproxy_test.go`** — that failure is the
   designed review moment, not an obstacle to route around.
6. **CORS + CSP.** Serving side: echo exactly one allowlisted origin,
   non-credentials mode, on `/api/v1`, the handoff endpoints and the pre-auth
   meta endpoint. Viewing side: extend `connect-src` at
   `internal/server/spa.go:42` with the configured remotes' origins.
7. **Active-session listing + revoke** (`GET`/`DELETE /api/v1/me/sessions`).
   None exists in the repo — criterion 5 needs it. Self-scoped, so
   `ClassUnauthenticated` like `/api/v1/me/orgs` (enumeration uniformity, not
   tenancy).
8. **CLI** `remote add` with interactive pin-confirm; `remote-credential`
   family. No CLI `rename` (decision 5).
9. **Web UI + Playwright flows** — the M6 gate names the popup ceremony and the
   kill switch explicitly; they are gate items, not polish. Polling is
   `refetchInterval` on the react-query already in `web/`.
10. **Two-instance E2E harness** (none exists — checked). Go legs: two
    in-process apps, separate DBs, `httptest.NewTLSServer`, pin = the test
    cert's SPKI (`remotefetch.SPKIFingerprint`). Assert
    `remotefetch.Dials()` does not move across a workspace flow — criterion 6's
    harness half. **Undecided and shapes the code: whether the Playwright leg
    allowlists `http://localhost:PORT` or runs TLS with `ignoreHTTPSErrors`.
    The ADR mandates https for remote URLs, not for allowlist entries — decide
    deliberately and surface it rather than letting it fall out.**

---

# Session 3 (final implementation session) — web UI, flows, and the two named gaps

Status at the end of this session: **the Go side is complete and green on BOTH
engines; the web UI and the Playwright two-instance harness are built and the
M6 [UI] deliverable (popup ceremony + kill switch) PASSES end to end.** One
flake remains in the full Playwright run and is characterised below.

## What landed

### 1. The `AddWorkspaceOrigin` wart (item B2) — FIXED
`Workspace.AddOrigin` now returns the `OriginView` it wrote, so the handler
builds its 201 body from it. No second authorization, no spurious
`remote.origin_allowlist_read` per add. `canonicalOrEmpty` deleted with it.

### 2. The workspace session's assurance record — CLOSED (migration 00021)
`internal/store/migrations/{sqlite,postgres}/00021_workspace_assurance.sql`:
`ALTER TABLE workspace_handoffs ADD COLUMN factors TEXT NOT NULL DEFAULT '[]'`.
No new table, so no `hikyo:table` directive and no PG reset drop-list change.

- Written at **approve** from `caller.Assurance.Factors` (the ceremony the human
  actually performed, in the popup, on this instance's origin), read at
  **redeem** into `MintSession`. The column exists because approval and
  redemption are two requests minutes apart and the approving session may be
  gone by then — the transaction row is the only honest carrier.
- `ApproveWorkspaceHandoff` gained a `factors` parameter through the resolver
  and the `TxAuthorizer` passthrough. `annotated_queries.json` repinned (358).
- **Query column ORDER matters**: `factors` is selected LAST in
  `WorkspaceHandoffByState|ByCode` so sqlc's row struct stays convertible to the
  table model (`sqlitegen.WorkspaceHandoff(row)`). Put it anywhere else and the
  resolver stops compiling.

### 3. The step-up elevation path — BUILT (decision 13 superseded)
`Workspace.elevate` (`internal/service/workspace.go`). A redeemed **step-up**
now elevates the workspace session it bound instead of being refused by name:

- Opens a sliding reauthentication window over `(bound session, bound
  environment)` through the human-auth service's own seam (`Workspace.Reauth
  *Auth`, wired in `internal/app/app.go`), so a lowered environment is honoured
  here exactly as it is for TOTP/OIDC/WebAuthn. Fails closed at a 0 window.
- **Never single-decision**: `ConsumeReauthWindow` resolves a single-decision
  window back to a WebAuthn ceremony row for byte-exact unit matching, and a
  handoff transaction is not one.
- **Rotates the bound session's bearer** (`RotateSessionFactors`) and writes the
  approving ceremony's factors onto it. Same session id, same clocks, same
  origin binding — one session, new value. Rotation is deliberate: a bearer
  stolen before an elevation must not become an elevated bearer after it. The
  redemption response carries the new value (`elevated`, `environment`,
  `window_expires_at`, all additive and optional in the contract).
- **The security check that is easy to miss**: `StartHandoff` is
  pre-authentication, so anyone may open a step-up naming any session id. The
  bound session is therefore resolved WITHIN THE APPROVING PRINCIPAL'S OWN
  SESSIONS (`SessionsForPrincipal(h.PrincipalID)`). Without that, a stolen
  workspace bearer could be elevated with the thief's factors.
- Refusals, all uniform `ErrHandoffInvalid` with the cause on the trail only:
  `step-up-not-environment-scoped`, `step-up-assurance-unreadable`,
  `step-up-assurance-inadequate` (a password-only popup demonstrates nothing),
  `step-up-session-unknown`, `step-up-not-a-workspace-session`,
  `step-up-origin-mismatch`, `step-up-session-expired`, `step-up-window-closed`.
- Audit: the elevation emits `auth.reauthenticated`, added to the redeem route's
  `wireEvents`.
- Tests: `internal/isolation/workspace_stepup_test.go`, both engines, plus
  `TestElevationHonoursTheEnvironmentsOwnWindow`.

### 4. A latent #54 defect fixed at the root
`InsertReauthWindow` was a plain INSERT against a table with
`UNIQUE (session_id, environment_id)`, so the **second** ceremony over one
(session, environment) — a window that lapsed and was re-earned, or a repeated
workspace step-up — answered a fault instead of re-arming the window. Now an
UPSERT on both engines: the newer ceremony's clocks, factor class and epoch
replace the older ones and `consumed_at` is cleared. This fixes all four
openers (TOTP, OIDC, WebAuthn, workspace), not just the new one.

### 5. A real CORS/routing bug the flow found
**A preflight must MATCH a route or chi never runs the group's middleware.** The
contract declares no OPTIONS operations (correctly), so `OPTIONS
/api/v1/auth/workspace/start` fell through to the router's not-found handler,
which knows nothing about CORS and answered with no headers — the browser
reports that as a missing `Access-Control-Allow-Origin`, which reads like an
allowlist problem and is not. Every cross-origin **POST** of the workspace tier
was unreachable while the GETs worked. Fixed with a catch-all OPTIONS route
inside the API group (`internal/server/server.go`); `workspaceCORS` still
answers the preflight itself.

### 6. Web UI
Three new surfaces in `web/src/app/navigation.ts` (the flow registry closes over
it, so surface + route + flow landed together):

| Surface | Path | Section |
|---|---|---|
| `remotes` | `/remotes` | Organisation |
| `workspace-approve` | `/workspace/approve` | null (chromeless) |
| `workspace-callback` | `/workspace/callback` | null (chromeless) |

- `CHROMELESS` is DERIVED from `section === null`; `App.tsx` routes those
  outside the shell and — this is the non-obvious part — serves
  `workspace-approve` in the SIGNED-OUT branch too. A first establishment lands
  in a popup with no cookies for the serving instance, and bouncing it to
  `/login` would throw away the `state` the transaction is addressed by. The
  approve page renders `<Login/>` itself instead and the URL survives.
- `web/src/routes/Remotes.tsx` — directory cards (state sentence per the
  7-member enum, `credential-rejected` as its own loud state, "showing the last
  known directory, N old", identity/version/org+project names and counts),
  add/rename/remove, the workspace launcher, and the serving side's origin
  allowlist with `sessions_revoked` reported out loud.
- `web/src/routes/Sessions.tsx` — the settings panel: every artifact holding the
  account, workspace sessions as their own artifact type carrying their
  requesting origin, with revoke.
- `web/src/api/remotes.ts` — same-origin react-query hooks over the generated
  client, `refetchInterval` polling (NOT EventSource).
- `web/src/api/workspace.ts` — the cross-origin half. Never goes through
  `api/client.ts`: `credentials: 'omit'`, `mode: 'cors'`, generated Zod schemas
  on every response, live `/api/v1/meta` skew check before establishing, PKCE
  S256, nonce-named `BroadcastChannel` (`hikyo.workspace.<state>`), bearer in a
  module-level Map and nowhere else.

**Two UI decisions worth review:**

1. **The ceremony is TWO clicks and the platform forces it.** `window.open`
   only survives the popup blocker inside the task of a real user gesture, and
   the handoff transaction cannot be opened without a network round trip first.
   So click one prepares (`prepareWorkspace`: live meta read + transaction) and
   click two opens (`openPrepared`, whose first statement is the `window.open`).
   It buys something worth having anyway: the human reads which origin they are
   about to be sent to before a window appears.
2. **A liveness poll, and it is how both kill switches become visible.**
   `probeWorkspace` GETs the remote's `/api/v1/me/sessions` with the bearer
   every 5s. A 401/403 drops it. An OPAQUE failure counts a strike and two
   consecutive strikes drop it — because de-allowlisting withdraws the CORS
   headers with the consent, so "consent withdrawn" and "host down" are
   indistinguishable from script, and a card claiming an unusable workspace is
   open is the one thing it must not do.

### 7. Playwright: the two-instance harness
`web/e2e/fixtures/instance.ts` now starts **two** real instances and
`web/e2e/flows/workspace.spec.ts` drives the whole arc.

**DECISION (the one left open): the browser leg is loopback HTTP.**
`service.CanonicalOrigin` accepts http so a loopback ORIGIN is representable as
an allowlist entry, while `remotefetch.ValidateRemoteURL` refuses plaintext so a
REMOTE URL never is. What the browser leg proves — popup on the remote's origin,
CORS, `noopener` + BroadcastChannel, header-borne bearer, both kill switches —
is origin-shaped, not pin-shaped, so http exercises it honestly and NO
certificate exception is needed anywhere (no `ignoreHTTPSErrors`, no SPKI launch
flag). The pinned TLS half is proven where it belongs, in
`internal/isolation/two_instance_test.go`, against two real routers over real
TLS.

**Two hosts, not two ports.** A is `http://127.0.0.1:45789`, B is
`http://localhost:45790`. Cookies are NOT partitioned by port: one hostname
would mean one cookie jar and B's login would silently destroy A's session.

**Two store-level seams, both documented in the fixture:**
- `repointRemoteAtB` — the entry is CREATED through the real API against a
  pinned TLS front that proxies B's own directory (so the credential is really
  sealed and the snapshot is really B's), then its URL is repointed at B's
  loopback http origin. An entry can only be created over https, correctly.
  The card then renders the `unreachable — last known` state honestly.
- `seedDirectoryGrant` — `instance-directory` is deliberately not in the
  operator set, and granting it through the API is a three-ceremony detour
  (MFA-mandatory surface; granting to oneself invalidates one's own sessions),
  at one 30-second TOTP step boundary per ceremony. The grant surface is #55's
  to prove. Written before the first sign-in so it cannot invalidate a session.

### Traps hit in session 3 (all cost real time)

11. **Every instance-scope surface is MFA-mandatory**, so the flow suite's
    bootstrap administrator cannot open the remotes page at all with a password.
    The fixture enrols a REAL TOTP factor and steps up
    (`web/e2e/fixtures/totp.ts`).
12. **A TOTP code is single-use PER STEP** (`last_step < ?`, strictly) and the
    validation window is only ±1 step wide, so two ceremonies inside the same 30
    seconds have no code that is both fresh and acceptable. The refusal is
    `unauthenticated`, indistinguishable from a wrong code, and it reads exactly
    like a clock skew that is not there (the server's `Date` header agrees with
    Node to the second, and both implementations generate identical codes for
    identical instants — checked against `pquerna/otp` directly). `presentTotp`
    walks steps 0..+2 and waits for a boundary between rounds.
13. **A killed flow run leaves a server holding the port**, and the next run's
    health probe cannot tell it from its own — the bootstrap then writes to a
    datastore nobody is serving and the first authenticated call answers 401,
    which reads like a credential bug. There is now a `portTaken` guard that
    fails loud, and `stopInstance` uses SIGKILL.
14. **`getByLabel('Origin')` matches the `aria-labelledby` REGION too.** Use
    `getByRole('textbox', { name: 'Origin' })`.

## Verification

```
gofmt -l .        # empty
go vet ./...      # clean
go build ./...    # success
go test ./...     # 1183 passed, 35 packages (sqlite)
HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_71d \
  go test -count=1 ./...   # 1702 passed, BOTH ENGINES
go tool sqlc generate                                              # clean
go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml  # clean
(cd clients/ts && pnpm run generate && pnpm run typecheck && pnpm run test)  # 4 passed
(cd web && pnpm run typecheck && pnpm run test)                     # 20 passed
(cd web && pnpm run e2e --project=mobile)                           # 26 passed
(cd web && pnpm run e2e --project=desktop --grep "kill switches")   # PASSES
```

Note: the PG database was recreated as `hikyo_71d` for migration 00021.

## The full-run crash, found and fixed

`pnpm run e2e` with both projects first failed with `net::ERR_CONNECTION_REFUSED`
against the viewing instance partway through the second project, while each
project passed on its own. The cause was the first shape of the preflight fix: a
catch-all `OPTIONS /api/v1/*` route registered INSIDE the API group. It also
tripped three CI invariants at once — classification totality, audit
completeness and contract/router agreement — all of which were telling the truth:
a route that the contract does not describe has no business existing.

The correct shape is not a route at all. `workspaceCORS` moved to the TOP of the
router's middleware chain (`r.Use`), where it runs on every request whether or
not one matches, and answers the preflight itself. No new route, no contract
entry, no invariant exemptions.

**Honesty note on the causal claim**: the route was removed and the full suite
went green TWICE in a row (52 passed both times), where it had failed with the
route. That is correlation plus a mechanism that is plausible but not proven —
a handler returning 204 has no obvious way to end a process. If
`ERR_CONNECTION_REFUSED` ever returns mid-suite, do not assume this was the
cause: read the instance's stderr for a panic first.

## Status against the six locked criteria

| # | State |
|---|---|
| 1 | **MET**, and now visible: the directory card renders state, identity, version, org/project names and counts, the `credential-rejected` loud state and the "showing the last known directory, N old" sentence, asserted by a Playwright flow against a real second instance. |
| 2 | **MET.** The popup lands on B's own origin — asserted by comparing the popup's origin against B's in the flow — and A's server originates nothing during the arc (`two_instance_test.go` measures `remotefetch.Dials()` across it). |
| 3 | **MET at every layer this ticket owns, with one caveat stated inline.** The handoff transaction, the popup ceremony, the workspace session, CORS, CSP and the atomic origin-removal kill switch are exercised end to end in a browser; the assurance record now travels (00021) and a step-up ELEVATES the bound session under a real reauthentication window instead of being refused by name, proven on BOTH engines in `workspace_stepup_test.go`. **Caveat: the elevation has no UI consumer yet** — the reveal surface that would call it is #50/#58's ticket, so "reveals under B's ceremony" is proven at the service layer and not in the browser. |
| 4 | **MET.** Unchanged. |
| 5 | **MET**, and now visible: the settings panel lists a workspace session as its own artifact type carrying its requesting origin, and revoking it there ends the workspace in the other instance's shell within one liveness poll — asserted in the flow. |
| 6 | **MET.** CI half (no-proxy closure over the pinned surface + the wire-registry half + live dial instrumentation) and harness half (`two_instance_test.go`) unchanged. The browser leg adds a third observation: the workspace ceremony completes while the viewing server cannot reach the serving one at all. |

## Left for the reviewer, not hidden

1. The two Playwright store-level seams (`repointRemoteAtB`, `seedDirectoryGrant`),
   both documented at their call sites with the reason.
2. The `InsertReauthWindow` upsert touches #54's locked machinery. It fixes a
   real latent fault for all four openers; it is worth a reviewer's eye.
3. The elevation ROTATES the workspace bearer. That is the same act the human
   step-up performs, and the redemption response carries the new value — but it
   means a shell that ignores the response loses its session.
4. `remote.workspace_session_expired` and `remote.auth_failed` remain
   unregistered for the reasons already recorded (no honest emitter).

# Review round 1 fixes

Ten findings from the standards/spec review, all fixed in this tree, none
deferred. Two behavioural ones were driven test-first (both confirmed red
before the fix, green after).

## The two real defects

1. **The coalescing cache was scope-blind and fabricated failures.**
   `remote show X` cached a ONE-ENTRY round; a `remote list` arriving inside
   `CoalesceWindow` inherited it, and `settle` marked every entry absent from
   that round `unreachable` — persisting a fetch-failure snapshot and a
   `remote.fetch_failed` audit event for remotes nobody had contacted.
   - Root fix, `internal/service/remotefetchgate.go`: `coalesce(now, want)`
     hands a cached round back **only if the round fetched every requested
     remote** — its keys are its scope. A narrower round REPLACES a wider one
     rather than merging, because merging would serve an older fetch's result as
     if this round had produced it. `covers()` is the test; `shared()` is gone.
   - `internal/service/remotes.go` `fetchRound` is now a loop: a viewer that
     waits on an in-flight round **re-enters** rather than taking its results on
     trust, because the round it waited for may have been a narrower one. The
     fan-out moved to `runRound` so the claim's release is not deferred inside
     the loop.
   - `settle` no longer has a `!got → OutcomeUnreachable` branch at all. A
     missing entry now takes the same path as an exhausted trigger budget:
     serve the snapshot AS a snapshot, write nothing, audit nothing. With the
     gate fixed it is unreachable — but the fabrication path must not survive as
     a fallback.
   - Test: `TestRemoteCoalescingIsScoped{SQLite,Postgres}` in
     `internal/isolation/remote_e2e_test.go` pins the exact sequence (two peers,
     `ShowRemote(peer-a)`, then `ListRemotes` inside the window) and asserts
     peer-b comes back `ok` with its real identity and that zero
     `remote.fetch_failed` rows exist.

2. **`forgetWorkspace` never cleared the strike count**
   (`web/src/api/workspace.ts`). A re-established workspace inherited the old
   count and died on its FIRST blip instead of its second. One
   `failures.delete(origin)`; test in `web/src/api/workspace.test.ts` drives
   three consecutive unreachable probes and asserts the third survives.

## Spec conformance

3. **`remote add` now reads the pre-auth meta endpoint BEFORE the credential
   paste** (`internal/cli/remotes.go` `addRemote`), which is the ADR's order:
   fingerprint confirm → meta read → paste. It runs over a `NewClient` built
   from the pin the human just confirmed, so the bytes come from the displayed
   key; unreachable and revision-incompatible are both loud refusals naming the
   remote, and neither degrades. `AddRemote`'s doc comment in
   `internal/service/remotes.go` now states what the CLI actually guarantees and
   records that the web add form does not do a meta read and does not need one
   — the authenticated fetch is what decides whether the entry exists.
   Test: `TestRemoteAddReadsMetaBeforeAskingForTheCredential`
   (`internal/cli/remotes_internal_test.go`) drives the ceremony against a real
   `httptest.NewTLSServer` with a `ReadPassword` hook that calls `t.Fatal` — so
   a paste before the check is a test failure, not an assertion. Three cases:
   a host that 404s meta, a peer at revision 0, and a revision-1 peer that
   passes and carries on; the meta hit counter is asserted in all three.

4. **`remote remove` uses a typed-name confirmation**, per ADR § Parity. New
   `disclose.ConfirmName` beside `Confirm`; the shared read loop is extracted as
   `readLine(tty, limit)`. **The trap worth knowing:** `Confirm`'s loop capped
   the answer at nine bytes, so reusing it verbatim would have made any remote
   name longer than that impossible to confirm. `ConfirmName` reads up to 256
   and compares EXACTLY (no case folding). Tests in `disclose_test.go` cover a
   23-character name, a near-miss, a case-shifted answer and the no-terminal
   refusal.

## Honesty and hygiene

5. `internal/service/remotes.go` `viewOf` now returns an error, pinned by
   `TestRemoteCorruptSnapshotFailsLoud{SQLite,Postgres}` (corrupt the stored
   `listing` column, then flip the peer to refusing and reset the gate BEFORE
   the read — otherwise a successful fetch overwrites the corrupt row and the
   test proves nothing). A stored
   snapshot that does not parse is an invariant break — this instance wrote
   those bytes from a listing it had already bounded — and swallowing it
   rendered the remote as reachable with zero organisations.
6. `internal/service/workspace.go` `Serve` distinguishes "no connection row"
   (`domain.ErrNotFound`, the ordinary human-holder case) from a database fault,
   which now fails loud instead of auditing an empty actor.
7. `internal/service/remotefetchgate.go`: `ErrFetchRateLimited` is DELETED and
   `admit` returns a bool. Nothing consumed the sentinel, and its doc comment
   asserted a refusal policy the only caller deliberately does not implement.
   The comment now states the real one — budget exhaustion degrades to the
   stale-labelled snapshot.
8. `internal/audit/registry.go`: the `remote.*` paragraph said the category was
   "not registered here yet" and that `remote.directory_served` was pinned in
   `audited_exemptions.json`. Both were false in this tree. It now describes
   what is true, and names `remote.auth_failed` as the second deliberately
   unregistered type beside `remote.workspace_session_expired`.
9. `internal/server/remotes.go`: `joinKeySet` was `strings.Join(keys, "\n")`
   hand-rolled. Deleted; the reason it exists moved to the call site.
10. `web/src/api/remotes.ts`: the directory poll claimed 15s left "room for a
    second tab", but 2 tabs x 4/min = 8/min overruns the 6/min per-viewer
    budget. Now 20s (3/min per tab, two tabs exactly inside the budget), with
    the comment stating that overrun degrades to a stale-marked snapshot rather
    than erroring.

## Verification

- `gofmt -l .` clean, `go vet ./...` clean, `go build ./...` clean.
- `go test ./...` green on sqlite AND on
  `HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_71_final`.
- `pnpm run typecheck` clean; `pnpm test` 22 passed (4 files).
- `pnpm run e2e` 52 passed, desktop and mobile.

# Codex R1 fixes (cross-model review, round 1 of 3)

Five parallel Codex passes (`.xreview/71-r1-p1a|p1b|p2|p3|p4.md`) returned 20
findings: 7 HIGH, 13 MEDIUM. **All 20 are fixed in this tree; none deferred.**
Every behavioural fix was driven test-first and the red was verified by
disabling the fix and re-running (recorded per finding below).

## Disposition

| # | Finding | Disposition |
|---|---|---|
| p1a-1 | ws bearer's origin binding not enforced at authn | FIXED |
| p1a-2 | 00021 fabricates `[]` assurance for live handoffs | FIXED |
| p1a-3 | `ic` decoy not work-uniform with revoked credentials | FIXED |
| p1a-4 | snapshot CHECK admits impossible rows; `ok` on the failure path | FIXED |
| p1b-1 | step-up does not require a fresh ceremony | FIXED |
| p1b-2 / p2-1 | operation + key-set binding stored, never enforced | FIXED |
| p1b-3 | `/me/sessions` reachable by `ws` and `ic` | FIXED, with one deviation stated below |
| p1b-4 | CI invariants blind to operation-less endpoints | FIXED |
| p1b-5 | audit actor guarantees not upheld or tested | FIXED |
| p2-2 | postgres READ COMMITTED races (redemption, `AddRemote`) | FIXED |
| p2-3 | round timeout fabricates unreachable results | FIXED |
| p2-4 | "instance-wide" budgets are process-local | FIXED (invariant enforced by documentation + ratification note) |
| p2-5 | plaintext proxies, proxy TLS uses the remote's pin, no wiring, `//api` | FIXED (four parts) |
| p3-1 | no-proxy closure bypassable by naming | FIXED |
| p3-2 | `remote add` permits plaintext, confirms a blank fingerprint | FIXED (claim verified first) |
| p3-3 | `ReadPassword` nil default; no interrupt-safe terminal restore | FIXED |
| p3-4 | `Vary: Origin` missing on denied / no-origin branches | FIXED |
| p3-5 | CSP `connect-src` admits `https://*.example` | FIXED |
| p4-1 | stale probes delete a replacement bearer | FIXED |
| p4-2 | liveness probe bypasses Zod, treats failure as success | FIXED |
| p4-3 | signed-out popup arrival never exercised | FIXED |
| p4-4 | `noopener` claimed but not asserted | FIXED |
| p4-5 | bearer-persistence assertion cannot prove memory-only custody | FIXED |

## HIGH cluster A — step-up integrity

**The fresh-ceremony gate (p1b-1).** `ApproveHandoff` now demands, for a
`step-up` purpose, a LIVE #54 reauthentication window on the APPROVING session
over the transaction's bound environment, whose ceremony happened at or after
the transaction was created (`Workspace.freshCeremonyClass`,
`internal/service/workspace.go`). Three fail-closed predicates: existence over
(approving session, bound environment), liveness at the current epoch and both
clocks, and freshness against `h.CreatedAt`. The window is the row TOTP, OIDC
and WebAuthn reauth each write when their ceremony verifies, so the gate is
satisfied by a real factor verification through the product's own ceremonies
and by nothing else.

The ceremony's factor class is persisted on the transaction
(`workspace_handoffs.factor_class`, migration 00021) and `elevate` reads THAT
rather than re-deriving a class from `h.Factors` — deriving from the assurance
record is precisely the inheritance being refused. The class also JOINS the
assurance record written onto the elevated session (`withFactor`), because a
reauthentication does not rewrite a session's own factors: without the join a
password login plus a live TOTP ceremony read as single-factor and the
elevation refused itself.

Tests: `TestStepUpDemandsARealFactorVerification`
(`internal/isolation/workspace_stepup_test.go`) drives the REAL ceremony end to
end — bootstrap admin, TOTP enrolment, `ReauthTOTP`, approve, redeem — and
asserts the approval is refused BEFORE the ceremony and accepted after. The
shared `runWorkspaceAssuranceAndStepUp` gained the `noCeremony` and
wrong-environment refusals. **Red verified:** with `freshCeremonyClass` bypassed,
`TestStepUpDemandsARealFactorVerification` fails with "an MFA session with no
fresh ceremony approved a step-up".

**The binding is consumed (p1b-2 / p2-1).** `reauth_windows` gained
`bound_operation` and `bound_key_set` (00021, both engines, `NOT NULL DEFAULT
''` = unbound, which is what every pre-#71 opener writes, so #54's
environment-wide semantics are untouched). `elevate` writes the transaction's
operation and canonical key set onto the window it opens;
`Auth.ConsumeReauthWindow` gained an `operation` parameter and refuses a BOUND
window presented for any other operation or key set. An unnamed operation (`""`,
what `RequireDisclosureAuthority` passes) can never equal a bound one, so a
bound window fails closed for it rather than being read as unbound. Key sets are
canonicalized once at the boundary (`service.CanonicalKeySet`: sorted,
newline-joined) so the comparison is a set comparison. `StartHandoff` also now
refuses a step-up naming no environment, at the transaction rather than at
redemption.

Tests: `TestStepUpBindingIsConsumed{SQLite,Postgres}` — consent for
`value.reveal`/`DATABASE_URL` authorizes exactly that pair and refuses another
key set, a superset, another operation, and an unnamed operation; and a
differently ordered key set is the SAME consent. The 2026-08-13 disposition adds
`TestStepUpRevealIsSpentByValuePath{SQLite,Postgres}`: a matching consent is
spent by `Values.Get(..., reveal=true)`, while `value.copy-source` still refuses
through that real seam. **Red verified:** before the ceremony mapping, the
matching real reveal failed with `ErrReauthUnitMismatch`.

## HIGH cluster B — endpoint confinement

**The admitting set (p1b-3).** New `TxAuthorizer.AuthenticateSelfSurface` admits
the three SESSION artifacts and nothing else — the same structural trick
`Authenticate` uses — and `Actor.resolveSelf` routes `ListSessions` and
`RevokeSession` through it. An instance-connection credential (and every
service-account token) is therefore refused at these operation-less endpoints by
construction, closing criterion 4's endpoint-level half.

**Stated deviation, for R2 to arbitrate.** The orchestrator's brief said `ws`
must not reach `/me/sessions` at all. It is not implemented that way, and the
reason is concrete: the shipped shell's liveness poll IS this endpoint (session
3, UI decision 2), and it is how BOTH kill switches become visible to a foreign
origin. Refusing `ws` wholesale would 401 every live workspace within one poll —
the client reads 401 as "revoked" and drops the session — so the feature would
be removed rather than confined. What is enforced instead is the security
property the finding actually names: a workspace bearer sees and may revoke
EXACTLY ITS OWN ROW (`selfScope`, `internal/service/workspace.go`), so an XSS on
the viewing origin cannot enumerate the human's CLI and browser sessions with
their IPs and user agents, nor end them. Self-termination stays available; it is
the shell's own disconnect.

Test: `TestSelfSessionSurfaceConfinesForeignArtifacts`
(`internal/isolation/workspace_session_test.go`). **Red verified:** with
`resolveSelf`/`selfScope` reverted, the `ic` credential lists sessions and the
workspace bearer sees two.

**The CI blind spot (p1b-4).**
`TestEveryRouteIsConfinedByAnOperationOrPinnedAsSelfScoped`
(`internal/isolation/eligibility_test.go`) enumerates the LIVE wire registry and
requires every http route either to map to an operation — and therefore pass the
artifact-eligibility chokepoint — or to be on a pinned list of 38 operation-less
routes, grouped by which authentication door they use. It is a set equality: a
route that gains an operation must LEAVE the pin, so the pin cannot become a
place confinement questions go to be forgotten.

**One adjacent instance found while writing the pin, and fixed with it.**
`GET /api/v1/me/orgs` is the other operation-less self-scoped projection — the
route `/me/sessions` copied its shape from — and it still resolved through
`Actor.resolve`. An instance-connection credential authenticated there and
received a successful listing: the same endpoint-level criterion-4 failure p1b-3
names, one route over. `Orgs.ListMine` now uses `resolveSelf`. A workspace
bearer keeps it, deliberately: it is a session of this instance holding exactly
this human's own grants, which is the ADR's stated blast radius for it, and the
shell needs it to render. Asserted in the same test.

`TestContractSecuredOperationsTakeAnArtifact`
(`internal/isolation/contract_test.go`) no longer restates
`{"serveDirectory": true}`. The expectation is DERIVED from
`authz.EligibleOperations(crypto.ArtifactInstanceConn)` and asserted in both
directions, so dropping the contract's `machine-credential` declaration — which
used to leave the test green — now fails.

## HIGH — origin binding at authentication (p1a-1)

`requesting_origin` is carried through `GetSessionByVerifier`/`GetSessionByID`
into `SessionRow` (both engines, `annotated_queries.json` repinned to 362), and
`authenticateResolvedSession` compares it against the request's `Origin` header
for workspace rows only. The header is threaded as
`audit.Context.RequestOrigin`, set in `API.wireContext` — deliberately a
separate field from the audit `Origin` enum beside it, which is a different fact
with the same English name.

**ABSENCE IS MISMATCH**, stated because it has fallout: a workspace bearer only
legitimately lives in browser JS making CORS requests, which always carry an
Origin, so a presentation without one is a presentation from somewhere that is
not the shell it was issued to. In-process test callers therefore have to say
which origin they are (`browserCtx` in
`internal/isolation/workspace_session_test.go`). CLI and browser artifacts are
untouched by the predicate.

Test: `TestWorkspaceSessionRefusesAForeignOrigin` — its own origin authenticates;
another allowlisted origin, no header, and a prefix of its own origin do not; and
a CLI session is unaffected by all three. **Red verified:** with the predicate
disabled all three foreign presentations authenticate.

## HIGH — no-proxy closure (p3-1)

`pinnedContractSurface` in `api/noproxy_test.go` pins ALL 124 path+method pairs
the contract declares, as a set equality. The vocabulary checks stay as defence
in depth; they are no longer the closure. `POST /api/v1/fleet/{peer}/execute`
and a generic `/api/v1/actions` taking its target in a body both fail now, which
is M6's actual requirement: a proxy-shaped endpoint cannot enter unnoticed
REGARDLESS of naming.

## HIGH — `remote add` over plaintext (p3-2)

**Claim verified first, and it was correct.** `cli.CanonicalOrigin` admits http
(deliberately — a loopback origin is legitimate for other verbs, and workspace
allowlist entries may be plaintext), `FetchIdentity` returns `("", nil)` for a
non-https origin, and the ceremony then confirmed a BLANK fingerprint, read meta
in the clear and asked for a credential paste. The server's
`ValidateRemoteURL` refused the result — one secret too late.

`addRemote` now refuses non-https before any ceremony runs, independently of the
general CLI's loopback exception, and refuses an empty pin as a second gate.
Server-side `ValidateRemoteURL` already refused http; both layers confirmed.
Test: `TestRemoteAddRefusesPlaintext` (`internal/cli/remotes_internal_test.go`),
whose terminal hooks `t.Fatal` if either the fingerprint prompt or the credential
prompt is reached.

## HIGH — postgres races (p2-2)

Two proof-free row locks, mirroring #54's `LockPrincipalRow` (postgres
`FOR UPDATE`, sqlite's single writer serializes; one `-- name:` per engine, which
is the repo norm):

- `LockWorkspaceOrigin` — `RedeemHandoff` takes the allowlist entry's lock and
  holds it through the mint, so a concurrent `RemoveOrigin` cannot delete the
  entry and sweep its sessions between the membership check and the insert. The
  kill switch had a hole exactly the width of one redemption.
- `LockInstanceIdentityRow` — `AddRemote`'s phase-three census takes the
  instance singleton's lock before the count and the duplicate-identity check.
  There is no per-remote row to lock because the row being decided about does
  not exist yet.

## HIGH — round timeout honesty (p2-3)

`Client.RoundBudget(n)` derives the whole-round maximum as
`(ceil(n/FanOut) + 1) × Deadline`; `runRound` uses it in place of
`Deadline * 2`. At 50 remotes and a fan-out of 4 that is thirteen waves, and the
flat budget gave the round 20 seconds of a 130-second job.

Separately and more importantly, `FetchAll` now returns a result only for
targets it ATTEMPTED, dropping any target whose wave never started (checked
before the semaphore and again after acquiring it, always before a byte is
written). `settle` already serves a snapshot AS a snapshot for a missing entry
and writes nothing, so an unattempted remote now produces no snapshot write and
no `remote.fetch_failed` event. Test:
`TestRoundBudgetCoversEveryWaveAndUnattemptedTargetsAreOmitted` (12 targets =
three waves).

## MEDIUMs

- **p1a-2.** 00021 no longer back-fills live rows with a default that would be
  false twice over. It adds `factor_class`, then `DELETE FROM
  workspace_handoffs` — handoffs live ten minutes, so the cost is that a popup
  opened across the upgrade is reopened. The redeem path additionally refuses an
  approved step-up carrying no factor class, which covers a rolling deployment
  where an old process approves a new row.
- **p1a-3.** Both decoy connection rows now carry PRESENT `revoked_at` and
  `last_used_at`, so a miss does the heaviest hit's timestamp work on its own
  engine rather than a lighter shape.
- **p1a-4.** The `remote_snapshots` CHECK is all-or-nothing over all SIX success
  columns (version and both counts included — a NULL there decoded to `""`/`0`
  and read as a peer claiming no version and no organisations), plus
  `last_outcome <> 'ok' OR observed_at IS NOT NULL`. The converse — a failure
  path writing `'ok'` — cannot be a CHECK, because `RecordFetchFailure` touches
  only the attempt columns; it is refused in Go by `validFailure`, and
  `validSnapshot` now requires the success path's outcome to BE `ok`.
- **p1b-5.** `remote.directory_served`'s TypeSpec said actor = the connection
  principal; a human holding `instance-directory` reaches the same operation and
  is a legitimate emitter. The declaration was wrong, not the emitter: it now
  says "the authenticated principal" and the payload gained a required
  `principal_class`. `handoffFailure` takes the actor and records it wherever one
  is known (the callback stage has authenticated a human; the redeem stage of an
  approved transaction knows the approver). `assertServedActor` in
  `remote_e2e_test.go` asserts both the actor id and the class, for the
  connection case and the non-connection case, and `runRemoteLifecycle`
  additionally asserts that the redeem-stage `remote.handoff_failed` row names
  the approving principal while the pre-authentication start-stage refusal
  stays anonymous — absence is a structural fact there, and inventing an actor
  would be worse than none.
- **p2-4.** No distributed limiter. The SINGLE-SERVING-PROCESS-PER-DATASTORE
  invariant is stated at the construction site (`fetchGate`'s doc comment,
  `internal/service/remotefetchgate.go`) with what breaks if it is violated and
  what would have to move if replication is ever supported. See the ratification
  note below.
- **p2-5.** Four parts. Plaintext proxies refused at `remotefetch.New`. The
  CONNECT tunnel is opened in `DialContext` under its own WebPKI `tls.Dialer`
  and `Transport.Proxy` stays nil, so the proxy hop is verified as an ordinary
  WebPKI peer while the transport's pinned config applies to exactly the
  end-to-end handshake inside the tunnel (Go applies ONE `TLSClientConfig` to
  both hops, which is why the previous shape failed every proxied fetch on the
  remote's pin). `HIKYO_DIRECTORY_PROXY` wires it explicitly, https-validated at
  config load, default off; `http.ProxyFromEnvironment` stays unused.
  `CanonicalRemoteURL` returns the slash-free origin and both `AddRemote` and
  `Client.Directory` use it, so `//api/v1/instance/directory` is unrepresentable.
- **p3-3.** `addRemote` calls `ios.readPassword` (the accessor honouring the
  documented nil default) instead of reading the field, which had made every
  real invocation refuse itself after the human confirmed a fingerprint.
  `readTerminalPassword` captures the terminal state and restores it from a
  SIGINT handler, then exits 130 — a Ctrl-C during a masked read used to leave
  echo disabled, so the NEXT secret the user typed was invisible and they could
  not tell. Portable across the repo's unix/windows split (no `syscall.Kill`).
- **p3-4.** `Vary: Origin` is set before the branch, so it is present on the
  denied, no-origin and preflight paths too. Test:
  `TestVaryOriginIsSetOnEveryBranch`, five cases.
- **p3-5.** `cspOrigin` PARSES and RECONSTRUCTS a canonical origin and drops
  anything that does not round-trip, replacing the character filter that
  `https://*.example.test` walked straight through (a wildcard host contains no
  forbidden character). Scheme, userinfo, path, query, fragment, host alphabet
  and port are all checked, and the emitted string must equal the stored one.
  **One narrow allowance, added because the full e2e run found it:** http is
  accepted on LOOPBACK hosts (`localhost`, `127.0.0.1`, `::1`) only. The remote
  URL grammar refuses plaintext, so an http entry is never one a human added
  through the API — but the two-instance browser harness repoints an entry at a
  loopback http origin at the store layer, deliberately (session 3's recorded
  decision), and https-only here silently removed B from `connect-src` and broke
  the whole browser leg. A loopback origin cannot be intercepted, and this is
  the same asymmetry `service.CanonicalOrigin` already codifies for allowlist
  entries. Test: `TestCSPConnectSrcAdmitsOnlyExactHTTPSOrigins`, twelve refusals
  (including `http://127.0.0.1.evil.example:8080`, which only looks like
  loopback) plus the loopback, canonicalization and dedup cases.
- **p4-1 / p4-2.** `web/src/api/workspace.ts`: strike counts and deletions are
  keyed by SESSION id, and `rememberWorkspace` is the store's only writer, so a
  probe completing about a replaced session is a no-op. `probeWorkspace` sets an
  `AbortSignal.timeout` deadline, requires `response.ok`, and parses the body
  with the generated `zSessionList`; everything else counts a strike. Nine tests
  in `web/src/api/workspace.test.ts`.
- **p4-3 / p4-4 / p4-5.** `web/e2e/flows/workspace.spec.ts`: a new flow clears
  the SERVING instance's cookies only, asserts the popup renders the inline
  login on the approve route with its path and query intact, logs in and
  approves. The main ceremony asserts `window.opener === null` inside the popup
  before authorizing. It captures the redeemed bearer from the redemption
  RESPONSE and asserts that exact value appears in neither origin's
  localStorage, sessionStorage, `document.cookie` nor `context.cookies()` for
  both origins, and that the liveness request carries `Authorization: Bearer
  <value>` and no `Cookie`.

## Two deliberate deviations from the brief

1. **No migration 00022.** The reauth-window binding, the handoff factor class,
   the handoff invalidation and the snapshot CHECK all landed in 00020/00021,
   which are NEW IN THIS UNMERGED BRANCH and have never shipped. The immutability
   rule protects released migrations; tightening a CHECK this branch itself wrote
   would otherwise cost a full sqlite table rebuild to undo a mistake nobody has
   ever run. No new tables, so no PG reset drop-list change. Dev databases on
   00021 must be recreated — the PG leg below used a fresh `hikyo_71e`.
2. **`ws` is confined at `/me/sessions`, not refused.** See HIGH cluster B.

## Ratification table addendum (owner-ratified 2026-08-13)

| Bound | Statement |
|---|---|
| `AggregateTriggerRate` | Installation-wide ONLY under a single serving process per datastore. Enforced by architecture (one multicall binary, embedded SPA, no scheduler) and documented at `fetchGate`. Horizontal replication would multiply it by the replica count and needs a datastore-backed limiter first. |
| Directory forward proxy | New, optional, default off: `HIKYO_DIRECTORY_PROXY`, https only, explicit configuration only. |

## Verification

```
gofmt -l .                                            # empty
go vet ./...                                          # clean
go build ./...                                        # success
GOOS=windows go build ./...                           # success (the terminal-restore fix)
go test ./...                                         # 1201 passed, 35 packages (sqlite)
HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_71e \
  go test -count=1 ./...                              # 1726 passed, BOTH ENGINES
go tool sqlc generate                                 # clean
go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml   # clean
(cd clients/ts && pnpm run generate && pnpm run typecheck && pnpm run test)
(cd web && pnpm run typecheck && pnpm test)           # 29 passed (4 files)
(cd web && pnpm run e2e)                              # 54 passed, desktop and mobile
```

The postgres database was recreated as `hikyo_71e`: migrations 00020 and 00021
changed (see deviation 1), so a database carrying the previous shape of them
fails with SQLSTATE 2BP01.

### Two Playwright traps the new flows hit

15. **Both projects run against the SAME pair of instances**, so a workspace
    session one test leaves behind is one the other project's kill-switch test
    counts — `revoked 1 workspace session` is a real assertion and the right fix
    is to clean up, not to loosen it. The signed-out flow removes the origin it
    used at the end.
16. **A password login cannot clean up after itself on B.** Every instance-scope
    surface is MFA-mandatory (trap 11), so the single-factor session the popup
    establishes cannot reach B's remotes page. The flow captures B's cookies
    before clearing them and restores the stepped-up administrator session for
    the cleanup.

---

# Codex R2 addendum — p3-1 closed in full (round 2 of 3)

R2 (`.xreview/71-r2-p3.md`, finding 1) re-graded p3-1 as **PARTIAL**. The
124-pair set equality over `api.Operations()`
(`TestContractRouteSurfaceIsExhaustivelyPinned`) closes contract-route
additions, but three bypass classes survived it. All three are now closed in
`api/noproxy_test.go`; nothing is deferred.

| Bypass class | Closure | Red proven by |
|---|---|---|
| Direct chi route outside the generated API group | `TestLiveRouterSurfaceIsExhaustivelyPinned` | temporary `r.Get("/fetch")` and `r.Get("/ui-gated-fetch")` in `server.New` |
| Schema expansion inside an existing operation | `TestDirectoryListingFieldsArePinned` | temporary `environments []string` field, then a `[]string` → `[]DirectoryProj` widening, then an `env_names` field on `Remote`'s snapshot half |
| Naming-based wire-registry half | the old test deleted, subsumed | n/a — see the transitive argument below |

## 1. The live router, pinned as a set

`TestLiveRouterSurfaceIsExhaustivelyPinned` walks the router `server.New`
actually assembles (`chi.Walk` over the returned `chi.Routes`) and asserts set
equality against `pinnedContractSurface` ∪ `pinnedNonContractRoutes`
(`GET /healthz`, `GET /readyz`, each with its reason) ∪ the method-agnostic
`/assets/*` pattern. `r.Handle` registers all ten methods for one asset
registration, which is why that one is allowlisted by pattern rather than by
method+pattern; `NotFound` / `MethodNotAllowed` are not walked because they are
fallbacks, not routes, and dispatch on nothing the caller names.

The neighbouring tests do not cover this on their own, which is the point:

- `TestInvariant01ClassificationTotality` (internal/isolation) walks the router
  but only demands each route be CLASSIFIED — adding one wire-registry line
  satisfies it — and it walks with a **nil `ui`**, so ui-gated routes are
  outside its view entirely. The new test passes a non-nil `ui`.
- The contract cross-check in internal/isolation skips every route outside the
  `/api/v1` prefix, which is exactly where a Go-first route sits.

Verified empirically: with `r.Get("/ui-gated-fetch")` added inside the
`if ui != nil` block, `TestInvariant01ClassificationTotality` **passes** and
`TestLiveRouterSurfaceIsExhaustivelyPinned` fails. That is the gap, measured.

## 2. The directory listing's fields, pinned

A route set does not change when an existing operation starts returning more,
and criterion 6 is about VALUES: "no endpoint on either instance returns
another instance's secret values to a server". The directory listing is the
whole of the data half — `serveDirectory` is the single operation the
instance-connection credential may reach (pinned by
`TestArtifactConfinementTableShape`), and a remote's stored snapshot is that
same listing fetched server-to-server.

**`Remote` is pinned alongside it, and that is not decoration.** The contract
does NOT `$ref` `DirectoryListing` from `Remote`: the snapshot half is
**inlined** onto the entry as five optional fields (`identity`, `version`,
`org_count`, `project_count`, `orgs`). `apigen.Remote` is therefore a *second*
struct through which another instance's values reach a response, generated from
a separate YAML block with nothing making the two agree. A pin naming only
`DirectoryListing` would have left it unwatched — this was caught during
verification, and the earlier draft of this section asserted a
`Remote.listing` reference that does not exist. The test now also asserts that
every field in `Remote`'s snapshot half has a `DirectoryListing` counterpart,
so the entry cannot project a value the directory endpoint never serves.

`TestDirectoryListingFieldsArePinned` reflects over `apigen.DirectoryListing`,
`apigen.DirectoryOrg` and `apigen.Remote` and pins **json tag → Go type**, both directions
(addition fails, removal fails). Reflection over the generated structs rather
than the YAML because those are the fields that actually serialize: a property
added to `openapi.yaml` carries no bytes until codegen runs, and a field
hand-added to the generated file carries bytes with no property at all — both
land here. The type is pinned alongside the name because `projects []string`
becoming `[]DirectoryProj` smuggles data through a field set that never
changed; that widening was reproduced end to end (struct changed, both
`internal/server/remotes.go` call sites updated, `go build ./...` green) and
the pin still went red.

## 3. The wire-registry half — deleted, not replaced

`TestWireRegistryHasNoProxyShapedRoute` was a vocabulary match over the
registry's key set. It is gone. The replacement is transitive and stronger:
the new test pins the live router as a set, and
`TestInvariant01ClassificationTotality` asserts the wire registry and the live
router are the same set of `http:` keys **in both directions** (every walked
route must be classified; every classified route must be walked). A wire entry
therefore cannot exist without a route, and no route escapes the pin — whatever
either is named. Class 1's red covers any Go-first route addition regardless of
naming, which is strictly stronger than the vocabulary check removed. Two
half-strength closures over one surface is one closure nobody re-reads.

## Verification

`gofmt -l .` clean, `go vet ./...` clean, `go build ./...` clean,
`go test ./...` 1202 passed across 35 packages (sqlite; no store changes, so
the Postgres suite is unaffected).

## Codex R3 — final round (3-round cap)

Verdicts: p3-1 SOUND (router + schema pins), p1a-1 SOUND (origin enforcement
verified at `internal/authz/session.go` with its foreign-origin test). One
blocking item: the R2 bearer-custody fix inspected page `b`'s tab-scoped
sessionStorage, which says nothing about the popup tab's. Dispositioned by
applying R3's own prescription: the flow now snapshots the POPUP's stores at
the last moment it is on B's origin (no `hik_1_ws_`/`hik_1_hc_`/`hik_1_hs_`
artifact; B's script-readable CSRF token is legitimate and excluded), keeps
the origin-scoped localStorage/cookie checks on page `b`, and documents the
structural argument: the bearer is minted by the shell's redemption AFTER the
popup leaves B, so no B-tab sessionStorage moment exists that could hold it.
e2e 54/54 after the change.

## Owner dispositions (2026-08-13)

1. **RESOLVED.** Owner ratified all nine bounds; `remotefetch/bounds.go` records the 2026-08-13 disposition.
2. **RESOLVED.** Owner agreed with the hard-short residual; workspace sessions now idle at 15 minutes and cap at 4 hours.
3. **RESOLVED.** The #58 ceremony seam now derives the matching authz operation from every reauthentication purpose, so a correctly bound workspace window is spendable by the real reveal path and a different operation still refuses.
4. **ACKNOWLEDGED — NO CHANGE.** The single-serving-process invariant remains documented at `fetchGate`; no distributed limiter was requested.
5. **ACKNOWLEDGED — NO CHANGE.** `remote.auth_failed` and `remote.workspace_session_expired` remain unregistered because neither has an honest emitter.

---

# Rebase onto origin/main b623d52 (#40 values, #58 reveal, #76 backup, #62 OIDC federation, #73 SCIM)

Mechanical conflict resolution plus the fixes the UNION of six feature sets
needed. Nothing was deferred and no test was weakened.

## Migrations renumbered

`00015_multi_instance` -> **00020**, `00016_workspace_assurance` -> **00021**,
both engines. Upstream took 00015-00018. Every in-tree reference updated
(queries, service comments, this document). Verified: upstream's 00015-00018 do
NOT touch `sessions` or `reauth_windows`, so 00020's `sessions` rebuild still
restates the correct shape — the comment now says "the shape reached by 00018,
which is the 00014 shape" rather than leaving a reader to check.

## Conflicts, and how each was decided

- **`api/openapi.yaml`** — my side was verified purely additive (0 deletions, 0
  modified keys) and spliced into upstream's document as 11 path items, 3
  parameters and 22 schemas. No `operationId`, path, parameter or schema name
  collides with upstream's 44 new schemas, and every `$ref` my blocks make
  resolves in the merged file.
- **`internal/isolation/harness_test.go`** — took upstream's `DROP SCHEMA public
  CASCADE`, which SUBSUMES the enumerated drop list my six tables were added to.
  The handoff's old "add every new table to both drop lists" rule now applies to
  `internal/conformance` only.
- **`internal/conformance/conformance_test.go`** — union: upstream's
  `federation_issuers` plus my six #71 tables, children before parents.
- **`internal/isolation/contract_test.go`** — took upstream's `machineSatisfiable`
  check. Mine (`machineReachable[id]`) assumed the instance-connection credential
  was the ONLY machine-credential-eligible artifact, which #62's delivery surface
  made false. My bidirectional confinement checks above it survive untouched, so
  the `ic` pin is not weakened — only the general claim is generalised.
- **`internal/isolation/audit_e2e_test.go`** — took upstream's `probeKeyring`
  (identical memoization to my inlined `keyrings sync.Map`, minus a type
  assertion) and deleted mine. Lifecycle sweep is the union of all four:
  federation, SCIM, remote, backup — backup LAST because it advances the restore
  epoch, remote before it because it authenticates real artifacts at the current
  one.
- **`web/e2e/fixtures/instance.ts`** — my two-instance skeleton with upstream's
  seeding, passkey and hardened-health machinery ported onto instance A. Details
  below.
- **`web/src/app/{App,navigation}.tsx|ts`, `registry.ts`, `registry.test.ts`,
  `app.css`** — unions. One is NOT a union and is the important one: see below.

## Fixes the merge required (root causes, not patches)

1. **`CHROMELESS` was derived from `section === null` and is now DECLARED.**
   This is a SECURITY fix the conflict markers did not show. My #71 App.tsx
   routes `CHROMELESS` surfaces as PUBLIC (no session) — correct for the login
   page and the two workspace ceremony pages. Upstream's `values` surface is
   also `section: null` (it is reached from the matrix, not the sidebar) but is
   a signed-in, chromed surface. Merging naively would have made the entire
   reveal surface publicly routable. `CHROMELESS` is now an explicit id list and
   `shellSurfaces` is its complement; the doc comment names `values` as the
   counterexample so the derivation is not re-introduced.
2. **`ConsumeReauthWindow` merged both parameters** — #58's `purpose` and my
   `operation`. The 2026-08-13 disposition closes the remaining seam:
   `requireCeremony` maps all four purposes to their authz operation names and
   presents that name at consumption. A workspace step-up's matching bound
   window is therefore spendable by the real reveal path, a different binding
   still refuses, and every #54 opener stays unbound with its environment-wide
   semantics unchanged.
3. **`instance_connections` added to `MaxKnownCredentialEpoch`**, both engines.
   #76's `TestMaxKnownCredentialEpochCoversEveryEpochColumn` pins the query to
   the SCHEMA, and my table carries a `credential_epoch` a forged archive could
   otherwise plant a credential at and survive the restore bump.
4. **`instance_identity` added to `migrationSeededTables`** (`internal/store/backup.go`).
   Decision 2 has the migration mint the identity row, so a freshly migrated
   restore target is not empty by #76's definition and every PG restore drill
   failed. The truncate replacing it with the archive's is right rather than
   merely tolerable: a restore reconstitutes THAT instance, and a remote that
   pinned the old identity must keep resolving to it.
5. **`cli.Verbs`** — kept upstream's derivation from `verbHandlers` and deleted
   my restated literal; `remote` and `remote-credential` are in the dispatch
   table, so the derived list carries them.
6. **`api/noproxy_test.go`** — 52 upstream routes added to
   `pinnedContractSurface`, each grouped under a written confirmation of what it
   returns. `TestRemoteContractSurfaceIsPinned` now skips `/scim` paths: SCIM
   owns the word "directory" for the provider's own directory, PUSHED here and
   stored, and asking a multi-instance question about a route it does not
   describe only trains the reader to wave it through. Nothing escapes — the
   exhaustive set pin still covers every SCIM route.
7. **`internal/isolation/eligibility_test.go`** — `POST /api/v1/auth/reauth/totp`
   pinned as operation-less under category 2: it resolves through
   `az.Authenticate` (cli+browser), so a workspace bearer cannot open a
   reauthentication window on the human's own account.

## The Playwright harness merge, and the one real bug it exposed

Upstream evolved the SINGLE-instance harness (seeded tenant, virtual
authenticator, `SEEDED`/`PASSKEY` files, hardened health probe); #71 rewrote it
into a TWO-instance one. The merge keeps the two-instance skeleton and runs
upstream's machinery against instance A.

- **The hostnames SWAPPED, and the reason is load-bearing.** A is now
  `localhost` and B is `127.0.0.1`. A WebAuthn relying-party id must be a
  registrable domain and an IP literal is not one, so the instance that runs
  passkey ceremonies has to hold the NAME. The two still differ, which is all
  the cookie-jar separation needs.
- **A no longer enrols its own TOTP factor**: `seedTenant` already enrols one
  and its provisioning URI plus spent-step bookkeeping travel to the workers in
  `SEEDED`. A second enrolment would rotate the secret out from under
  `nextTotpCode`. A's setup session steps up with `nextTotpCode()`; B, which has
  no seeded tenant, keeps its own enrolment.
- **`mintStorageState` preserves the foreign jar through the FILE**, not through
  module state. `refreshSharedSession()` runs in WORKER processes where the
  `instances` array is empty, so a re-mint that read B's cookies from memory
  would silently drop them mid-suite.
- **`web/e2e/fixtures/totp.ts` deleted**: `seed.ts` already ships the same RFC
  6238 generator, and two of them in one fixtures directory is one nobody
  re-reads.

**Trap 17, and it cost the longest debugging leg of this rebase.**
`context.cookies(url)` applies the browser's own DELIVERY rules, and a `Secure`
cookie is not delivered to an `http://` URL whose host is an IP LITERAL —
Chrome's plaintext carve-out for secure cookies is `localhost` BY NAME. The
signed-out flow captures B's session to restore it for its cleanup, and after
the hostname swap `context.cookies(BASE_URL_B)` returned an empty array. It then
restored nothing, the cleanup could not reach B's MFA-mandatory remotes page,
and the test timed out — which ALSO left a workspace session and a stale
allowlist entry behind, which is what killed the second Playwright project with
`ERR_CONNECTION_REFUSED`. Two symptoms, one cause. The capture is now by DOMAIN
(`(await context.cookies()).filter((c) => c.domain === HOST_B)`), which is what
the test meant all along.

## Verification

```
gofmt -l .                                            # empty
go vet ./...                                          # clean
go build ./...                                        # success
GOOS=windows go build ./...                           # success
go test -count=1 ./...                                # 1562 passed, 39 packages (sqlite)
HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_71_rebase \
  go test -count=1 ./...                              # 2329 passed, BOTH ENGINES
go tool sqlc generate                                 # clean, no drift
go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml   # clean, no drift
(cd clients/ts && pnpm run generate && pnpm run typecheck && pnpm test) # 4 passed
(cd web && pnpm run typecheck && pnpm test)           # 29 passed (4 files)
(cd web && pnpm run e2e)                              # 82 passed, desktop and mobile
```

The postgres database is a FRESH `hikyo_71_rebase`: the migration renumber means
any database carrying the old 00015/00016 fails with SQLSTATE 2BP01.

## Repins

`operation_formulas.json` (143), `annotated_queries.json` (422),
`audited_exemptions.json` (33 wire + 1 operation — the union that KEEPS
upstream's removal of `cli:migrate`/`cli:server`, which now emit events, and
adds my three), `internal/cli/testdata/help.txt` (regenerated with
`go test ./internal/cli -update`, carries both feature sets' verbs).

## Post-rebase cross-model review (2026-08-13)

Focused Codex (gpt-5.6-sol, high) pass on the rebase-resolution delta only:
R1 two findings (restore-epoch coverage, binding-branch test coverage), both
refuted with primary evidence in R2 — the epoch union lives in authn.sql's
MaxKnownCredentialEpoch (both engines, instance_connections present) and the
binding branch is covered by TestStepUpBindingIsConsumed{SQLite,Postgres}.
**R2: both WITHDRAWN, FINAL VERDICT CLEAN.** Full matrix green on the final
tree: sqlite 1562 / postgres 2329 (fresh DB) / web 29 unit / e2e 82, ports
45801-45803 per the parallel-session port scheme.

## Main update and conflict resolution (2026-08-13, PR #115)

Merged `main` at `91cedcb` without rewriting #71's commit. The combined tree
keeps #109's revisions/publish surface and #117's in-transaction federation
timing checks alongside both multi-instance tiers.

- #109 owns migration `00019`; multi-instance and workspace-assurance moved to
  `00020` and `00021` on both engines. Generated SQL, Go API, and TypeScript
  clients were rebuilt from the merged sources.
- Semantic merge collisions were resolved: revision snapshot conversion
  helpers have domain-specific names, #109 routes are included in the
  no-proxy closure pin, and workspace reveal tests publish their staged value
  before exercising #71's step-up consent.
- Live PR findings were fixed in this head: workspace start/redeem enter the
  shared pre-auth admission budget; remote names use the entity-name grammar;
  rename reloads the persisted last-known snapshot; proxy CONNECT writes and
  reads are deadline- and cancellation-bounded with failure-path close.
- Exact-head Aikido follow-up findings were fixed in a normal follow-up commit:
  per-fetch pinned transports disable keep-alives so no unreachable idle pool
  retains TLS/CONNECT sockets, and PKCE is closed at both boundaries to
  canonical base64url verifiers (43-128 characters) plus an exact 43-character
  S256 challenge. Short, padded, non-base64url, and overlong values are tested.
