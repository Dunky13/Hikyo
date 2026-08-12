# Handoff: #48 hierarchy CRUD — org / project / environment / folder via API + CLI

Issue: https://github.com/Dunky13/hikyo/issues/48 (parent #41, blocked by #47 — merged).
Specs, all on `wayfinder-docs`: `docs/spec/domain-model.md`, `docs/adr/flat-model.md`
(supersedes the inheritance model in full), `docs/adr/api-cli-surface.md`,
`docs/spec/api-cli-spellings.md`, `docs/adr/tenant-isolation.md`,
`docs/adr/permission-model.md`, `docs/spec/ops-catalogue.md`.

Scope: the **hierarchy portion of C1 only** — Organization, Project, Environment,
Folder. No Key/Value rows (later ticket); Instance has no CRUD.

## What exists

### Contract (`api/openapi.yaml`)

21 new operations under the `hierarchy` tag: full CRUD + rename (`show`,
`list`, `create`, `rename`, `delete`) for org/project/environment/folder,
plus `PUT …/environments/order` (atomic reorder taking the complete ordered
id list — cannot produce duplicate positions or gaps). New `Conflict`
response; `ErrorCode` grew `conflict` + `limit_exceeded` (legal pre-freeze
only — see Disposition). 3.1 profile and freeze fixtures pass; TS client
regenerated.

### Store

New `folders` table + `environments.display_order`
(`migrations/{sqlite,postgres}/00009_hierarchy.sql`). **`display_order` carries
no column default on either engine** — a default on an ordering column is the
silent fallback this project refuses (a writer that forgot the column would
quietly claim first position). Postgres adds it with a default, backfills, then
`DROP DEFAULT`; sqlite cannot add a NOT NULL column without a default nor drop
one afterwards, so it reaches the same shape through the table rebuild migration
00006 established (create twin → copy with an explicit `0` → drop → rename). Both
engines carry `CHECK (display_order >= 0)`. The rebuild's premise is stated in
the migration: `environments` has no creation path before this ticket and the
grant API is #55's, so no real deployment holds a row here; one that somehow does
fails the migration loudly rather than losing it. `lint.CollectTables` now
replays create/drop/rename to distinguish the tables that exist at rest from
every name a CREATE mentioned — the transient twin needs no scope directive, and
declaring one (as 00006 does) is still accepted. Folder rows carry the
denormalized `org_id + project_id` chain; `folder` scope class added to the
lint enum (`chain=org_id,project_id`). 24 store methods × 2 engines, every
one proof-verified with its own `authz.Store*` op. Constraint violations map
to `ErrConflict` via **typed** codes only — `errors.As(&sqlite.Error)` +
`SQLITE_CONSTRAINT_*` on sqlite, `pgconn.PgError` SQLSTATEs on postgres; no
string matching. Deletes never cascade: projects/grants block org delete, an
env-scoped grant blocks environment delete, non-empty projects refuse with
`conflict`.

**Environment-set mutations take the project row first.** `Projects.Lock` (`SELECT
… FOR UPDATE` on postgres, a plain read on sqlite, whose single
`_txlock=immediate` write connection already serializes) is taken by both
environment create and reorder: the cap check and the append position are
read-then-write, and without the lock two postgres transactions at cap−1 both
pass, and two reorders can interleave their per-row writes into a blended
permutation. The engine divergence is commented at both query sites.

### Service (`internal/service/hierarchy.go`)

One authority for name/path validation (`checkName`, `checkFolderPath`);
contract carries only the length bound. Environment cap
(`MaxEnvironmentsPerProject = 50`, ops-spec bound) enforced in-transaction;
the fixed 422 message is built from the const (single source). Folder paths
are a **flat namespace** in v1 — rename moves exactly that row, nothing has
children.

### Transport (`internal/server/hierarchy.go`)

Strict-server error legs rerouted through the uniform writer
(`NewStrictHandlerWithOptions`) — handlers are ~8 lines, "fixed message per
code" lives in one place, and **no handler can fall through a switch and
answer 500 by omission**. All pre-existing `switch classify(err)` cascades in
`api.go` (11) were converted to the same idiom; existing server tests passed
unchanged, which is the byte-shape evidence. Side effect inherited from the
rerouting: `createOrg` duplicate-name now answers 409 (was a raw-driver 500).

Uniform nonexistent shape at every level:
`TestUniformNonexistentAtEveryLevel` does `bytes.Equal` on real wire responses
over all 19 by-id routes. **Tenant routes declare 403 if and only if their
formula is MFA-mandatory** — `isolation.TestTenantRoutesDeclareForbiddenOnlyForMFA`
asserts the iff against the operation registry, and
`server.TestAssuranceRefusalOnATenantRouteIsForbidden` feeds a fixture
`ErrUnauthorized` so the mapping is pinned by a non-tautological test. Grant
refusal on a tenant operation is always the 404 (`authorize()` returns
`ErrNotFound` there); the one `ErrUnauthorized` a tenant operation can produce is
the assurance leg — grant HELD, session single-factor — which is deliberately
distinguishable per `internal/authz/authorize.go`'s locked comment, so `renameOrg`
and `deleteOrg` (atom `instance-config`, MFA-mandatory) declare it.

### CLI (`internal/cli/hierarchy.go`)

`project`/`env`/`folder` verb families + `org rename|delete`. Golden tests
re-pinned (help, exit codes, one `-o json` document per entity).

**Syntax is validated before target resolution and session lookup in all four
families** (`org` included), so an exit code never depends on login state:
unknown subverb, missing required flag, a stray extra positional, and a
positional contradicting its own selector flag are all usage (2) whether or not
a session exists. Every subverb calls exactly one of `checkTarget` (takes one
object) or `checkNoPositionals` (takes none), from a switch `subverb()` already
made exhaustive — so `folder list stray` and `project create stray --name x`
refuse instead of dropping the word. The contradiction is checked against the
FLAG only, and *availability* of a target is deliberately NOT a syntax question:
`--org`, `HIKYO_ORG`, a pin file and a context may each supply it, so all four
families ask that after resolution through `addressed()`. `conflict` and
`limit_exceeded` map to exit 4 (refused), not 1.

`hikyo project delete` requires
`--confirm <project-name>` byte-matched against the server's copy of the name
(permission-model's locked row: "explicit confirmation naming the project");
absent → exit 4 **before any request at all**; mismatched → exit 4 after the
single GET it needs to read the name. The demo asserts the REQUEST LOG for each
case (zero requests / GET only / GET then DELETE), because exit 4 alone cannot
tell a client-side refusal from the server's non-empty-parent conflict —
verified by removing the guard and watching the log assertion fail. Org/env/folder
deletes carry no confirmation — the locked row names only project deletion
(it will crypto-shred the project DEK).

### E2E demo

`runHierarchyDemo` (isolation suite) drives the real CLI through the whole
surface: create org→project→envs→folders, `org list`, `project list`, `env list`
(count AND `len(items)`), `env show`, `folder show`, reorder, rename at every
level, then successful `env`/`folder`/`project` deletes with the request log
asserted at each step. Sentinel-broken once to prove the assertions execute.

Isolation probes: every "genuinely missing" twin is **authorized**-but-missing.
A twin addressing `prj_missing` uses `alice` (org-scoped grants in org A, so she
would reach it if it existed); a twin addressing a missing CHILD inside `prjA1`
keeps `mchA1`, whose grant covers that project — only the child is absent, which
is already the authorized-not-found case. Mutation
probes compare a `contentSnapshot` — every mutable field: names, notes, paths,
display order — plus the `settings.*` audit-row count, not just row counts: an
unauthorized rename or reorder that commits and then answers `ErrNotFound` leaves
every count untouched.

## Decisions taken in-slice

- **Reorder spelling** — no ADR prescribes one; chose `PUT
  …/environments/order` with the full ordered list (atomic, one formula) over
  per-env PATCH. Any mismatch (short list, duplicate, foreign id) is one fixed
  `bad_request` — a foreign id discloses nothing. **An empty project's whole set
  is the empty list**, so `[]` is a legal no-op and the contract's `minItems` is
  0 to match. Deleting an environment leaves its display-order gap behind by
  design; **create appends at `max(display_order)+1`, never at the row count** —
  after `[0,1,2]` minus the middle the count is 2 and the next position is 3, and
  using the count there would hand the new row a position the last row already
  holds (`conformance: order_after_deletion` is the regression). A reorder is what
  closes a gap, deliberately and by an operator.
- **Reorder audit payload carries the resulting order**, not only its length:
  `environment_order` is the comma-joined id list (server-minted ids are trusted
  vocabulary, so `KindString`, not free text). Swapping production and staging
  must not produce the same record as any other permutation of the same set.
- **Name bounds** — no ADR fixes entity-name length; adopted the org
  contract's existing 128 for all four entities. OpenAPI `maxLength` counts
  code points, the service counts bytes; the service is authoritative, the
  mismatch surfaces as a 400.
- **Folder audit payload field is `namespace`** (wire field stays `path`) —
  the forbidden-content guard reserves `*path*` for instance-derived JSON
  pointers.
- **Rename/delete read the row in-transaction** so the audit trail records
  the actual transition (`previous_name` + `name`).
- **Lists unpaged** (precedent `OrgList`), bounded by the 50-environment cap.
- `x-hikyo-min-revision: 1` on every new operation (`api.Revision` stays 1
  pre-freeze).

## Disposition items (human) — surfaced at merge gate

1. **Closed CLI verb set grew**: `rename`, `show` (all four), `env reorder`,
   and the whole `folder` family are declared additive joins (precedent:
   `values set --clear`). The ticket's own acceptance ("list and rename at
   every level") forces them, but the spelling declaration lives in a code
   comment (`internal/cli/hierarchy.go`); the spellings doc has no hierarchy
   section. **#27/freeze must confirm or rename.**
2. **`ErrorCode` grew** `conflict` + `limit_exceeded` — legal only because
   the freeze gate is unarmed; post-freeze this exact change is forbidden by
   the repo's own fixture.
3. **`org.get`/`rename`/`delete` reclassified instance→tenant** (`LevelOrg`)
   per C1's "each level"; `GET /orgs/{org}` moved to `auditedNone` (list/count
   still audited). `POST/GET /orgs` stay instance-class.
4. **No org-lifecycle capability atom exists** in the permission ADR — org
   rename/delete run `instance-config@instance`; an org admin cannot rename
   their own org (uniform 404). Inventing an atom would reopen the ADR.

## Known gaps / deferred

- `environment.update-note` remains route-less (#44 probe scaffolding); env
  `note` column stored but absent from the wire `Environment` schema.
- Protected-environment clause of project delete defers with the flag it
  depends on (#55).
- Folder path segments permit internal spaces (no spec grammar exists); the
  key grammar deliberately not applied to entity names or folder paths.

## Verification record

`go build/vet/gofmt` clean; `go test ./...` exit 0 on sqlite **and** postgres
18 (`HIKYO_TEST_POSTGRES_DSN`, conformance + isolation both engines); sqlc +
oapi-codegen regen idempotent; TS client regen idempotent + typecheck + 4/4
contract fixtures (Node 24 per `.nvmrc`). Two-axis review (standards + spec)
findings fixed in-slice; cross-model review record appended below.

## Cross-model review record

Codex `gpt-5.6-sol`, high effort, 3 passes (contract/server/service,
store/authz/audit, CLI/tests), 3-round cap.

**R1: BLOCKED on all three passes — 13 findings. 12 fixed, 1 rebutted.**
**R2: passes 1 and 2 CLEAN; pass 3 blocked on three incomplete R1 fixes, all
completed — positional validation extended to the `list`/`create` subverbs and to
the whole `org` family, `org` syntax moved before authentication, and the
remaining `mchA1`/`prj_missing` twins (environment create, project rename,
environment reorder) swapped to `alice`.**
**R3 (pass 3): final verdict CLEAN.** The missing-child twin pushback (four
`mchA1` twins deliberately kept — they address `prjA1` inside the grant with a
missing child, already the authorized-not-found case) was accepted. All three
passes CLEAN within the 3-round cap; no items left for human disposition from
the cross-model axis.

Fixed: tenant 403 undeclared in the contract (P1.1, fixed as a declaration
rather than a remap — see below); create-after-delete display-order collision
(P1.2); contract/service length disagreement undocumented (P1.4); empty-project
reorder rejected by the schema the service accepted (P1.5); `display_order`
column default (P2.1); postgres cap race with no project-row lock (P2.2); missing
non-negative check (P2.3); reorder audit payload could not identify the
permutation (P2.4); confirmation tests that passed with the guard removed (P3.1);
extra positionals silently dropped and positional/flag contradictions (P3.2);
syntax validated after authentication, making exit codes state-dependent (P3.3);
probe twins that were themselves unauthorized, and mutation probes blind to
in-place writes (P3.4); missing JSON goldens and demo coverage (P3.5).

Found while fixing, not reported: `conflict`/`limit_exceeded` fell through the
CLI's status mapping to exit 1 (internal), telling a script the server broke when
it had answered correctly. Now exit 4.

**Rebutted — P1.1's remedy, not its finding.** The finding is correct that
`ErrUnauthorized` renders 403 on tenant routes; the proposed remedy (render 404)
is wrong. On a tenant operation `authorize()` returns `ErrNotFound` for grant
refusal and `ErrUnauthorized` only from the assurance leg, which fires *after* the
grant check succeeds — the caller HOLDS the capability and is short a factor.
`internal/authz/authorize.go`'s locked comment (#44/#54) chose that distinction
deliberately: they can already reach the object, so 404 would tell a capability
holder it is missing, and it would put tenancy policy in a transport that owns
none. The defect was the undeclared status; the fix declares it on exactly the two
MFA-mandatory tenant operations and pins the iff against the registry.

**Rebutted in full — P1.3 (contract compatibility).** `getOrg`'s reclassification
and the `ErrorCode` growth are deliberate pre-freeze decisions, already recorded
as Disposition items 2 and 3 above and carried to the merge gate. The freeze gate
is unarmed (no freeze tag exists), the version promise binds only "from the first
stable release", and no external client exists to break. The finding's remedy — a
revision strategy — would arm a promise the project has not yet made.
