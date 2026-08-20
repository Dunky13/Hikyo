# Handoff: #70 definitions Git flow — export / check / plan / apply

Issue: https://github.com/Hikyo-Org/hikyo/issues/70. Parent: #41. This is slice A: canonical bundle, store, service, authorization/audit, API, CLI, and Go E2E. Slice B owns the web surface described at the end.

## What exists

### Contract

Seven API revision 2 operations live under `/api/v1/orgs/{org}/projects/{project}/definitions` in `api/openapi.yaml`; generated Go and TypeScript clients are current.

| Method and path | Response / behavior |
|---|---|
| `GET /export?portable=true|false` | Exact canonical bundle bytes, `application/json`. Portable strips ids and `base_revision`. |
| `POST /check` | Raw bundle → `{state, base_revision?, current_revision, differences}`. No persistence. |
| `POST /plans` | Raw bundle → `201 {plan}` with immutable pins and concrete impact. |
| `GET /plans/{plan}` | The same immutable plan view. |
| `POST /plans/{plan}/apply` | `{allow_delete,digest?,commit?,ref?,actor?}` → `{revision,published,plan_id}`. |
| `GET /settings` | `{definitions_source,last_apply?}`. |
| `PUT /settings` | `{definitions_source:"db"|"git"}` → the same settings view. |

Machine credentials are admitted for export/check/plan/get/apply/settings-read. Settings-write is human-only. Export/check/settings-read use `read@project`; plan/get/apply use `definitions-edit@project`; settings-write uses `project-settings@project`.

### Canonical bundle library

`internal/definitions` owns the closed v1 JSON vocabulary, strict parse, normalize, encode, digest, identity matching, resolution/diff, and drift classification. Encoding sorts object keys at every depth, sorts environments/groups/keys by name, uses two-space indentation, disables HTML escaping, preserves integer literals, and ends in one LF. Digest is unprefixed lowercase SHA-256 hex over canonical bytes.

Bounds are 1 MiB raw and 10,000 total key/environment/group entries. Unknown and duplicate members, trailing JSON, the removed `base` field, ids without `base_revision`, invalid declarations/presence, stale ids, and duplicate identity/final names refuse loudly.

### Importer reconciliation

`internal/importer.Plan` now carries `definitions.Bundle` directly; the provisional importer `Bundle` / `BundleKey` types are deleted. Phase 1 emits one project-wide additive bundle with no `project`, ids, or `base_revision`; empty `environments` and `key_groups`; and keys whose metadata/group fields are zero-valued and whose `required_in` / `forbidden_in` rules are both `{mode:"none",environments:[]}`. Planning normalizes it and the CLI writes `definitions-bundle.json` through `definitions.Encode`, so the artifact parses through `definitions.Parse` and resolves as additive creates.

### Store

Migration `00027_definitions_git_flow.sql` (renumbered from 00026 on rebase — main took `00026_offline_delivery_records`) exists for SQLite and PostgreSQL. It adds `projects.definitions_source TEXT NOT NULL DEFAULT 'db' CHECK (db|git)` and `definitions_plans`, whose rows retain canonical bundle bytes, digest, schema/value/protected pins, rendered diff, expiry, apply stamp, and provenance.

Generated queries and repos implement source read/write; plan create/get/latest-applied/open-count/apply/prune; project-wide snapshot revisions; environment protection; per-key live environments; and per-environment live-value count. Expired unapplied plans are pruned by the existing hourly/startup retention sweep.

### Service

`internal/service/definitions.go`, `definitions_apply.go`, and `definitions_apply_exec.go` implement export/check/plan/get/apply/settings. Apply is one `tx.Write`: authorize; lock project; re-check digest/topology/schema/value/protected pins; enforce deletion and reveal gates; apply final topology/catalogue through stores using two-phase rename handling; bump schema revision once; stamp provenance/audit; fan out final-state publication; announce after commit.

Definitions revision now advances for every bundle-represented change: key semantic fields and metadata, environment create/clone/rename/delete, and key-group create/rename/delete. Reorder and folder-only changes do not advance it. Git mode guards every direct definition edit after authorization and before mutation. Values, protected/reauth settings, retention, grants, and definitions apply are not guarded.

### Authorization and audit

Operations: `definitions.export`, `definitions.check`, `definitions.plan`, `definitions.plan.get`, `definitions.apply`, `definitions.settings.get`, `definitions.settings.set`. Store-operation sets include every actual repo method, including plan environment live-count and settings response last-apply reads.

Events: `definitions.plan_created`, `definitions.applied`, `definitions.apply_rejected_stale`, `definitions.deletion_refused`, `definitions.additive_modification_refused`, and `settings.definitions_source_changed`; definitions-apply publication uses trigger `definitions-apply`. Plan-get and the CLI transport have reviewed audit exemptions. `cli:definitions` is tenant-class.

### CLI

`internal/cli/definitions.go` serves:

```text
hikyo definitions export [--portable] [--output-file PATH] [--project P]
hikyo definitions check --file PATH [-o table|json]
hikyo definitions plan --file PATH [-o table|json]
hikyo definitions apply --plan ID [--file PATH] [--allow-delete]
    [--commit C] [--ref R] [--actor A] [-o table|json]
```

Export preserves exact response bytes. Its file leg creates a new 0600 file without overwrite and warns on stderr inside a Git worktree. Apply `--file` parses canonically and sends its digest. Check alone returns 0 equal, 1 different, 2 error; drift is an outcome and prints no error diagnostic. All other verbs keep the closed CLI taxonomy. Help, usage, exact export bytes, table/JSON shapes, check exits, digest forwarding, worktree warning, and refusal mappings are golden-tested.

### E2E

`internal/isolation/definitions_e2e_test.go` runs the same ten scenarios through `seededDB` on SQLite and PostgreSQL: round trip; all four stale pins; key and environment deletion guards; all 18 Git-mode direct writes plus apply; additive semantics; id/name matching and swaps; stale-base classification; inherited reveal; open-plan quota, inclusive expiry, and GC. Every refusal compares catalogue/topology/plan content, schema revision, values, snapshots, and snapshot entries before/after.

### ADR-touching scheduler widening

Expired definitions plans remain in the hourly retention/GC run and startup catch-up because `docs/adr/ops-spec.md` explicitly assigns expired plans to that scheduler. This deliberately widens the scheduler system-proof operation set with `definitions.PruneExpiredPlans`; invariant 11 pins the added operation with the mandate beside it. The tenant-isolation ADR requires human review for any such widening, so this is recorded as an explicit review decision, not hidden as plan-creation cleanup.

## Decisions taken

1. Bundle format is closed canonical JSON v1. Non-id fields always emit. Names are the portable references. No `project` or `base` field. Ids without a base are malformed. Bounds are 1 MiB / 10,000 entries.
2. Environments carry only `{id?,name}`. Protection is project-settings state; note and display order are cosmetic.
3. `project_schema_revisions.revision` is the one definitions counter. It includes metadata, environment topology, and groups; reorder does not.
4. A plan pins canonical digest, schema revision, every environment's current published value revision (0 when never published), the environment id set, and protected environment ids/names. Any movement or protected-set growth refuses with re-export/re-plan guidance.
5. A based bundle whose base is not current is refused at plan. Check still reports `db_ahead` or `diverged`; no override exists.
6. Matching is id first, then name, independently per kind, with final-state validation. Swaps work; stale ids and duplicate bindings/final names refuse.
7. A base means desired state and omissions delete. No base means additive: creates and unchanged name matches only; modifications refuse; `allow_delete` is invalid.
8. Plans persist for 24h, at most 20 open per project. Applied rows remain as provenance. Apply is atomic, reauthorizes publication per final environment, bumps once, and never retries/merges stale input.
9. `definitions_source` defaults to `db`. In `git`, direct definition edits refuse with the exact ui-spec sentence: ``Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`.`` Apply remains allowed. Environment reorder and folder create/rename/delete are frozen too, even though bundles cannot express them: they are still definitions-edit acts. The consequence is that Git mode intentionally has no route for those cosmetic changes until the project returns to DB mode.
10. Values import keeps `definitions_revision` informational. Definitions apply does not set run-manifest `phase_completion.applied`; no manifest-plan linkage exists.
11. The importer emits the canonical additive bundle type directly: no ids/base/project, no environments/groups, and `none` presence for both rules; artifact name remains `definitions-bundle.json`.
12. `definitions scaffold` is not built and has no ticket in this slice.
13. Direct `Environments.Delete` retains its existing value-clearing semantics. The unconditional live-occurrence refusal exists only on definitions apply.
14. Check uses its ADR-locked 0/1/2 contract despite 1/2 meaning internal/usage globally. This exception is isolated to check and stated in help.

Additional implementation pins: digest has no `sha256:` prefix; protected pins persist id+plan-time name so identity is rename-safe and GET returns stable impact text; expiry is inclusive; topology is checked before schema revision; metadata no-ops do not bump; provenance fields are printable, at most 256 bytes, and labels containing bearer-shaped runs refuse; reveal-denied apply preserves its authorization sentinel but carries SafeDetail naming the plan-previewed key. The classification-aware declaration validator lives once in `internal/schema`; bundle parse calls it because each bundle key carries its classification, and direct key ingresses call the same helper. No-op apply mirrors identical declaration updates: it succeeds with the current revision and no plan stamp, audit, revision bump, publication, or snapshot.

## Test map

| Concern | Primary proof |
|---|---|
| Parse/encode/digest/match/drift | `internal/definitions/*_test.go` |
| Importer canonical additive bundle and emitted bytes | `internal/importer/plan_test.go` + `internal/cli/importer_internal_test.go` |
| Plan persistence and settings/source | store package tests + definitions E2E |
| Pins, deletion, reveal, atomic final-state apply | definitions service tests + definitions E2E |
| Status/body/raw bytes/nonexistence | `internal/server/contract_test.go` |
| Help, usage, outputs, exits, safe file/digest | `internal/cli/golden_test.go` + definitions fixtures |
| Formula/class/audit closure | focused isolation contract/invariant tests |
| Both-engine workflow and refusal rollback | `TestDefinitionsSQLite`, `TestDefinitionsPostgres` |

## Web surface and known gaps

- The project settings UI implements the `definitions_source` selector, the persistent Git-mode banner, last-apply provenance labels, and Playwright coverage in `web/e2e/flows/settings.spec.ts`.
- No definitions-authoring UI exists anywhere in the repository. Git-mode read-only behavior is therefore carried by the settings surface plus server-side guard refusals on every existing key/group/environment/folder mutation route.
- The S3 closure registry proves those existing router surfaces are guarded, but cannot flag a future authoring surface that is added without being registered. That is a deliberate gate-blindness to keep visible in review.
- `definitions scaffold` is unbuilt and unticketed.
- Run-manifest `phase_completion.applied` remains false; manifest-to-plan linkage is unticketed.
- Direct environment deletion still clears live values; only definitions apply requires explicit emptying.

## Open questions / dispositions

1. Human disposition needed: keep the check-specific 0/1/2 exception or reconcile the global closed exit taxonomy.
2. Human disposition needed: extend the live-value refusal to direct `Environments.Delete`, or retain the current distinction.
3. Human disposition needed: ticket `definitions scaffold`, or remove it from future-facing documentation.
4. Human disposition needed: define whether/how a definitions plan/apply links to run-manifest `phase_completion.applied`.

## Implemented web contract

Project settings calls `GET /definitions/settings` and `PUT /definitions/settings` with `{definitions_source:"db"|"git"}`. The read may include:

```json
{"definitions_source":"git","last_apply":{"plan_id":"dpl_…","applied_at":"…","applied_by":"usr_…","commit":"…","ref":"…","actor":"…","revision":42}}
```

`commit`, `ref`, `actor`, and `last_apply` are optional. The selector is a project-settings act, not a definitions-edit act. After switching to Git, direct key/group/folder/environment definition writes answer conflict with the exact SafeDetail above; show that detail verbatim and render those editors read-only. Values and environment policy controls remain writable according to their own permissions. A definitions apply remains the one admitted definition write and refreshes `last_apply`.

There is no browser plan/apply or authoring surface. If one is added, consume the contract shapes directly: check returns `state/base_revision?/current_revision/differences`; plan returns id/digest/base/current/additive/expiry/protected environments/diff/deletion flag/reveal-required; apply sends explicit `allow_delete` plus optional provenance and returns revision/published environments/plan id. Render `key_deletions[].live_in` and `env_deletions[].occurrences` before enabling deletion acknowledgement.

## Folded main-CI repair (#63 compose-demo)

Main run 32332585828 exposed three #63 compose-demo defects while PR #179 carried #70. Compose 2.38.2 omits resolved `env_file` from config JSON, so doctor now falls back to the structurally verified source path plus Docker's resolved stamp-label value and emits a dedicated warning if that proof is unavailable. The demo now validates the golden `check` field and admits only the exact environmental severity pairs. The changed-path classifier explicitly schedules compose-demo for its compose/run implementation, script, and demo-fixture surfaces; the existing unknown-path all-jobs fallback that scheduled PR #179 remains fail-closed.

## Verification record

- P1/P2/P3/P4: definitions, service, store, API/server/app/authz/audit touched-package suites passed; catalogue conformance passed SQLite and PostgreSQL; generated TypeScript client generate/typecheck/test passed 4/4.
- `go test ./internal/cli -count=1` — pass.
- Focused route/class/formula/audit/registry invariants — pass; no formula fixture repin required.
- `timeout 600 env GOCACHE=/tmp/hikyo70-go-cache HIKYO_TEST_POSTGRES_DSN=postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_70 go test ./internal/isolation/ -run TestDefinitions -count=1` — pass, both engines.
- `go test ./internal/definitions ./internal/service ./internal/store/... ./api ./internal/server ./internal/app ./internal/authz ./internal/audit ./internal/cli -count=1` — pass.
- `GOCACHE=/tmp/hikyo70-go-cache go test ./internal/importer ./internal/definitions ./internal/cli -count=1` — pass after importer reconciliation; no PostgreSQL leg required by these packages.
- `go build ./...` and `go vet ./...` — pass.
- `gofmt -l .` — empty; `git diff --check` — pass; both isolation JSON fixtures parse with `jq empty`.

## Review record

R1 contained 13 findings. Confirmed C1-C8 are fixed: secret value-literal declaration enforcement at every ingress; final-state grammar/caps; rename/create ordering; constituent apply audits; pending-draft discard; no-op short-circuit; substring provenance filtering; and stored-digest recomputation. Standards S1-S9 are fixed, including one reveal predicate and the ui-spec sentence as the normative Git-mode text.

Rejected findings and binding rationale:

- R-a protected ceremony: the immutable plan field is the permission ADR's explicit machine confirmation; publish fan-out has no additional ceremony on any schema path.
- R-b environment-delete publish authorization: topology deletion is definitions-edit / `OpEnvDelete`; the deleted environment is not republished.
- R-c per-environment reveal: apply uses the same reveal gate, operations, and scope as direct key paths; widening would change the specification.
- R-d sealer outside the transaction: `prepareSchemaPublish` follows the documented SQLite deadlock-avoidance pattern shared by every schema path.

Open question R-e: add cross-engine canonical golden vectors when a second producer exists. Go is currently the only canonical encoder/digest producer; the TypeScript client does not re-encode bundles.

Cross-model review (Codex gpt-5.6-sol, high effort, 3-round cap): R1 13 findings (0 critical / 5 high / 7 medium / 1 low) — dispositioned as above. R2 verified 16 of 17 fixes; C7 (provenance token filtering) was incomplete because the generic 32-char run misses short-bodied canonical tokens — closed by also refusing any label `audit.RedactTokens` would alter. R3: CLEAN. In-session Standards and Spec axes ran in parallel with R1; the Spec axis confirmed the matching algorithm, pin re-check, unconditional environment-deletion refusal, git-mode guard coverage, and check's 0/1/2 exit contract against the ADR text.

Verification: TDD seams, focused invariants, both-engine E2E, full dual-engine `go test ./...` (38 packages, PG leg on a fresh per-issue database), web typecheck/vitest/build, and the settings Playwright flow (40 passed; one org-deletion disarm timing flake under parallel full-suite load passed 8/8 on isolated re-runs).
