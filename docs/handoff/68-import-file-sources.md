# #68 — Import framework + file sources (K8s, SOPS, Infisical)

Parent: #41. Owning ADR: `docs/adr/import-paths.md`, as amended by
`docs/adr/flat-model.md` (§ Ripple register, import-paths entry: buckets
collapse to `new | set`). Serializations: `docs/spec/api-cli-spellings.md` § 3.

Phase 1 authors artifacts and stops. Phase 2 is `hikyo values import`. There is
no flag that turns two-phase off, and no code path in this slice that writes to
the server from `hikyo import`.

## What exists now

### `internal/importer` — the connector framework (client-local, pure library)

| File | What it owns |
|---|---|
| `importer.go` | The bounds (one block), the `Code`/`Error` refusal vocabulary, `Budget`, the `Connector` interface, the compile-time connector registry, `Run` |
| `names.go` | The rename transform against the canonical key grammar, the near-miss advisory, `canonicalJSON` |
| `spawn.go` | The shared sanitized subprocess scope |
| `k8s.go`, `sops.go`, `infisical.go` | The three file connectors |
| `artifacts.go` | `mapping.json`, `run-manifest.json`, the additive definitions bundle, the values file — serialization and strict parsing |
| `plan.go` | Phase 1's whole decision surface: rename → collide → classify → type → bucket → trim preflight → author |

`Connector` exposes `Name()` and `Read()` and nothing else. There is no write
operation to implement, which is what makes "a connector cannot mutate a foreign
store" structural rather than a per-connector courtesy.

### Server side

| Piece | Where |
|---|---|
| `import.presence` operation — phase 1's read, `read@project` (minimal form of the ADR's split formula — see § The precondition authorizes the union), human-only, audited-none | `internal/authz/registry.go` |
| `value.import` operation — phase 2's batch write, `read@project ∧ edit(E) ∧ publish(E)`, human-only. The read atom is the security-gate finding: strict import's response (imported / skipped / rejected-by-name) is a presence-and-catalogue read even without a manifest, and a write-only editor (edit ∧ publish, no read) must not enumerate declarations or set/absent state by probing the verb — write-only rotation keeps `values set` | same |
| `humanOnly` on the registry row + `machineRefused` at the chokepoint | `internal/authz/registry.go`, `authorize.go` |
| Occurrence token minting (HMAC, scoped) | `internal/crypto/token.go` |
| The occurrence canonical encoding | `internal/delivery/delivery.go` |
| `Values.Occurrences` / `Values.Import` | `internal/service/import.go` |
| `POST …/values/occurrences`, `POST …/values/import` | `api/openapi.yaml`, `internal/server/values.go` |
| `value.imported` audit event | `internal/audit/registry.go` |

### CLI

`hikyo import` (new top-level verb) and `hikyo values import` (new subverb),
both in `internal/cli/importer.go`.

`import` moved out of `app.ClientVerbs` into `cli.verbHandlers`, and
`cli:import` flipped from `ClassStub` to `ClassTenant` in the same change — the
totality invariant refuses a stub verb that already has operations, which is
exactly the "implementation rides in on a stale class" case it exists to catch.

One flag spelling deviates from every other verb, deliberately and per the
spellings spec: on `import` the TARGET environment is `--environment`, because
`--env <slug>` names the SOURCE-side slice inside an Infisical export. `import`
therefore does not use `parseCommon`'s flag set. Flag mode requires both
`--project` and `--environment` on the invocation; it never targets a
committable migration from `HIKYO_*`, `.hikyo.json`, or a named context. Replay
continues to take both values from its reviewed mapping.

**Replay is refused rather than half-honoured.** `--mapping` with an explicit
`--project`/`--environment` is a usage error (the template is a record, not a
suggestion), and a template mapping more than one environment is refused by name
— replaying only its first would import a fraction of what the human reviewed
and say nothing about the rest. Multi-environment sessions are the wizard's,
which is unticketed. The template's recorded `folders` rows are **honoured, not
recomputed**; a source path the template never saw is a loud refusal.

**Replay needs two things the template does not carry.** `mapping.json` records
the project and the target environment (which override the command line — a
recorded artifact is not a suggestion) and the source's file *digest*, not its
path. So `--mapping` still needs `--file <path>` to supply the export, and
`--org` (or a context, or `HIKYO_ORG`) to resolve the org the project sits in. A
digest that differs from the recorded one is **not** an error: it is recorded in
the run manifest, which is exactly the "a replay against a moved source is
visible as a different run manifest, not silently the same reviewed run" rule.

## Decisions taken

### Occurrence tokens: keyed, scoped, computed — no migration

A token is `HMAC-SHA256(scopedOccurrenceKey(org, project, env), encoding)`,
base64url, `v1:`-prefixed, mirroring `ChangeToken`/`DeliveryCursor` under its
own HKDF label (`hikyo/import-occurrence/v1`).

**Two encodings, discriminated by a field, not by an absence:**

| Case | Encoding |
|---|---|
| declared at phase 1 | `(v1, "declared", name, key_id, entry_id-or-"", classification, declaration digest)` |
| undeclared at phase 1 | `(v1, "undeclared", name, intended_classification, intended_type)` |

**Every planned key gets a token, declared or not.** The undeclared ones are
exactly the keys an import is about to create; a manifest row without a
server-minted token would be the one row an edited manifest could forge freely.
This is why the presence read takes each candidate name plus the exact
classification and primitive type the emitted bundle line declares.

Consequences, each deliberate:

- **No new table, no migration, no sqlc change.** The token is recomputed on
  verification and compared; there is nothing to store and nothing to expire.
- `entry_id` is the value row id, which is minted per write and never reused
  (encryption ADR forbids reuse), so `set → set` with a changed value moves the
  token. That is the case a bucket label cannot catch, and it is asserted.
- Including the declaration digest and classification makes "a changed
  declaration rejects that key" fall out of the same comparison — per key, which
  is what a project-wide revision could never do.
- Fabricated ≡ stale by construction: both recompute to a mismatch, and there is
  **one** refusal wording (`movedTokenRefusal`). Asserted by comparing the two
  error strings.

### Phase-2 verification is PER KEY, and the definitions revision is not compared

A key the manifest reviewed passes if either holds:

- it was **declared** at review and its token still recomputes to the same value
  (value occurrence, classification and declaration digest, in one comparison);
- it was **undeclared** at review, the current declaration has exactly the
  intended classification and type bound into the token, and the value is
  **still absent**. Applying this run's own bundle is the expected transition;
  reclassification, a different type, or a value appearing is movement and
  rejects that key by name with the same fabricated/stale wording.

The manifest's `definitions_revision` is **recorded, never compared**. Comparing
it globally would refuse every run that followed the documented flow: applying
the bundle bumps the revision, so `plan → apply → import` would be a guaranteed
`ErrConflict` while the CLI's own next-steps output directed users straight into
it. Staleness detection is per key, inside the token. The field stays in the
serialization (it is pinned by the spellings spec) as an informational record.
**#70: keep it informational** — a per-key declaration pin would duplicate what
the token already covers.

The cross-engine E2E now runs the documented flow with **no re-plan**: phase 1
→ apply the bundle it authored → `values import` against **the original
manifest**. That is the test that would have caught the global-revision bug.

### Any movement aborts the whole run

The ADR says movement "rejects THOSE KEYS BY NAME". This implementation rejects
the whole run **naming exactly the moved keys**, and writes nothing. Reasoning:
the run is one transaction, a partially applied migration whose manifest no
longer describes it is worse than one the human re-runs, and re-running phase 1
is cheap. **Flagged for the reviewer** as an interpretation, not a reading the
ADR forces.

### The precondition authorizes the union, always

The ADR's split formula is project-scoped structure read ∧ read(E) per
consulted environment. Grants inherit downward, so `read@project` subsumes
`read@environment` on the same chain; the registry carries the minimal
equivalent, `read@project` alone — the env conjunct is never independently
deniable, and the formula-matrix invariant refuses dead conjuncts. An
environment-only reader still fails it, which keeps the response's
project-schema facts (declared types, catalogue revision, token movement) off
the environment-scoped read surface. Phase 2
re-evaluates it for **the manifest's environments AND the import's own
target**, always, before any token is compared. Authorizing only the
caller-supplied list let a caller omit the target, present a captured token, and
read the match/reject answer as a one-bit oracle on state they may not read. The
target is authorized because it *is* the target. Regression test:
`scenarioImportPreconditionOracle`.

### Incompatible existing declarations are refused at phase 1, by name

An existing declaration whose **classification** or **declared type** disagrees
with what the import would declare is a refusal listing every offender — not a
stderr warning the run steps past on its way to writing a secret-store value
into a `config` key that every plain-`read` holder can see. Import never
modifies a declaration, so the conflict is the human's to resolve. The declared
type is the same textual expression `keys show` renders; an imported primitive
is compatible with an `any_of` only when it is one of the union's branches. An
already-declared key gets no fabricated `types[]` row: only a type the template
author actually supplied is recorded, and it must satisfy the same rule.

The escape hatch is the mapping template: a template line declaring that key's
existing classification/type **is** the ADR's "resolved by hand" consent —
recorded, reviewable, committable. `declared_type` is wired end to end for this;
it is no longer dead.

### Bundle format (new, minimal, versioned) — coordination point for #70

No bundle format exists in the tree. This ticket defines a minimal one in
`internal/importer/artifacts.go`:

```json
{
  "format_version": 1,
  "project": "<project-id>",
  "keys": [
    {"name": "DB_URL", "folder_path": "db", "classification": "secret",
     "declaration": {"rule": {"type": "string"}}}
  ]
}
```

Names are the portable handles. There is **no base revision and no `base`
field** — that absence *is* the additive semantics (source-of-truth ADR
§ Additive bundles; the flat-model ADR deleted `base` outright). **#70 owns the
real format**; when it lands, reconcile these two and delete whichever loses.
`definitions plan|apply` is not built here — this ticket only EMITS the
artifact, and `cli:definitions` stays `ClassStub`.

### Values file (new, minimal, versioned)

`{"format_version":1,"project":…,"environment":…,"entries":[{"key":…,"value":…}]}`.
Written through `disclose.Emit`'s file leg — the repo's existing secret-file
discipline (dirfd-parent-checked, `O_EXCL`, `0600`, umask-independent). Nothing
was reimplemented.

### Infisical format pin

Exporter command, pinned:

```
infisical export --format=json --env <slug> --path <folder-path>
```

Minimum version **v0.43.0**; shape read off Infisical/cli v0.43.121
(`packages/cmd/export.go` `formatAsJson` over `packages/models/cli.go`
`SingleEnvironmentVariable`) and fixture-pinned in
`internal/importer/testdata/infisical-export.json`. A JSON **array** of objects
carrying `key`, `value`, `type` (`shared|personal`), `secretPath`, `_id`.

- Not an array → refused, pointed at the `.env` scaffold path.
- Entry without `secretPath` → refused (no folder provenance).
- Entry without `type` → refused (personal overrides already resolved).
- `type: "personal"` → skipped and listed by name.

**Deviation worth reviewing:** the pinned export carries folder provenance per
entry but **no environment field**. The ADR asks for "folder/env provenance". The
env slug is therefore operator-supplied (`--env`, required for this connector)
and recorded in the template scope and the manifest's source identity, rather
than read out of the file. The alternative — pinning the raw `/api/v3/secrets/raw`
response, which does carry `environment` — was rejected because the ADR calls for
an *exporter command*, and `curl` is not one. Also note `infisical export` is
**not recursive**: it returns the secrets at `--path`, so a multi-folder
migration is several runs.

### SOPS

`decrypt.DataWithFormat` from the library's stable `decrypt` package, YAML and
JSON only (dotenv routes to the `.env` scaffold path; INI/binary refused).
Plaintext hints are read off the file **at rest** — a scalar without the `ENC[`
marker was never encrypted — which needs no reach into library internals. Nested
**maps** become folder levels; **arrays and non-map structures** become `json`
leaves through `canonicalJSON`. Fixture-pinned:
`["https://a.example","https://b.example"]` — sorted keys, no spaces, HTML
escaping off.

After decryption, SOPS plaintext is parsed into a `yaml.Node` and charged with
the Kubernetes `chargeNode` walk before `Decode` materializes maps and slices.
Aliases recursively charge their targets; `sops-alias-bomb.yaml` pins the named
decoded-bytes refusal on this post-decryption path.

**Library caveat, recorded:** the GPG key source `exec`s `gpg` *inside* the
library, with no hook for the child's environment. The shared sanitized path is
therefore `importer.WithSanitized`, a **scope** that strips `HIKYO_*` from this
process for the duration of the call, restores it afterwards (including on
panic), and serializes under a mutex. Blunt, and right here: `import` is
client-local, single-purpose and short-lived, and a scrub covering children we
do not spawn ourselves is worth more than a builder covering only the ones we do.
Asserted on a real child process in
`internal/importer/connector_test.go:TestSubprocessEnvironmentIsSanitizedAtTheSharedPath`,
which also asserts `SOPS_AGE_KEY` **survives** — a blunter scrub would break
decryption.

### Error sanitization: names escaped, enum-shaped fields never echoed

Two rules, because foreign structural fields and foreign key names need
different treatment:

- **Enum-shaped fields are refused without echoing the value.** A hostile
  manifest can put a live token, or `\x1b[2J\x1b]0;pwned\x07`, where a `kind`
  or an Infisical `type` belongs. The refusal names the *field* and the expected
  value: "the document's `kind` is not `Secret`".
- **Names must be shown** (the ADR requires errors to name keys), so they go
  through `quoteName` — Go quoting escapes control bytes, DEL and non-ASCII, and
  the result is length-capped at `MaxShownNameBytes`. That closes terminal-control
  injection into an operator's stderr and into the log that keeps it. The same
  renderer is mandatory on success output, including rename sources and
  Infisical personal-override skip lists; Kubernetes error locations use it
  instead of uncapped `%q`.

Fixtures: `k8s-hostile-kind.yaml`, `k8s-hostile-name.yaml`,
`infisical-hostile-type.json`.

### Kubernetes

`gopkg.in/yaml.v3` only; **no client-go**. `data` base64-decoded, then
`stringData` overlaid, stringData wins (admission semantics). Documents are
parsed to a `yaml.Node` first so duplicate mapping keys get their own code
rather than a string match on someone else's message — and because
`node.Decode` **echoes content** on a type mismatch
(`cannot unmarshal !!str \`sk_live...\``), which is the empirical reason every
parser error in this package is dropped rather than wrapped. A single-Secret
import targets the environment root.

## Bounds chosen (→ ops catalogue)

These are in one block at the top of `internal/importer/importer.go` and should
join `docs/spec/ops-catalogue.md`'s composable-maxima catalogue.

| Bound | Value | Why |
|---|---|---|
| `MaxFileBytes` | 4 MiB | Per export file, checked at the interface before any connector runs |
| `MaxDecodedBytes` | 16 MiB | Expansion **after** decoding — base64, YAML aliases, a decrypted tree. The decompression-bomb class |
| `MaxRecords` | 5000 | Charged while decoding; `schema.MaxKeysPerProject` is 1000, with room for a multi-Secret manifest |
| `MaxDepth` | 32 | Checked while descending, before the record count can be reached |
| `MaxValueBytes` | `schema.MaxValueBytes` (64 KiB) | Reused, not reinvented: importing something the value engine would then refuse is a failure found at the wrong end |
| `RunDeadline` | 60s | Whole run, covering decryption (which may contact a KMS or run gpg). Enforced by running the non-context-aware `decrypt.DataWithFormat` in a goroutine and selecting on ctx |
| `MaxShownNameBytes` | 128 | How much of a foreign NAME any message renders, after quoting |
| `MaxImportCandidates` | 5000 | How many candidate names one presence read may ask the server to mint tokens for |

**Where the bounds run matters as much as their values:**

- exports, mappings, run manifests, and values files all use one bounded reader:
  it refuses non-regular file modes before opening, then uses a descriptor
  `stat` plus `io.LimitReader(MaxFileBytes+1)`, so the cap is checked *before*
  the bytes are resident and a growing file still cannot blow memory;
- the decoded-bytes cap is charged over the parsed **node graph** before
  `Decode` materializes anything. YAML alias expansion happens during `Decode`,
  so a post-hoc length check has already allocated the bomb. Fixture:
  `k8s-alias-bomb.yaml` and post-decryption `sops-alias-bomb.yaml`; the K8s test
  also asserts that total allocation stayed under 4× the cap;
- every record is charged **before** the type branch, so an Infisical export of
  a million personal overrides cannot walk past the record cap by being skipped.

## New dependency

`github.com/getsops/sops/v3 v3.13.3`, approved by the ticket, confined to
`internal/importer` by a new allowlist in `internal/boundary/boundary_test.go`.

**Cost worth a reviewer's eye:** it pulls **823 packages** into the build,
including every KMS backend (AWS, GCP, Azure, HashiCorp Vault) plus
`urfave/cli` and the MongoDB driver, and `go get` **upgraded existing transitive
deps** (`logrus`, `json-iterator`, `google.golang.org/api`, `genproto`,
`otelgrpc`, `golang.org/x/time`, `gopkg.in/ini.v1`). Everything builds and the
full suite passes, but this is a real size increase in a single multicall binary
that also targets the ops spec's Pi-4 floor. Narrowing it is not cheap: the
sops store constructs every master-key type while parsing metadata, so there is
no import path that reaches age/GPG without reaching the cloud backends.

## Test map

| Suite | File | Covers |
|---|---|---|
| Connector fixtures | `internal/importer/connector_test.go` | (a) true-positive mapping per source, (b) adversarial parser fixtures (wrong kind, duplicate key, binary value, malformed), (c) hostile-error sanitization asserted against the value bytes that produced the refusal, (d) every bound fails loud naming itself, (e) the shared sanitized spawn path, on a real child process |
| Plan / grammar / artifacts | `internal/importer/plan_test.go` | Valid names byte-preserved; the documented transform; hard stops; near-miss; `new \| set` buckets; enumerated overwrite; secret-by-default; template downgrades and types; renames surfaced and recorded; post-transform collision; trim preflight; single-Secret root targeting; existing declarations not re-declared; template/manifest strict round-trip and version-mismatch refusal |
| Human-only | `internal/authz/authz_test.go` | The chokepoint predicate: machines refused, humans not, local host authority exempt, per-operation not global |
| Cross-engine (sqlite **and** postgres) | `internal/conformance/import_test.go` | Phase-1 presence + token movement (incl. `set → set` with a changed value); phase-2 strictness, skip-by-default, enumerated overwrite; imported values materialized into the committed snapshot; **phase-2 replay against moved state rejects by occurrence token, naming the key**; fabricated token indistinguishable from stale; definitions-revision mismatch; per-source fixture E2E for **all three** connectors (k8s, infisical, sops) with the collision, rename, typing and classification matrices — the sops leg is also the only E2E that decrypts through `WithSanitized` and asserts the plaintext hint downgrades nothing |
| Security regressions | `internal/importer/connector_test.go`, `internal/conformance/import_test.go` | Oracle closure (precondition authorizes the union); per-file bound before the bytes are resident; alias bomb refused at the named bound with allocation asserted; hostile `kind`/`type`/name never echoed; personal overrides charged before they are skipped; run deadline interrupts decryption |
| Golden CLI | `internal/cli/golden_test.go` + `testdata/` | `help.txt`, `exit-codes.txt` — including `import` with no source and no terminal being a hard error rather than a hung prompt — plus `-o json` shape fixtures for the two new response types (`value-occurrences-json.json`, `value-import-json.json`) |
| Audit | `internal/isolation/audit_e2e_test.go` | `value.imported` has a real emitter; `cli:import` exemption pinned in `testdata/audited_exemptions.json` |
| Registry pins | `internal/isolation/testdata/operation_formulas.json` | Both new operations' formulas |

Commands:

```bash
go build ./... && go vet ./...
go test ./internal/importer/ ./internal/authz/ ./internal/cli/
HIKYO_TEST_POSTGRES_DSN='postgres://…' go test ./internal/conformance/ ./internal/isolation/
```

## Coordination notes

### #69 (live modes: kubeconfig, Vault HTTP; Vault/OpenBao entirely)

- Add connectors to the `connectors` map literal in `importer.go`; the bounds,
  the rename transform, the canonical JSON, the artifact serializations and the
  plan are already shared and need no change.
- `Input` will need live-mode selectors (`--namespace`/`--name`,
  `--mount`/`--path`/`--kv-version`). Today it carries `Path`, `Data`, `EnvSlug`.
  `Scope` in `mapping.json` already has the k8s and vault-shaped fields the spec
  names.
- **Per-request and page/request-count caps do not exist yet** — they are
  live-mode bounds and were deliberately not invented here. The `Budget` type is
  where they go.
- `WithSanitized` already covers kube exec plugins and Vault token helpers.
- Vault's pinned JSON Lines capture format is unimplemented.

### #70 (`definitions plan|apply`)

- **Reconcile the bundle format** (above). This one is deliberately minimal and
  is flagged as provisional.
- `cli:definitions` is still `ClassStub`; flipping it is #70's job, in the same
  change that registers its operations.
- The `--out-dir` artifact names are fixed: `definitions-bundle.json`,
  `mapping.json`, `run-manifest.json`, `values-<env-id>.json`.

### #51 (publish pipeline / drafts / snapshots) — integrated

After #51 landed, `values import` retained its immediate, atomic bulk-write
contract and now calls the shared `republish` pipeline once after all imported
cells land. Validation, immutable snapshot creation, revision allocation,
change-token derivation and `revision.published` therefore commit in the same
transaction as the imported cells. A fully skipped run creates no revision.
The original audit shape remains: `value.set` per key plus `value.imported` per
run, with the shared revision event added by materialization.

### PR #111 post-merge-hardening

- Phase 1 refuses to author a values file larger than the 4 MiB cap phase 2
  accepts; the refusal happens before any artifact is created.
- Values files bind both project and environment, including imports without a
  manifest. Mapping and manifest environment rows may not be empty.
- Reviewed artifacts and Infisical exports reject exact and case-variant JSON
  duplicate members before struct decoding, preventing last-value-wins
  retargeting or provenance changes.

## Not built (and why)

- **The wizard.** Out of scope, and **unticketed** — nothing tracks it today.
  `hikyo import` on a TTY with no source arguments refuses by name, pointing at
  flag mode. All nine wizard interaction states in the spellings spec are
  unimplemented.
- **Environment creation from a plan.** Flag mode addresses an environment by id
  that must already resolve for the presence read to have happened; the
  template's `environments[].create` is serialized and always `false`.
- **Cross-environment reconciliation.** A wizard concern (one canonical
  identity/type/classification project-wide across a fan-out); flag mode targets
  exactly one `(project, environment)`, so it cannot arise.
- **Type suggestions.** A wizard affordance applied only on human accept. Flag
  mode declares `string` with NO exception, including for a leaf that arrived as
  a serialized structure: declaring it `json` from its first import would be the
  silent tightening the ADR rejects — the key refuses a plain string the day
  someone sets one, under a constraint nobody declared. A canonical-JSON value
  under a `string` declaration is perfectly valid. `Record.Type` stays the
  connector-level fact (the future wizard's suggestion input); the template is
  what declares `json`. Asserted in both the plan tests and the cross-engine
  E2E.
- **`phase_completion.applied`.** A successful `values import --manifest` now
  rewrites the manifest with `imported[<env>] = true`, so a resumed migration
  knows where it stopped. `applied` stays false: that transition belongs to
  `definitions apply` (#70), and claiming it here would be a marker for an act
  nobody performed. A write-back failure is reported on stderr and does not fail
  the command — the import has committed, and a non-zero exit would tell a
  script the write did not happen when it did. The rewrite preserves the
  manifest's permissions and renames a same-directory, exclusively-created temp
  file over the entry, so symlinks are replaced rather than followed and a temp
  write failure leaves the reviewed artifact untouched.
- **Artifact JSON is single-valued and duplicate-free.** Strict parsing rejects
  any second top-level value and checks object members at every depth before
  decoding, naming a repeated member instead of accepting last-one-wins JSON.

## Open questions for the reviewer

1. **Whole-run abort vs per-key rejection** on token movement (above). Stricter
   than the ADR's wording; is that the right reading?
1a. **The presence route is a POST.** It carries a body (`candidates`) because the run
   must ask about names the project does not declare yet. It is a read in every
   other sense: `read@project`, audited-none, no writes. Route:
   `POST …/values/occurrences`.
2. **The sops dependency's size** (823 packages, transitive upgrades). Acceptable
   for a self-hosted binary that also targets a Pi-4 floor?
3. **Infisical's missing env provenance** — operator-supplied `--env` recorded
   rather than read from the export. Correct pin, or should the raw-API envelope
   be pinned instead?
4. **Importing into an existing `config` declaration** is surfaced as a warning
   and proceeds (import does not mutate declarations, per the ADR). Should it
   instead hard-stop?
5. **`x-hikyo-artifacts` was already documentation-only** — no runtime human-only
   enforcement existed anywhere. This ticket added `humanOnly` to the operation
   registry and enforced it at the chokepoint, and extended
   `TestTenantRoutesDeclareForbiddenOnlyForMFA` to admit 403 for human-only
   operations alongside MFA-mandatory ones (both are post-grant refusals, same
   shape, same reasoning). The other human-only verbs the ADR names — `adopt`,
   `scaffold`, `login` — are unbuilt; when they land they should set the same
   flag.
