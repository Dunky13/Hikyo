# Wenv import & migration paths (ADR, locked 2026-08-06)

> **Amended by the flat-model ADR ([flat-model.md](./flat-model.md), 2026-08-06, [#40](https://github.com/Dunky13/wenv/issues/40), per the [oss-mechanics.md](./oss-mechanics.md) amendment procedure):** collision buckets collapse to `new | set` — the `inherited-set` and `masked` buckets are empty by construction and deleted; `--overwrite` applies to the enumerated `set` list; phase-1 presence queries return `set | absent`. Everything else stands. Detail in that ADR's ripple register.

Context: Wenv's adoption story begins on a box that already has secrets somewhere else — a K8s cluster full of native Secrets, a SOPS repo, an Infisical or Phase installation, a Vault or OpenBao KV tree. The source-of-truth ADR ([#13](https://github.com/Dunky13/wenv/issues/13), [source-of-truth.md](./source-of-truth.md)) settled `.env`-family onboarding (offline `scaffold` → review → `apply` → strict `values import`) and fixed the standing constraints every broader import inherits: **every import is a value-bearing import funnelling through the publish pipeline, never a Git sync**; `values import` is human-only with strict closed-schema semantics ([#13](https://github.com/Dunky13/wenv/issues/13), [#18](https://github.com/Dunky13/wenv/issues/18), restated in [api-cli-surface.md](./api-cli-surface.md)); and the CLI's context/trust model, output grammar and noun-verb taxonomy are fixed ([#25](https://github.com/Dunky13/wenv/issues/25)) — importers join that grammar, they do not invent one. This ADR fixes the per-source mapping of foreign secret stores onto Wenv's keys, classification and environments, the import machinery's shape, and the v1 in/out decision per source.

***Amends the API/CLI ADR ([#25](https://github.com/Dunky13/wenv/issues/25)), declared.*** That ADR's v1 verb taxonomy is closed with exactly one join point (the deployment-adapter verbs, [#28](https://github.com/Dunky13/wenv/issues/28)); this ADR amends the closed set rather than pretending a second join point already existed. The amendment, in full: (a) one new top-level human-only verb, **`import`**, joins the taxonomy under #25's existing grammar — context resolution, output rules and artifact-eligibility unchanged, no new output classes; (b) `import` joins the **human-only list** beside `adopt`, `scaffold`, `values import`, `login`; (c) `import` enters the **parity exemption list** as client-local by nature — it acts on local files and foreign stores from the box the CLI runs on, the same exemption class as `render`/`adopt`/`doctor`; (d) `values import` gains one **optional additive input**: an expected-state precondition consumed from the run manifest (§ *Binding phase 1 to phase 2*) — absent it, `values import` behaves exactly as locked. Nothing else in #25 moves; exact flag spellings remain delegated to the synthesis ([#27](https://github.com/Dunky13/wenv/issues/27)).

The amendment follows the locked-ADR amendment procedure ([oss-mechanics.md](./oss-mechanics.md) § Governance) in full: **#25's ticket is reopened for the record and re-closed with the amendment noted; the amendment is recorded in [api-cli-surface.md](./api-cli-surface.md) itself** (§ Declared amendments, added by this ADR's commit); and the adversarial cross-model review that locks this ADR covers the amendment text as part of its scope.

Granularity note: this is the wayfinding-level import ADR. It fixes the architecture (connector structure, two-phase invariant, entry modes, mapping artifacts), the trust rules for foreign sources, the mapping/classification/collision/rename semantics, the per-source structural mapping, and the v1 scope per source. Mechanism-level detail is delegated: exact flag spellings, wizard interaction states, the mapping-file and run-manifest serializations, and per-connector fixtures → the API/CLI spec at synthesis ([#27](https://github.com/Dunky13/wenv/issues/27)); concrete bound *values* for the connector resource limits fixed structurally here → the ops spec's composable-maxima catalogue ([ops-spec.md](./ops-spec.md)). Each delegated site MUST satisfy the constraints stated here.

## Architecture: a connector family, live and file modes both

Each supported source gets a **connector**: a reader that knows how to enumerate the source's structure and fetch its current values. Every connector operates in up to two modes:

- **File mode** — the connector parses an export the user produced with the source's own tooling, in a **format this ADR names per source** (§ *Per-source structural mapping*). No network contact with the source itself — with one disclosed exception: a SOPS file encrypted to a KMS or Vault Transit key contacts that key service to decrypt (§ *SOPS*), so file mode is offline only for age/GPG-encrypted material.
- **Live mode** — the connector contacts the source directly (kubeconfig, Vault HTTP API) and reads the same information over the wire. Live mode automates the export step and nothing else (§ *The two-phase invariant*).

*Rejected: file-only import* — the owner's call, taken deliberately: for sources whose API is a thin read (Vault/OpenBao KV) or whose client config is ambient and universal (kubeconfig), forcing an intermediate export file adds a plaintext artifact and a manual step without adding safety, since the same human runs both commands in the same session. File mode remains available everywhere live mode exists, for air-gapped migration and for users who prefer the artifact. *Rejected: server-side importers* (upload an export, the server maps it) — parsing foreign formats on the server widens the pre-freeze API surface and moves foreign plaintext handling into the trust core for zero UX gain; import stays client-side. *Rejected: a dedicated importer per source with its own grammar* — [#25](https://github.com/Dunky13/wenv/issues/25) forbids new grammar; connectors are modes of one verb.

**Connectors are ordinary internal implementation units behind an in-process Go interface with compile-time registration** — interface-shaped for testability and uniform bounds enforcement, **not an extension point**. The OSS-mechanics ADR ([oss-mechanics.md](./oss-mechanics.md)) fixes exactly two extension points (the deployment-adapter seam and ESO), and this ADR adds none: a new source is an in-tree code contribution shipped in a release, exactly like any other feature, with no stability promise attached to the internal interface (`internal/` is not a compatibility surface, [oss-mechanics.md](./oss-mechanics.md)).

**Connectors are strictly read-only against the source.** No connector ever writes to, deletes from, or mutates a foreign store — import is a read. This is an interface invariant, not a per-connector courtesy: the interface exposes no write operation to implement.

**Connector work is bounded.** Every connector enforces, uniformly at the interface: per-file and per-response size caps, a decoded-bytes cap (base64, YAML aliases, decompression — expansion bounded *after* decoding), record-count and tree-depth caps, per-request and whole-run deadlines, page/request-count caps for live traversal, and an aggregate cap across a multi-environment wizard session. Exceeding a bound fails loud, naming the bound. The concrete values join the ops spec's composable-maxima catalogue ([ops-spec.md](./ops-spec.md)); their existence and placement are fixed here — resource exhaustion must be impossible *before* a bundle exists, not just after.

**Every foreign byte is treated as secret from first read until classified.** Connector and parser errors are sanitized structurally: no raw response bodies, no YAML/JSON snippets, no URLs with embedded credentials, no value fragments — errors name keys, paths, bounds and codes, never content. Response bodies are size-capped before parsing; nothing value-bearing reaches logs, stderr or audit. Adversarial parser and hostile-provider-error fixtures are part of each connector's test surface (delegated to [#27](https://github.com/Dunky13/wenv/issues/27) with the other fixtures).

## The two-phase invariant

**Every import, in every mode, authors artifacts and stops.** Phase 1 — wizard, flags, or replay — produces:

- **one project-wide additive definitions bundle** per target project — exactly the artifact class the source-of-truth ADR fixed: create-only, refusing to modify declarations it was not computed against. One bundle, not one per environment: keys, types and classifications are **project-scoped** ([schema-model.md](./schema-model.md)); only presence varies by environment. A wizard session fanning out across environments must reconcile every key to **one canonical identity, type and classification** before emitting — two environments proposing incompatible declarations for one key is a conflict the wizard resolves interactively and flag mode fails on;
- one or more **values files** (per target environment), the material for `values import`;
- one **mapping template** and one **run manifest** (§ *Entry modes, the mapping template and the run manifest*).

Phase 2 is the existing surface: the human reviews, then **`definitions plan --file` → `definitions apply --plan`** publishes declarations under the plan's locked machinery — immutable plan, digest, freshness pins, impact preview, authorization recheck, protected-environment binding ([source-of-truth.md](./source-of-truth.md)) — and `values import` runs strict per environment. Undeclared keys are still rejected; the closed schema is not conceded on the import path — the largest imports are precisely the accumulated-typo case the closed schema exists to catch ([schema-model.md](./schema-model.md)).

*Rejected: one-shot live import with `--plan` preview* — a plan preview is ephemeral; it produces no PR-reviewable artifact, and it pushes classification decisions into an interactive prompt under migration pressure. One-shot saves a single command on an operation run once per source and costs the product's own review thesis. There is no flag that turns two-phase off.

**Phase 1's Wenv-side contact is read-only, and its authorization is stated, not implied.** The wizard and flag modes query the target project's structure — declared keys, environment list, folder tree, and per-key **presence state** in each target environment. The formula: structure reads carry the project-scoped `read` the member already holds; **presence reads require `read(E)` for every environment whose presence is consulted** — an environment the actor cannot read contributes no buckets and is not offered as a target. Presence means the three-state signal the inheritance and revision ADRs fix — `set` / `absent` / `masked` — as the write-presence class ([revision-model.md](./revision-model.md)): whether and how a key is set, never what it is. Phase 1 never requires `reveal`, never compares values, and never writes. The phase-1 read operations are registered in the tenant-isolation operation registry and probe-classified tenant-scoped like every other read ([tenant-isolation.md](./tenant-isolation.md)); phase 2 consumes its verbs' existing formulas unchanged.

## Entry modes, the mapping template and the run manifest

Three entry modes, one artifact chain:

- **Wizard** — `import` with no source arguments on a TTY. Walks the source's structure interactively, guides the target mapping (environments, folders, renames, classification, types), and may fan out across several target environments in one session — emitting the single project-wide bundle plus per-environment values files. For users who want to be guided.
- **Flag mode** — `import --from <source>` plus source-side selectors. Targets **exactly one (project, environment)** per invocation; the human slices the source with the connector's selectors (`--namespace`/`--name`, `--path` prefix, `--env` slug, a file path). For users who know their slice.
- **Replay** — `import --mapping <file>` re-runs a recorded mapping non-interactively.

`import` without a TTY and without `--from`/`--mapping` is a hard error, not a hung prompt.

Two recorded artifacts, deliberately distinct:

- **The mapping template** — the portable, declarative record of every *choice*: source scope, environment mapping, folder mapping, renames, classification decisions, type declarations, overwrite selections. Versioned (format version + connector contract version). Replayable against another source instance (dry-run on staging, replay against prod). **Names, paths, renames, types and classifications — never values.** Committable; it puts the choices themselves in the pull request beside the bundle they produced.
- **The run manifest** — the bound record of one *run*: template reference, non-secret source identity as far as the connector can state it (cluster/context name, `VAULT_ADDR` origin, export-file digest), **per-record source version identifiers where the source provides them** (K8s `resourceVersion`, Vault v2 `secret_version`), the target's immutable ids (project, environments, key ids where they exist), the definitions revision observed, the **per-(key, environment) occurrence token** observed (§ *Binding phase 1 to phase 2*), and a **phase-completion marker** recording how far the run got (authored / applied / imported per environment) so a resumed migration knows where it stopped. Versioned likewise. Also value-free and committable. A replay under a different kube context, a moved `VAULT_ADDR`, or a changed source version is visible as a different run manifest, not silently the same "reviewed" run.

Every mode emits both — the wizard is an authoring frontend for the template; flag mode records its effective template identically.

The values files are never committable: they follow the API/CLI ADR's secret-file discipline (dirfd-parent-checked `O_EXCL`, `0600`, never ordinary stdout), and phase 1 ends with the source-of-truth ADR's warning that source plaintext still sits on disk — extended here: the emitted values files do too, until `values import` completes and the user deletes them.

### Binding phase 1 to phase 2

Skip-by-default (§ *Collisions*) is only as good as the binding between the observation and the write: state observed at phase 1 can move before phase 2 runs — a key set in the meantime, by someone else, would be clobbered by a `values import` that "reviewed" it as `new`. So the run manifest is not documentation, it is a **precondition**, and it binds *occurrences*, not bucket labels:

- **Phase 1 records, per (key, environment), a server-minted opaque occurrence token** naming the exact resolved state observed — which value occurrence is in effect (and via which layer), or the specific absence/mask state. A bucket label cannot do this job: `set → set` with a changed value preserves the bucket, so a bucket-checked "reviewed overwrite" would still clobber the newer value. A value edit advances the occurrence; the token no longer matches.
- **Phase 2 verifies tokens inside the import's own authorized transaction**: the emitted `values import` invocation consumes the manifest (the optional additive input declared in this ADR's #25 amendment), and the server checks that the definitions revision and each written key's occurrence token still match. Any movement — a `new` key now set, a changed value, a changed declaration, a changed mask — **rejects those keys by name**, loud; overwrite and unmask consent bind to the exact reviewed occurrences and nothing that moved.
- **The precondition is not an oracle.** Before any token is checked, a manifest-carrying `values import` re-evaluates phase 1's read formula — `read(E)` for every environment the manifest names — in the same transaction, on top of the verb's own formula; a caller lacking it receives the plain authorization failure and no precondition result. And the tokens are server-minted and opaque: an edited or fabricated manifest cannot phrase a question about someone else's state that the server will answer — an unrecognized token is exactly as informative as a stale one.

Without a manifest, `values import` behaves exactly as locked — the precondition is what makes import's skip-by-default *true*, not a new default for the verb.

## Trust: ambient credentials, read-only, never persisted

Live-mode connectors authenticate to the foreign source with **the source's own ambient conventions and nothing else** — held in memory for the run, presented only to the configured source origin, **never persisted** by Wenv:

- **Kubernetes**: kubeconfig and its current (or `--context`-selected) context, including exec-plugin credential resolution — disclosed: an exec plugin is third-party code the connector runs.
- **Vault/OpenBao**: the documented client conventions, pinned to include the token helper, `VAULT_TOKEN`/`~/.vault-token`, `VAULT_ADDR`, `VAULT_NAMESPACE`, and the client TLS variables — and OpenBao's `BAO_*` equivalents, with the `BAO_*` form taking precedence when both are set, matching OpenBao's own client. The connector states which resolution it performed.
- **SOPS**: the ambient decryption keyring (age, GPG, KMS credentials) exactly as `sops -d` resolves it — disclosed: KMS/Transit-encrypted files contact the key service (§ *Architecture*).
- **Infisical** (when live mode ships, § *v1 scope*): the environment-variable token their tooling documents.

Rules bounding this:

1. **No foreign credential ever appears on argv.** The machine-identities ADR's argument transfers intact: argv is `ps`, `/proc`, shell history ([machine-identities.md](./machine-identities.md)). Connectors read credentials from the source's own files and environment variables only.
2. **Wenv never persists a foreign credential.** Nothing enters the local trust store or the context model — those remain Wenv-only artifacts ([api-cli-surface.md](./api-cli-surface.md)). There is no `import login`, no saved connection, no connector credential file.
3. **Credentials never travel off-origin.** A connector presents the credential only to the origin its ambient configuration names, over TLS as that source's client conventions require; **redirects are not followed with authentication attached** — a redirect elsewhere is a hard error naming the origins.
4. **Every subprocess a connector invokes runs in a sanitized environment.** Kube exec plugins, Vault/OpenBao token helpers, `gpg`/`age`/KMS helpers — any external program credential resolution or decryption pulls in — receives an environment stripped of Wenv credentials, contexts and trust material. A connector-interface invariant, not a per-connector courtesy: the subprocess spawn path is shared and the stripping happens there.
5. **Read-only operations only** (the interface invariant above, restated as a trust property: a migration tool that can write to the thing being migrated from is a migration tool that can destroy it).

*Rejected: Wenv-held connector credentials* — a new persistent artifact class holding foreign secrets, standing credential storage built for a one-shot operation. *Rejected: interactive prompt per run* — re-typing a Vault token per invocation pushes users to argv and shell-history workarounds, the leak class already closed.

The human running a migration already has these tools configured; Wenv adds zero foreign-credential-management surface.

## Targeting and hierarchy creation

The target **project must pre-exist**. Project creation mints the per-project DEK ([encryption-model.md](./encryption-model.md)) and is the explicit act of a `manage-projects` holder ([permission-model.md](./permission-model.md)) — an authority-laden step that stays one. Import never creates an org or a project.

Below the project, **the plan may create environments and folders**, as explicit reviewable lines (`create environment <name>`, folder paths implied by key declarations). The wizard states up front which environments a session will create. Created environments get stated defaults and are **never auto-protected** — protected flags, reveal windows and retention are policy acts made in project settings afterwards ([permission-model.md](./permission-model.md), app-chrome reference [#29](https://github.com/Dunky13/wenv/issues/29)).

*Rejected: nothing-above-folder* (pre-create environments by hand) — a wizard that ends with "run three create commands and come back" has failed its job, and an explicit plan line is exactly as reviewable as a manual command. *Rejected: import creates projects* — crosses into `manage-*` authority and DEK minting; a provisioning tool wearing an importer's clothes.

## Classification: source-signal, secret-leaning

The `.env` scaffold precedent — everything `config` plus `# TODO: classify` — exists because a `.env` carries no signal. Foreign sources do, and the failure modes are asymmetric: config mislabelled `secret` costs convenience (masking, reveal ceremony); a secret mislabelled `config` is **standing disclosure** to every holder of plain read. So the default is uniform and leans one way only:

**Every imported key defaults `secret`, from every source.** K8s Secrets, Vault/OpenBao KV, Infisical and Phase stored it as a secret — that is the signal. SOPS gets no carve-out: a plaintext leaf in a partially-encrypted file proves an *at-rest* policy choice, not that the value is safe for every future holder of plain `read` — so SOPS plaintext status is a **downgrade hint**, never a default. (This reverses the owner's initial lean — split on the file's `encrypted_regex` boundary — by this ADR's own rule that the dangerous direction is never automatic.)

**Downgrading secret→config is an explicit per-key act.** The wizard offers it with hints — name patterns (`_URL`, `_HOST`, `LOG_LEVEL`, …) and, for SOPS, the leaf's plaintext status; hints suggest, they never apply. Every downgrade is visible in the bundle diff and recorded in the mapping template. Flag mode performs no downgrades; the template can declare them.

*Rejected: all-`config`-plus-TODO uniformity* — inverts the safe default for sources that are literally secret stores; one skipped TODO is a disclosed secret. *Rejected: name-heuristic auto-classification* — guesses silently in both directions, and the dangerous direction has no floor. *Rejected: SOPS encryption-boundary split as default* — an automatic downgrade in the dangerous direction, per above.

## Collisions: declarations refuse, values skip

**Declarations** are already governed: the additive bundle creates, cannot delete, and **refuses to modify a declaration it was not computed against** ([source-of-truth.md](./source-of-truth.md)). A source key colliding with an existing declaration that is compatible is simply not re-declared; an incompatible existing declaration (type, classification) is a refusal in phase 2, resolved by hand — import does not mutate declarations.

**Values bucket on the *resolved* state of the target environment, never the local layer alone.** Inheritance means a locally-absent key can resolve to an inherited value or an inherited mask ([inheritance-model.md](./inheritance-model.md)); bucketing on the local layer would classify both as `new` and walk around the very consents this section exists to require. Four buckets, each carrying its provenance (which layer produced the resolved state) in the plan:

- **`new`** — the key resolves to nothing: no local value, no inherited value, no mask at any layer. Imported.
- **`locally-set`** — a value is set in the target environment itself: **skipped by default**, listed by name.
- **`inherited-set`** — the key resolves to a value from an ancestor layer. Writing here is not filling a gap — it **creates a local override that changes the environment's effective value**: skipped by default, and importing it requires the same explicit per-key consent as an overwrite, labelled with the layer it shadows.
- **`masked`** — the resolved state is a mask, local or inherited: a deliberate absence. **Skipped by default**, listed separately — writing here *removes a deliberate absence* and requires explicit per-key unmask-and-set intent, recorded like an overwrite.

**Overwriting is opt-in and explicit**: per-key in the wizard, `--overwrite` (applying to the enumerated `locally-set` list — the inherited and masked buckets always take per-key consent, never a bulk flag) in flag mode, recorded in the mapping template either way — and enforced against the run manifest's occurrence tokens (§ *Binding phase 1 to phase 2*), so consent binds to the exact reviewed occurrences. An overwrite lands as a normal publish revision — rollback exists ([revision-model.md](./revision-model.md)). Skip-by-default makes re-running an import naturally idempotent, and the manifest precondition is what makes "cannot silently clobber values edited in Wenv since review" a checked property rather than a hope.

*Rejected: overwrite-by-default* ("the source is the truth") — true on day one of a migration, false the day after; a re-run would revert every value edited in Wenv since. *Rejected: refuse-the-whole-import on any collision* — kills incremental migration and re-runs.

## Renames: valid names untouched, invalid names transformed loudly

The canonical key grammar is pinned where the schema ADR's lexical rules live, restated in the synthesis spec ([#27](https://github.com/Dunky13/wenv/issues/27)); this ADR fixes the import behavior *relative to it*:

- **A source name already valid under the grammar is preserved byte-for-byte.** No case-folding, no normalization of valid names — a transform applied to an already-valid name is a silent rename.
- **An invalid name goes through the connector's deterministic, documented transform** — uppercase mapping for lowercase ASCII; `-`, `.` and path separators → `_`; per-connector rules stated in its documentation. The transform covers the common classes only.
- **A name the transform cannot resolve** — spaces, `=`, non-ASCII, anything outside the documented mapping — is a **hard stop requiring an explicit rename** in the wizard or the mapping template. No guessing beyond the documented transform.
- **Every rename is surfaced.** The wizard shows `source-name → TARGET_NAME` per key for acceptance or edit; flag mode applies the same transform and the plan lists every rename. Nothing is renamed invisibly.
- **Post-transform collision is a hard error.** Two source keys landing on one target name stop the run; the human resolves it in the wizard or the template. No suffix-numbering, no last-wins.
- **All renames land in the mapping template**, making it the authoritative record of what came from where.
- **Near-miss warnings fire in the plan** against existing declared keys — importing `DB_PASWORD` where `DB_PASSWORD` is declared warns, the schema ADR's near-miss machinery applied at the import boundary.

*Rejected: refuse-by-name with no transform* — the deployment adapter's stance ([deployment-adapter.md](./deployment-adapter.md)), correct there because an outbound effective name is load-bearing routing; here it would make the wizard a rename data-entry form for two hundred lowercase Vault keys. *Rejected: silent auto-transform* — the invisible rename is the mis-route the review gate exists to catch; hence the valid-names-untouched and hard-stop rules above.

## Per-source structural mapping

Uniform rules first, from the schema ADR's lexical grammar:

- **Values must be valid UTF-8 with no NUL** — violating values (binary K8s Secret entries, binary SOPS leaves) are **refused by name**; refusal is per-key, not per-import.
- **Write-time trimming is preflighted.** The schema ADR trims edge whitespace on write; a foreign value the trim would alter (a trailing newline on a certificate, a padded token) would import *changed, silently*. The connector detects every such value and **refuses it by name unless explicitly acknowledged** — the acknowledgement recorded in the mapping template, so a reviewed import states which values were knowingly trimmed.
- **Non-scalar leaves** (objects/arrays in SOPS, non-string JSON field values in Vault) become **`json`-typed values via a deterministic conversion** — one canonical serialization, fixture-pinned at implementation ([#27](https://github.com/Dunky13/wenv/issues/27)). No byte-verbatim claim is made for material that arrives as a parsed tree rather than bytes; scalar leaves that arrive as strings are imported as their exact bytes (subject to the trim preflight).
- **Source history is never imported** — the connector reads the current/latest value only; Wenv's own revision history begins at the import publish. No source's version history maps onto the revision model's semantics, and pretending otherwise would fabricate audit lineage Wenv cannot vouch for.

| Source | Folder mapping | Key mapping | Mode(s) | Notes |
|---|---|---|---|---|
| **K8s Secrets** | one Secret → one folder named after the Secret; a single-Secret import may target the environment root | manifest files: `data` decoded, then `stringData` overlaid, **`stringData` wins** — Kubernetes' own admission semantics; live reads: `data` only (`stringData` is write-only input, never present in reads) | file (manifest YAML/JSON, multi-document supported) + live (kubeconfig) | wrong `kind` refused by name; duplicate keys within one Secret refused; binary refused by name |
| **SOPS** | nested map levels → folder chain | scalar leaves → keys | file only (SOPS *is* a file; ambient keyring decrypts — KMS/Transit contact disclosed) | leaf arrays/objects → `json` via the deterministic conversion; plaintext-leaf status = classification *hint* (§ Classification) |
| **Vault / OpenBao KV** | path segments below the `--path` prefix → folder chain | leaf secret's fields → keys | file (the connector's **pinned capture format**, below) + live (HTTP API) | traversal algorithms fixed below; non-string field values → `json` via the deterministic conversion |
| **Infisical** | Infisical folders → folders | secrets → keys | file (a **pinned structured JSON export format** — exporter command, minimum version and schema fixtures pinned at implementation, [#27](https://github.com/Dunky13/wenv/issues/27)) | chosen env slug = the source slice; **an export that lacks folder/env provenance, or that has already resolved personal overrides into values, is refused by name** — flattened dotenv-style exports route to the `.env` scaffold path instead; where the pinned format marks personal overrides, they are skipped and listed by name |
| **Phase** | — | — | deferred (§ v1 scope) | documented recipe: dotenv export → `.env` scaffold path |

### Vault/OpenBao: traversal algorithms and the capture format, fixed

The **mount's KV engine version** (1 or 2) and a **v2 secret's version number** are distinct and never conflated. The engine version comes from an explicit `--kv-version` flag or, absent it, from the mount's own metadata (`sys/internal/ui/mounts` as the client conventions resolve it); guessing from response shape is not a mechanism.

- **v1 traversal**: `LIST` on `<mount>/<path>` recursively below the prefix; `READ` on `<mount>/<path>` per leaf. `list` + `read` capabilities on the subtree are required and stated up front.
- **v2 traversal**: `LIST` on `<mount>/metadata/<path>` recursively; per leaf, `READ` on `<mount>/metadata/<path>` for version state, then `READ` on `<mount>/data/<path>` for the **latest version only**. A latest version marked deleted or destroyed in metadata is **skipped by name** (no resurrection of older versions — history is never imported). `list` + `read` on both the `metadata/` and `data/` paths are required and stated up front.
- **The capture format is pinned as JSON Lines** — one JSON object per line, each `{path, mount, engine_version, secret_version (v2, else absent), deleted, destroyed, data}`. File mode consumes exactly this; records with `deleted` or `destroyed` true are skipped by name, matching live behavior. The documented enumeration recipe emits this format; a bare single-secret `vault kv get -format=json` capture is *not* the format and is refused with a pointer to the recipe (which handles the single-secret case by emitting one record).

## Typing: suggestions in the wizard, strings in flag mode

Every imported key must carry a type declaration; the conservative floor is `string`. The wizard offers **deterministic suggestions** — the value is canonical `true`/`false` → suggest `boolean`; the value matches the schema ADR's integer grammar → suggest `integer`; the value parses as a JSON object or array → suggest `json`; otherwise `string` — and a suggestion applies **only on human accept**. Because declarations are project-scoped, a suggestion is computed across *all* mapped environments' values for the key — a key that is `4` in staging and `auto` in prod suggests nothing. **Flag mode declares everything `string`**; the mapping template can declare types per key, so a reviewed replay can carry richer typing.

*Rejected: auto-inference* — a silent tightening. `WORKERS=4` inferred `integer` breaks the day someone sets `auto`; the human who accepts the suggestion is the human who knows the key's real domain (`any_of` exists for exactly the mixed cases — [schema-model.md](./schema-model.md)).

## v1 scope per source

Explicit per-source decisions, feeding the MVP boundary ([#26](https://github.com/Dunky13/wenv/issues/26)):

- **K8s Secrets — v1, file + live.** Highest audience overlap (k3s self-hosters); live mode is a kubeconfig read.
- **SOPS — v1, file** (its only possible mode). The largest self-hoster install base among the sources.
- **Vault / OpenBao KV — v1, file + live.** The live connector is a thin HTTP client; the escaping-Vault migration is a headline story of the positioning ticket ([#2](https://github.com/Dunky13/wenv/issues/2)).
- **Infisical — v1, file mode only**, in the pinned structured format (table above). Live API deferred; **trigger: user demand.**
- **Phase — deferred entirely.** Their export today is dotenv, which the settled `.env` scaffold path already handles; live mode would mean reimplementing their end-to-end client crypto — pure cost for the smallest source. Documented recipe instead. **Trigger: Phase ships a structured export worth mapping, plus demand.**

The wizard ships in v1 covering exactly the shipped connectors.

## Grammar join

**One new top-level verb: `import`**, under the declared #25 amendment (header). Mode selection: no source arguments on a TTY → wizard; `--from <source>` + selectors → flag mode; `--mapping <file>` → replay. Human-only; client-local parity exemption; no new output classes — the emitted artifacts are files under the existing secret-file discipline, and nothing import prints is a secret value.

- **Phase 2 is not new grammar**: `definitions plan`/`definitions apply --plan` and `values import` consume the emitted artifacts under their existing exit-code and staleness contracts, plus the one declared additive input on `values import` (§ *Binding phase 1 to phase 2*).
- **Exact flag spellings, the template and manifest serializations, and connector fixtures** are delegated to the API/CLI spec at synthesis ([#27](https://github.com/Dunky13/wenv/issues/27)), bound by everything fixed here.

*Rejected: extending `scaffold` with `--from <source>`* — `scaffold` is locked as a pure local transform that contacts no server ([source-of-truth.md](./source-of-truth.md)); wizard and live modes break that property, and overloading the verb would re-define locked semantics. `scaffold` remains the `.env` path, untouched.

## Bindings

**Amends #25** as declared in the header (verb taxonomy, human-only list, parity exemption list, one additive `values import` input). Binds the MVP boundary ([#26](https://github.com/Dunky13/wenv/issues/26): per-source in/out with triggers) and the synthesis ([#27](https://github.com/Dunky13/wenv/issues/27): spellings, serializations, fixtures, the canonical key grammar's restatement). Consumes at locked width: publish-pipeline funnelling, additive bundles and the plan/apply machinery (#13), human-only strictness (#13/#18/#25), three-state presence and write-presence signalling (#10/#11), lexical grammar and trim rules (#12), proof-carrying reads and the operation registry (#23), secret-file output discipline (#25), the two-extension-points rule (#33). One owner lean reversed in-session and recorded: the SOPS encryption-boundary classification split (§ Classification).
