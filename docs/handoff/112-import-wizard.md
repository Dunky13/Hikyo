# #112 — Interactive import wizard (phase-1 authoring frontend)

Parent: #41. ADR: `docs/adr/import-paths.md`. Serializations: `docs/spec/api-cli-spellings.md` § 3
(wizard interaction states + mapping template + run manifest). Builds on #68 (framework +
file sources), #69 (live connectors), #70 (definitions git flow).

The wizard is the **interactive authoring frontend for the mapping template**: it walks the
source structure and target mapping, records every choice into a `Template`, then runs the
**same plan path replay uses**. Byte-identity between a wizard session and an equivalent
flag/replay run (acceptance criterion 1) is therefore structural, not tested-in.

## Locked design decision: created environments are tokenless-by-design

A wizard session may fan out across target environments, **including ones it will create**
(declared up front, ADR § Targeting and hierarchy creation). The run manifest is a phase-2
precondition binding a **server-minted occurrence token per (key, environment)**. A
to-be-created env has no id at phase 1 (phase 1 never writes), so no token can exist.

Decision (Fable advisor, 2026-08-20; Option A / honest tokenless path):

- Created envs carry **zero occurrence rows**. They are named (not id'd) in
  `target.environments` and `phase_completion.imported`.
- Created envs sit **outside the precondition entirely**: at phase 2 the CLI invokes
  `values import` for a created env with `Precondition = nil` — NOT a degraded precondition
  (`checkPrecondition` rejects every key a manifest reviewed none of). They get the locked
  manifest-less strict-import semantics (closed schema + skip-by-default).
- Phase 2 for a created env: `definitions apply` creates it (bundle carries
  `create environment <name>` lines) → CLI resolves name→id via the `read@project` structure
  read → `values import` runs strict, no precondition. The server only ever receives real ids.
- **No server change.** Rejected Option B (server mints name-scoped tokens): a name is mutable
  and reusable, reintroducing the binding instability the id-scoped HMAC
  (`crypto/token.go scopedOccurrenceKey`) exists to kill, and needing a client-authored
  "created by this run" claim = the forgeable gap #68 closed. Its verification reduces to
  "still absent", which skip-by-default already provides.

Safety: a created env has no `set` bucket at review, so no overwrite consent can exist for it;
a value set in the apply→import window is **skipped-and-listed, never clobbered**. Accepted
residual, stated openly: that movement is skipped, not rejected-by-name.

## Build plan

1. **Plan-layer refactor (pure, TDD, server-free).** `BuildProjectPlan(ProjectPlanInput)`:
   N per-env inputs → one `Template`, one project-wide `definitions.Bundle`, per-env
   `ValuesFile`, one multi-env `Manifest`. `BuildPlan` (single env) becomes a thin N=1 wrapper
   so flag/replay bytes are unchanged and byte-identity is structural.
2. **Reconciliation** — project-scoped identity/type/classification/folder per key. Type
   suggestion computed across all envs' values (ADR § Typing). Conflicts are wizard-time
   prompts; a reconciled template replays without conflict; flag mode is single-env so never
   reconciles.
3. **Lift the multi-env replay refusal** in `cli/importer.go`, routed through the planner.
4. **Wizard engine** (9 states, ADR/spec §3) against a `Prompter` interface + injected source
   and presence readers; server/source calls stay in the CLI. TDD with a scripted prompter.
5. **CLI TTY entry** (flip the ExitRefused branch; no-TTY error unchanged) + aggregate session
   bound (30 min / 100 MiB, ops catalogue row).
6. **Serialization** — `Manifest.Target.Environments` → objects `{id|null, name, create}`;
   created-env values file `environment:null` + `environment_name`; `phase_completion.imported`
   keyed by name for creates. `api-cli-spellings.md` §3 updated alongside.
7. **Tests** — byte-identity goldens (scripted wizard vs flag per connector fixture; multi-env
   session → replay of its own template), multi-env conformance, no-TTY regression, aggregate
   bound.

## Status (all landed on this branch)

1. ✅ `BuildProjectPlan` multi-env planner; `BuildPlan` is the N=1 wrapper (byte-identity structural).
2. ✅ Reconciliation: one class/type/classification/folder per key; folder conflict refused.
3. ✅ Multi-env replay refusal lifted; routed through the planner.
4. ✅ Wizard engine (nine states) + `SuggestType`; scripted-prompter tests incl. byte-identity.
5. ✅ CLI TTY entry, terminal prompter, WizardHost, aggregate session bound (decoded bytes in
   the engine; wall clock via the session context).
6. ✅ Created environments: `create environment` bundle lines, `target.created_environments`,
   `environment_name` values file, tokenless phase-2 path in `values import`.
7. ✅ Conformance `import_multi_environment_fan_out`; no-TTY regression; prompter tests.

Two presence reads in the wizard: the first (default intent) discovers which keys are already
declared so classification/type review skips them; the second (final intent) mints the
occurrence tokens the manifest records, so a downgrade or an accepted type suggestion cannot
leave a stale token.

`values import` slices the run-manifest precondition to the target environment: a manifest spans
every environment a session touched, but each `values import` is per environment, and importing
B must not present A's occurrences (A's own import already advanced them).

## Multi-environment model: one source fanned (ADR "only presence varies")

The wizard reads the source **once** and maps that one read onto one or more target environments
(existing and/or created). Keys/types/classifications are project-scoped and reconciled once; only
presence — the buckets and the values written — varies per environment. This is what makes a
multi-environment session **faithfully replayable**: the template records one `scope`, and replay
re-reads that one source and fans it the same way, so wizard and replay agree.

A genuinely per-environment-different-source migration (e.g. Infisical staging-slug vs prod-slug
with different values, which is what would exercise interactive type/classification RECONCILIATION
conflicts) is **not** covered by v1: run the wizard once per slice. The reconciliation machinery
still enforces one identity/type/classification/folder per key in the bundle, and the planner
**refuses** any cross-environment conflict non-interactively (folder conflict → `CodeIncompatible`),
which is the "refused in replay" half of the acceptance criterion. Future work: record per-environment
scope in the template to author true multi-source reconciliation interactively.

## Codex review R1 → fixes applied (this branch)

R1 (gpt-5.6-sol high) returned CHANGES; all findings fixed:
- CRITICAL: `--overwrite` refused for a created-environment (tokenless) values file, before any
  server contact; wizard refuses `create <existing-env-name>`.
- HIGH: multi-env replay no longer imports one source's values into every environment (the wizard
  now uses the one-source-fan model above, so replay reproduces it).
- HIGH: `values import` requires the target environment to be named in the manifest before slicing
  its precondition.
- HIGH: the wizard records an existing non-default declaration (config, or a non-string type) as
  reviewed consent, so a declared key no longer hits a spurious incompatible refusal.
- HIGH: folder-conflict-prompt corruption is mooted (one source cannot conflict); the planner keeps
  the folder-conflict refusal as the safety net for hand-edited templates.
- MEDIUM: mixed definitions revisions across the session are refused; partial multi-values-file
  writes are fully cleaned up (no orphan plaintext); the session deadline is checked before emission.
- The plaintext-on-disk warning now names the wizard's source export file alongside the values files.

## Note: ops-catalogue vs code bound divergence (pre-existing, do not fix here)

`docs/spec/ops-catalogue.md` lists 10 MiB / 50 MiB / 50 000 / 10 min where
`internal/importer/importer.go` uses 4 MiB / 16 MiB / 5 000 / 60 s. Pre-existing on main;
flagged, not changed in this ticket. Wizard aggregate bound cites the catalogue's
`Wizard session aggregate` row (30 min / 100 MiB).
