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

## Known limitations (for the reviewer / future work)

- **Per-environment source slices in replay.** The wizard reads a source per target environment
  (so type suggestions can span differing per-env values). The mapping template records ONE
  `scope` (the first environment's read); a multi-environment REPLAY fans that one recorded source
  over every environment it names (presence varies, values are the one read's). A template whose
  environments used genuinely different per-env source files (e.g. Infisical per-slug exports) is
  not fully reproducible from the single recorded scope. The regenerated manifest is a different
  run manifest, which the ADR already treats as visible, not silent.
- **Plaintext-on-disk warning** names the emitted values files but not the wizard's per-environment
  source export files (flag mode names its single `--file`). A follow-up could thread the read
  source paths into `reportProject`.

## Note: ops-catalogue vs code bound divergence (pre-existing, do not fix here)

`docs/spec/ops-catalogue.md` lists 10 MiB / 50 MiB / 50 000 / 10 min where
`internal/importer/importer.go` uses 4 MiB / 16 MiB / 5 000 / 60 s. Pre-existing on main;
flagged, not changed in this ticket. Wizard aggregate bound cites the catalogue's
`Wizard session aggregate` row (30 min / 100 MiB).
