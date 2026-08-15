# Handoff — #57 Environment matrix UI + row editor + problems filter

Ticket: [#57](https://github.com/Dunky13/hikyo/issues/57) (parent #41). Blocked-by #51
(revisions/publish) and #56 (UI shell / flow registry) — both merged before this work
started. Authored by Codex `gpt-5.6-sol` (high) under a Claude orchestrator, per the
ticket's model routing; reviewed two-axis (standards + spec), one fix round, CLEAN.

## What shipped

The signature surface per the frozen prototype `prototype/env-matrix/31` (branch
`wayfinder-docs`) and `docs/spec/ui-spec.md`, on the flat value model
(`docs/adr/flat-model.md` — set|absent only; no inheritance, mask, provenance chain, or
drift signal anywhere in this surface).

- `web/src/routes/Matrix.tsx` — project-scoped matrix surface
  (`/orgs/:org/projects/:project/matrix`, surface id `matrix` in
  `src/app/navigation.ts`). Cascade lanes: sticky key column + sticky header,
  horizontally scrolling environment lanes, mono cells.
- Density valves: environment show/hide picker (min 1 visible,
  `toggleVisibleEnvironment`), collapsible groups (collapsed header shows the
  comma-separated key list), both per prototype iterations 10/12.
- Problems filter per iterations 30/31: client-computed problems
  (`required_in` × absent — including a staged `unset` — plus server validation
  refusals), filter bar "⚠ filter active: problems — showing n of m keys" +
  "✕ show all keys", filter survives group jumps, filtered-out groups render dimmed
  and inert (title "hidden by the problems filter"), group badges carry counts.
- `web/src/routes/MatrixRowEditor.tsx` — centered row editor opened from the key name
  or a cell: one field per readable environment, protected markers, fill-all,
  write-only secret placeholders, live per-field declaration checks, per-cell clear,
  and provenance per environment. Config copy-to keeps its protected confirmation +
  ceremony; secret reveal/copy stays on Values (#58).
- `web/src/routes/MatrixPublishSheet.tsx` — selective publish per the frozen
  `renderPublishSheet`: one section per environment holding drafts (checkbox default
  checked, `rN → rN+1`, draft preview with secrets masked and clears labelled),
  problem environments disabled with the veto naming key and environment — they hold
  back, never veto the clean ones; one atomic `publishPendingChanges` over the
  selected version ids. Protected environments in the selection require an explicit
  confirmation and run the #21 ceremony (`useProtectedPublishCeremony.ts`, purpose
  `publish`, same convention as Values' copy-into-protected).
- `web/src/routes/matrix-state.ts` — pure domain seam (problems computation, filter
  projection, blocked/selectable publish sets, protected-confirmation predicate,
  visibility toggling), vitest-covered in `matrix-state.test.ts`.
- `web/src/api/matrix.ts` — API boundary: catalogue + per-env values/settings/signals
  fan-out (tanstack-query `useQueries`), signals polled at 2s (the documented SSE
  polling fallback). A revision advance refreshes its matching values query; the
  boundary refuses half-present pending signals. Config previews persist in
  session storage under the immutable pending version id, so reload keeps publish
  review exact. Everything crosses `parsed()` + generated Zod.
- `web/src/api/client.ts` parses the generated error contract before retaining a
  caller-safe detail. Publish adds a matrix validation problem only when that detail
  names one known key/environment; authorization, stale conflicts, network failures,
  and unparsed refusals remain retryable mutation errors.
- `web/src/routes/Projects.tsx` — the projects list became a real surface (links each
  project to its matrix); extracted out of `Placeholder.tsx`, which is a chrome
  skeleton again.
- Signals never colour-only: draft dot + "draft set/cleared" text, `pending_by_others`
  marker, "changed in rN" chip, problem pill — each carries glyph/text + ARIA.

## e2e

`web/e2e/flows/matrix.spec.ts`, registry surface `matrix` (closed-registry closure
green). Serial flow, desktop + mobile projects, dark + light pinned-assertion passes
(axe serious/critical = 0, colour-stripped state text, focus, contrast, ≥44px,
computed styles vs tokens). Covers: problems filter persistence + veto naming
key/environment, selective publish holding back the blocked env while publishing the
clean one, protected publish confirmation + passkey ceremony, density valves, protected
config copy + secret routing to Values, and the acceptance demo — multi-environment
fill/edit, staged-preview reopen, reload-bound publish preview, centered 375px modal,
publish, signals update.

Fixtures: `seed.ts` adds `MATRIX_REQUIRED` (required only in production, staged-clear
to create the veto — a required-absent state cannot be *created*, schema publication
correctly refuses it, so the fixture walks the real user path). The Chromium virtual
passkey installer moved to `fixtures/instance.ts` (`installPasskeyAuthenticator`),
shared with `reveal.spec.ts`; its counter-persistence contract is documented there.

## Decisions

- **Copy from the matrix is config-only**; secret copy lives on Values with its
  disclosure ceremony. Wiring reveal-window plumbing into the matrix for secret copy
  ballooned scope with no S3 criterion behind it. Revisit only if a ticket asks.
- **Signals poll (2s) instead of SSE** — the signals endpoint is documented as the
  advisory stream's polling fallback; one live-update protocol per surface.
- **Publish addressed to one env, version ids spanning envs** — the API permits it and
  authorizes each affected environment separately; the sheet's selection is the
  affected set, atomic per flat-model.
- No Go changes; the #50/#51 API surface sufficed.

## Verification record (2026-08-15)

`pnpm typecheck` clean · `pnpm test` 75/75 · full Playwright suite 116/116 (3.1 min,
both viewport projects). PR review fixes cover all nine threads; protected publish is
enforced and regression-tested by rebased `main`'s transactional service path, while
the remaining eight fixes live in this PR.
