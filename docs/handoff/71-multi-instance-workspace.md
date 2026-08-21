# Handoff: #71 Multi-instance workspace tier — operating a remote's data

Issue [#71](https://github.com/Hikyo-Org/Hikyo/issues/71) was **reopened**: the
directory tier and the handoff ceremony had landed, but the workspace tier was a
bearer-backed liveness badge — the UI never routed Matrix, Values, history,
reveal, edit or publish operations to the remote. A live workspace could not
operate B's data. This run closes that gap.

The whole change is **frontend**. The server was already complete for the entire
workspace tier — both establishment and step-up — before this run:

- `internal/server/cors.go` echoes an allowlisted origin across all of
  `/api/v1` (methods, `Authorization`, preflight).
- `internal/server/api.go` `extractBearer` accepts a `Bearer` on every route;
  `internal/authz/session.go:414` enforces the workspace session's **origin
  binding** as an authentication predicate at the chokepoint.
- `internal/service/workspace.go` `StartHandoff`/`ApproveHandoff`/`RedeemHandoff`
  implement the **step-up** handoff: a step-up binds the initiating session,
  operation, environment and key set, `freshCeremonyClass` requires a fresh
  reauth window on the approving session over the bound environment, and
  redemption **elevates the session in place** — same session id, a rotated
  bearer value (`WorkspaceSession.Elevated`).

Nothing server-side was added. `api/noproxy_test.go` remains the
invariant that no viewing-server proxy endpoint exists.

## What landed (web)

**The transport seam.** Every generated SDK function resolves its client as
`options.client ?? client`. That override is the one mechanism by which the same
product view operates a remote.

- `web/src/app/queryClient.ts` — `makeQueryClient()` shares the root's TanStack
  defaults so each open workspace can hold its OWN `QueryClient`. Cache
  isolation is **structural**: a same-named org/project on two instances can
  never collide because the caches are different objects.
- `web/src/api/workspaceClient.ts` — `createWorkspaceClient(origin)`: a
  per-remote client, `credentials: 'omit'`, **no** CSRF interceptor, bearer read
  **live per request** (picks up reconnect + step-up rotation). A 401/403 drops
  the exact rejected **value** at once (keyed by value, not session id — a
  step-up rotates the value under a stable session id).
- `web/src/api/transport.tsx` — `WorkspaceContext` + `useTransport()`: the
  SDK-option fragment (`{ client }` in a workspace, `{}` at home) the wrapper
  hooks spread at one call site each.

**The wrappers, threaded** (each hook spreads `useTransport()`): `values.ts`,
`matrix.ts`, `history.ts`, `settings.ts` (env/project hooks), `session.ts`
(`useOrgs`), `identities.ts` (`useServiceAccounts`), plus the imperative
`fetchRevealWindow` / `environmentSettingsQueryOptions` (explicit `client`
param), and the direct `exportValues` call in `HistoryDrawer.tsx`. The reauth
ceremonies in `values.ts` stay **local** by design — a passkey assertion is
RP-bound and cannot cross an origin.

**The surfaces.** `web/src/routes/WorkspaceScope.tsx` wraps the matrix / history
/ values elements. A `?remote=<name>` query parameter puts them on that remote's
transport, with its own isolated cache, a persistent banner naming the origin, a
live version-skew (resume) check, a liveness poll, and a **reconnect** state for
the every-reload no-bearer case. **No new registry surfaces** — the workspace is
the same surfaces pointed elsewhere, which keeps the closed flow registry
(`e2e/registry.ts`) honest without registering and pinning duplicates.

**The picker.** `web/src/routes/Remotes.tsx` grows a live project picker: it
reads the remote's own orgs and projects **over the bearer** (the ids the
directory snapshot's names cannot give) and deep-links each into the matrix.

**The step-up.** `web/src/routes/Ceremony.tsx`, inside a workspace, hands off to
a step-up popup on the **remote's** origin instead of running a local reauth.
`prepareWorkspace(origin, stepUp)` opens the elevation (session/operation/
environment/key set bound into the start body and carried on the approve URL);
`web/src/routes/WorkspaceApprove.tsx` runs the remote's own #58 reauth over the
bound environment, then approves; redemption rotates the bearer in place and the
disclosure retries over the now-elevated transport.

## Decisions worth not re-deriving

- **Remote-as-query-param, not a new route.** New `SurfaceId`s each need a
  Playwright flow AND a pinned-assertion run in both themes (the registry gate).
  The workspace is the existing surfaces on a different transport, so it rides
  their existing flows.
- **Nested `QueryClient` over key-namespacing.** Structural cache isolation; no
  key edits, no collision possible, cache dies with the subtree.
- **Value-keyed drops everywhere.** The transport 401-drop, the liveness probe,
  and the strike counter all key on the bearer **value**. A step-up rotates the
  value under a stable session id, so a stale verdict about the pre-rotation
  value must be a no-op or it kills the live elevated bearer.
- **Step-up parameters ride the approve URL, no new server endpoint.** The
  approve page needs the environment/key set to run the remote's reauth; the
  server still validates the fresh window against the transaction's OWN bound
  environment, so a tampered URL parameter only fails closed. (Ceiling below.)

## Deferred / blockers, by name

- **Epoch-tracker blocker (do NOT close #71 on merge).** The reopen states:
  "Integrate the private session-epoch tracker before closing; remote-client
  work can proceed in parallel." The remote-client work is done; the tracker
  integration is a separate item. No `close #71` in the PR until Marc confirms
  it. The workspace context already carries the pieces (origin, bearer, live API
  revision) the tracker would hang off.
- **Reveal / protected-publish e2e over the TOTP-in-popup path.** B is an IP
  literal, so a workspace step-up on B must use the TOTP path (no passkey RP).
  The unit tests cover the step-up prepare/elevate client logic; the full
  browser reveal-over-popup-TOTP flow (with its 30s step waits inside a popup)
  is the highest-flake e2e and is not added here. The added e2e drives a READ
  of B's config value through the shell and the no-proxy route-guard tripwire;
  edit/publish/reveal *routing* to the remote is covered by the transport
  threading, the unit tests (the generated-SDK-through-workspace-client test
  exercises the value PUT path), and the same tripwire (a leaked edit to A
  would fail it) — but no edit is driven through the matrix UI in the browser.
- **URL length ceiling on step-up `key` params** (`ponytail:` in
  `prepareWorkspace`): a reveal-all over a very large environment enumerates
  every key id onto the approve URL. The server accepts 1000×200 chars in the
  *body*; a URL will not carry that. The TOTP path does not need the params;
  passkey challenge binding does. Upgrade path: post the key set to a short-lived
  server-side transaction read the approve page fetches by state (mirrors
  cli-reauth's transaction read).

## Running it

```
cd web && pnpm install && pnpm --dir ../clients/ts install   # clients/ts has its own deps
eval "$(fnm env)" && fnm use 24
pnpm typecheck && pnpm test
# e2e (two real instances; claim a unique port block):
HIKYO_E2E_PORT=45820 HIKYO_E2E_PORT_B=45821 HIKYO_E2E_PORT_TLS=45822 \
  NODE_OPTIONS=--dns-result-order=ipv4first pnpm e2e
```

The e2e seeds B with one operable config project (`fixtures/instance.ts`
`seedServingProject`) so a workspace has something to operate.
