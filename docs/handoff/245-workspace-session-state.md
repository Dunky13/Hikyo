# Issue #245: atomic workspace session state

## Contract

Each canonical remote origin now owns one in-memory `WorkspaceSessionState`:

- `bearer` is the live header credential and remains memory-only;
- `epoch` identifies the local installation of that credential;
- `consecutiveFailures` belongs to that epoch, not to bearer text in a second
  map;
- replacement installs a new epoch with zero failures in one `Map.set`;
- close, remote expiry, root-session expiry, logout, and root-session
  replacement remove the whole aggregate.

Liveness probes and workspace transport requests capture the aggregate they
started under. Their completion compares the captured epoch with the live
epoch before it can increment or clear failures, evict a bearer, or report a
newer session healthy. A step-up may retain the remote session id while rotating
the bearer; it still receives a new local epoch.

## Root ownership

The session API calls `transitionWorkspaceOwner` when `whoami` observes a
session id, a login installs a new session, logout succeeds, or `whoami` answers
401. Re-reading the same root session id preserves workspace health; changing
or losing it clears all remote workspace aggregates before cached local data is
reset or invalidated.

No bearer enters TanStack Query cache, mutation cache, browser storage, URLs,
logs, snapshots, generated output, or durable state.

## Validation

- `pnpm --dir web exec vitest run src/api/workspace.test.ts src/api/workspaceClient.test.ts src/api/session.test.ts`:
  28 passed
- `pnpm --dir web run test`: 262 passed across 24 files
- `pnpm --dir web run typecheck`: passed
- `pnpm --dir web run build`: passed
- `pnpm --dir web exec playwright test flows/workspace.spec.ts`: 26 passed
  across desktop and mobile against the exact rebuilt bundle
- two-axis review round 2: standards CLEAN; spec CLEAN

No API, database, migration, generated output, or wire contract changed.
