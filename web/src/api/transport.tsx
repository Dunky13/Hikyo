import type { Client } from '@hikyo/runtime-core';
import { createContext, useContext, type ReactNode } from 'react';

/**
 * The transport seam (#71, multi-instance ADR § What the workspace is, and is
 * not).
 *
 * Every generated SDK call resolves its client as `options.client ?? client` —
 * the shared same-origin singleton unless a call overrides it. That override is
 * the ONE mechanism by which the exact same product view operates a remote: the
 * api-wrapper hooks read the transport from this context and spread it into
 * their SDK options. Outside a workspace the context is null and the spread is
 * empty, so the singleton is used and nothing about local behaviour changes.
 *
 * There is deliberately no server in this path and no way to add one: the
 * override is a browser-side origin swap, and `api/noproxy_test.go` keeps the
 * viewing server from ever growing an endpoint that would proxy a remote.
 */

/** WorkspaceContextValue is the live workspace a subtree is operating within. */
export type WorkspaceContextValue = {
  /** The remote's canonical origin, e.g. `https://hikyo.went.io`. */
  readonly origin: string;
  /** The remote's NAME — the `?remote=` value that intra-workspace links carry. */
  readonly remote: string;
  /** The origin-scoped SDK client every call in this subtree routes through. */
  readonly client: Client;
};

/**
 * withRemote keeps a link INSIDE the workspace. Navigation between the
 * workspace's own surfaces — matrix → history, history → matrix — is
 * client-side (the bearer is in memory), and the `?remote=` parameter is what
 * marks a surface as operating a remote; a link that dropped it would silently
 * fall back to this instance's own data on the next surface. `remote` is empty
 * outside a workspace, and then the path is returned untouched.
 */
export function withRemote(path: string, remote: string): string {
  if (remote === '') {
    return path;
  }
  const separator = path.includes('?') ? '&' : '?';
  return `${path}${separator}remote=${encodeURIComponent(remote)}`;
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

/** WorkspaceContextProvider marks a subtree as operating one remote. */
export function WorkspaceContextProvider({
  value,
  children,
}: {
  value: WorkspaceContextValue;
  children: ReactNode;
}) {
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

/**
 * useWorkspaceContext returns the workspace a component is operating within, or
 * null when it is rendering this instance's own data. A component that must
 * behave differently in a workspace — the step-up ceremony, which runs on the
 * REMOTE's origin, not this one — branches on this.
 */
export function useWorkspaceContext(): WorkspaceContextValue | null {
  return useContext(WorkspaceContext);
}

/** TransportOptions is the SDK-option fragment that selects the client. */
export type TransportOptions = { readonly client?: Client };

/**
 * useTransport returns the SDK-option fragment an api-wrapper hook spreads into
 * every generated call it makes: `{ client }` inside a workspace, `{}` (the
 * singleton) at home. One call site, both transports — which is what lets the
 * wrapper modules serve local and remote data without a branch per endpoint.
 *
 * The rule the wrappers must keep: EVERY SDK call spreads this. A single missed
 * spread inside a workspace sends that one call to THIS server, with cookies,
 * and renders home data as the remote's — a leak no type checker catches, so
 * the extended two-instance e2e route-guards this server's data endpoints and
 * fails if any fire while a workspace is open.
 */
export function useTransport(): TransportOptions {
  const workspace = useContext(WorkspaceContext);
  return workspace === null ? {} : { client: workspace.client };
}
