import { QueryClientProvider } from '@tanstack/react-query';
import { useEffect, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';

import { safeOriginOf, useRemotes } from '../api/remotes.ts';
import { WorkspaceContextProvider } from '../api/transport.tsx';
import {
  assertCompatible,
  forgetWorkspace,
  livenessPollMs,
  openPrepared,
  prepareWorkspace,
  probeWorkspace,
  useWorkspaces,
  WorkspaceError,
  type PreparedWorkspace,
} from '../api/workspace.ts';
import { createWorkspaceClient } from '../api/workspaceClient.ts';
import { makeQueryClient } from '../app/queryClient.ts';

/**
 * WorkspaceScope is the boundary between operating THIS instance and operating a
 * remote (#71, multi-instance ADR § What the workspace is, and is not).
 *
 * The product surfaces — matrix, history, values — render the same component
 * either way; what changes is the transport under them, and this is where that
 * swap is made. A surface reached with a `?remote=<name>` query parameter is
 * operating that remote; without one it is local, and this renders its children
 * untouched so nothing about the local path changes.
 *
 * The remote is a QUERY PARAMETER rather than a new route on purpose: the
 * closed surface registry (`app/navigation.ts`) gates every path on a Playwright
 * flow, and the workspace is the SAME matrix/values/history the flow already
 * covers, pointed elsewhere — not a second set of surfaces to register and
 * assert twice over. The deep link that carries the parameter is built from a
 * live read of the remote's own project list, so its org and project ids are
 * the remote's, resolved over the bearer, never guessed from the directory
 * snapshot's names.
 */
export function WorkspaceScope({
  remote,
  children,
}: {
  /** Overrides the `?remote` parameter — the remotes card supplies it directly. */
  remote?: string;
  children: ReactNode;
}) {
  const [params] = useSearchParams();
  const name = (remote ?? params.get('remote') ?? '').trim();
  if (name === '') {
    return <>{children}</>;
  }
  return <WorkspaceBoundary remote={name}>{children}</WorkspaceBoundary>;
}

/**
 * WorkspaceBoundary holds one live workspace: the origin-scoped client, its own
 * isolated query cache, and the states a workspace can be in that the local
 * path never is — not yet connected, version-skewed, or killed out from under
 * the shell.
 */
function WorkspaceBoundary({ remote, children }: { remote: string; children: ReactNode }) {
  const remotes = useRemotes();
  const entry = remotes.data?.items.find((r) => r.name === remote);
  const origin = entry === undefined ? '' : safeOriginOf(entry.url);

  const workspaces = useWorkspaces();
  const bearer = workspaces.find((w) => w.origin === origin);

  // The liveness poll, here as well as on the remotes card. Operating a matrix
  // three routes deep is exactly where a kill switch must still bite: a
  // de-allowlist strips the CORS headers rather than answering 401, so a data
  // call fails at the browser without a status the transport can read, and
  // without this poll an idle workspace would keep claiming to be open. The
  // probe drops the bearer on a run of failures, which flips this boundary to
  // its reconnect state — fail closed, without reloading the shell.
  useEffect(() => {
    if (bearer === undefined) {
      return;
    }
    let cancelled = false;
    const id = setInterval(() => {
      if (!cancelled) {
        void probeWorkspace(bearer);
      }
    }, livenessPollMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [bearer]);

  if (remotes.isPending) {
    return (
      <p className="card" role="status">
        Loading…
      </p>
    );
  }

  if (entry === undefined || origin === '') {
    return (
      <section className="card" aria-labelledby="workspace-unknown">
        <h1 id="workspace-unknown">Unknown remote</h1>
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>
            No remote named <span className="mono">{remote}</span> is configured on this instance.
          </span>
        </p>
      </section>
    );
  }

  if (bearer === undefined) {
    return <Reconnect origin={origin} name={remote} />;
  }

  // The connected subtree — its cache, its client, its compatibility gate — is
  // KEYED on origin AND session id. That key is the whole isolation story:
  //
  //   - a different human reconnecting in the same tab after a revocation gets a
  //     NEW session id, so the key changes and the cache is thrown away — they
  //     never see a frame of the previous human's values;
  //   - switching `?remote=A` to `?remote=B` changes the origin, same effect;
  //   - a STEP-UP rotates the bearer VALUE under a stable session id, so the key
  //     does NOT change and the cache is preserved — the elevation is the same
  //     human continuing, not a new one.
  return (
    <ConnectedWorkspace key={`${origin}::${bearer.session}`} origin={origin} remote={remote}>
      {children}
    </ConnectedWorkspace>
  );
}

/**
 * ConnectedWorkspace holds one workspace session's cache and gates rendering on
 * the live compatibility check.
 *
 * It is mounted under a key of origin + session id, so everything below is
 * created fresh for a new session and torn down with the old one. The gate is
 * the ADR's "live meta read BEFORE resuming": product children — which would
 * fire data reads at a possibly downgraded or restored remote — do not mount
 * until the check passes, rather than mounting first and refusing after the
 * reads have already gone out.
 */
function ConnectedWorkspace({
  origin,
  remote,
  children,
}: {
  origin: string;
  remote: string;
  children: ReactNode;
}) {
  const [queries] = useState(() => makeQueryClient());
  const [client] = useState(() => createWorkspaceClient(origin));
  const [gate, setGate] = useState<'pending' | 'ok' | 'refused'>('pending');
  const [message, setMessage] = useState('');

  useEffect(() => {
    let live = true;
    assertCompatible(origin)
      .then(() => {
        if (live) setGate('ok');
      })
      .catch((error: unknown) => {
        if (!live) {
          return;
        }
        setMessage(
          error instanceof WorkspaceError
            ? error.message
            : 'This remote is not compatible with this shell.',
        );
        setGate('refused');
      });
    return () => {
      live = false;
    };
  }, [origin]);

  if (gate === 'pending') {
    return (
      <p className="card" role="status">
        Checking <span className="mono">{origin}</span>…
      </p>
    );
  }

  if (gate === 'refused') {
    return (
      <section className="card" aria-labelledby="workspace-skew">
        <h1 id="workspace-skew">Cannot operate this remote</h1>
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{message}</span>
        </p>
      </section>
    );
  }

  return (
    <QueryClientProvider client={queries}>
      <WorkspaceContextProvider value={{ origin, remote, client }}>
        <WorkspaceBanner origin={origin} />
        {children}
      </WorkspaceContextProvider>
    </QueryClientProvider>
  );
}

/**
 * WorkspaceBanner is the workspace's trust story in one line: you are operating
 * a DIFFERENT instance, as yourself, and everything you do lands in ITS audit
 * trail under your name. It is persistent because the fact is — a human three
 * clicks deep in a foreign matrix is owed the reminder of whose data it is.
 */
function WorkspaceBanner({ origin }: { origin: string }) {
  return (
    <div className="workspace-banner" role="status">
      <span className="workspace-banner__dot" aria-hidden="true" />
      <span className="workspace-banner__text">
        Operating <span className="mono">{origin}</span> — as you, on that instance. Everything you
        do here appears in its audit trail under your name.
      </span>
      <button
        className="btn"
        type="button"
        onClick={() => forgetWorkspace(origin)}
        aria-label={`Exit the workspace on ${origin}`}
      >
        Exit workspace
      </button>
    </div>
  );
}

/**
 * Reconnect is the state a deep-linked workspace URL lands in when the bearer
 * is gone — which is EVERY reload, because the bearer lives in memory only, and
 * also the moment a kill switch fires. It is the same two-click ceremony the
 * remotes card uses: prepare (a network round trip that names the origin the
 * human is about to sign in at), then a synchronous open on the gesture.
 */
function Reconnect({ origin, name }: { origin: string; name: string }) {
  const [prepared, setPrepared] = useState<PreparedWorkspace | null>(null);
  const [opening, setOpening] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const fail = (error: unknown) =>
    setFailure(
      error instanceof WorkspaceError
        ? error.message
        : 'The workspace could not be reconnected. Check that this instance allowlists this origin.',
    );

  const prepare = async () => {
    setFailure(null);
    setOpening(true);
    try {
      setPrepared(await prepareWorkspace(origin));
    } catch (error) {
      fail(error);
    } finally {
      setOpening(false);
    }
  };

  // Must stay synchronous to the gesture: a popup opened after an await has lost
  // the user activation and the browser blocks it.
  const go = (ready: PreparedWorkspace) => {
    setPrepared(null);
    openPrepared(ready).catch(fail);
  };

  return (
    <section className="card" aria-labelledby="workspace-reconnect">
      <h1 id="workspace-reconnect">Reconnect to {name}</h1>
      <p>
        Your workspace on <span className="mono">{origin}</span> is not open. Reconnect to operate
        it — you will sign in on that instance&apos;s own origin, in a popup.
      </p>
      {failure === null ? null : (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{failure}</span>
        </p>
      )}
      {prepared === null ? (
        <button className="btn btn--primary" type="button" onClick={prepare} disabled={opening}>
          {opening ? 'Contacting…' : 'Reconnect workspace'}
        </button>
      ) : (
        <button className="btn btn--primary" type="button" onClick={() => go(prepared)}>
          Continue to {origin} to sign in
        </button>
      )}
    </section>
  );
}
