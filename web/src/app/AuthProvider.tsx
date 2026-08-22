import { whoamiOp } from '@hikyo/operations';
import { zWhoAmI } from '@hikyo/zod';
import { QueryClientProvider } from '@tanstack/react-query';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { z } from 'zod';

import { ApiError, parsed } from '../api/client.ts';
import { transitionWorkspaceOwner } from '../api/workspace.ts';
import { makeQueryClient } from './queryClient.ts';

export type WhoAmI = z.infer<typeof zWhoAmI>;

export type AuthState =
  | { readonly status: 'checking' }
  | { readonly status: 'anonymous' }
  | {
      readonly status: 'authenticated';
      readonly sessionEpoch: string;
      readonly principal: WhoAmI['principal'];
    }
  | { readonly status: 'transitioning' };

type AuthContextValue = {
  readonly state: AuthState;
  readonly identity: WhoAmI | null;
  readonly failure: Error | null;
  readonly captureTransition: () => SessionTransitionGuard;
  readonly acceptSession: (identity: WhoAmI, guard: SessionTransitionGuard) => void;
  readonly endSession: (guard: SessionTransitionGuard) => void;
  readonly refreshSession: () => Promise<void>;
  readonly revalidate: () => Promise<void>;
};

type SessionTransitionGuard = {
  readonly revision: number;
};

type SessionCheckMode = 'blocking' | 'blocking-and-publish' | 'refresh-and-publish';

type Snapshot = {
  readonly state: AuthState;
  readonly identity: WhoAmI | null;
  readonly failure: Error | null;
  readonly queries: ReturnType<typeof makeQueryClient>;
};

const AuthContext = createContext<AuthContextValue | null>(null);
const CHANNEL_NAME = 'hikyo-root-auth';
const CHANNEL_MESSAGE = 'session-changed';
const MAX_TIMEOUT_MS = 2_147_483_647;

/** Read root identity without putting it in a session-owned query cache. */
async function readIdentity(): Promise<WhoAmI | null> {
  try {
    return await parsed(whoamiOp, {});
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return null;
    }
    throw error;
  }
}

function stateFor(identity: WhoAmI | null): AuthState {
  return identity === null
    ? { status: 'anonymous' }
    : {
        status: 'authenticated',
        sessionEpoch: identity.session.id,
        principal: identity.principal,
      };
}

function identityVersion(identity: WhoAmI | null): string | null {
  if (identity === null) {
    return null;
  }
  return [
    identity.session.id,
    identity.principal.id,
    identity.session.assurance.method,
    identity.session.assurance.authenticated_at,
    ...identity.session.assurance.factors,
  ].join('\u001f');
}

/**
 * AuthProvider is the one owner of root identity and local-instance cache
 * lifetime.
 *
 * There is deliberately no public QueryClient. Root `whoami` checks are
 * uncached, and every TanStack entry below this provider belongs to exactly one
 * browser session epoch (or to the anonymous pre-session epoch). A new session
 * id, logout, or expiry cancels old work and destroys every cached query and
 * mutation before the new epoch renders. A same-id assurance refresh preserves
 * entries and invalidates their answers for re-evaluation.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<Snapshot>(() => ({
    state: { status: 'checking' },
    identity: null,
    failure: null,
    queries: makeQueryClient(),
  }));
  const snapshotRef = useRef(snapshot);
  const requestRef = useRef(0);
  const transitionRevisionRef = useRef(0);
  const channelRef = useRef<BroadcastChannel | null>(null);

  const commit = useCallback((next: Snapshot) => {
    snapshotRef.current = next;
    setSnapshot(next);
  }, []);

  const destroySessionCache = useCallback((current: Snapshot): Snapshot => {
    void current.queries.cancelQueries();
    current.queries.clear();
    return current;
  }, []);

  const publishChange = useCallback(() => {
    channelRef.current?.postMessage(CHANNEL_MESSAGE);
  }, []);

  const settleIdentity = useCallback(
    (identity: WhoAmI | null, publish: boolean) => {
      const current = snapshotRef.current;
      const sameSession =
        identity !== null &&
        current.identity !== null &&
        identity.session.id === current.identity.session.id;
      if (identityVersion(identity) !== identityVersion(current.identity)) {
        transitionRevisionRef.current += 1;
      }
      transitionWorkspaceOwner(identity?.session.id);

      if (sameSession) {
        commit({
          ...current,
          state: stateFor(identity),
          identity,
          failure: null,
        });
        void current.queries.invalidateQueries();
      } else {
        const fresh = destroySessionCache(current);
        commit({
          ...fresh,
          state: stateFor(identity),
          identity,
          failure: null,
        });
      }
      if (publish) {
        publishChange();
      }
    },
    [commit, destroySessionCache, publishChange],
  );

  const checkSession = useCallback(
    async (mode: SessionCheckMode) => {
      const blocking = mode !== 'refresh-and-publish';
      const request = requestRef.current + 1;
      requestRef.current = request;
      const current = snapshotRef.current;
      if (blocking) {
        commit({
          ...current,
          state:
            current.identity === null ? { status: 'checking' } : { status: 'transitioning' },
          failure: null,
        });
      }
      try {
        const identity = await readIdentity();
        if (requestRef.current === request) {
          settleIdentity(identity, mode !== 'blocking');
        }
      } catch (error) {
        if (requestRef.current === request) {
          const latest = snapshotRef.current;
          commit({
            ...latest,
            state: blocking ? stateFor(latest.identity) : latest.state,
            failure: error instanceof Error ? error : new Error('root authentication check failed'),
          });
        }
      }
    },
    [commit, settleIdentity],
  );

  const revalidate = useCallback(() => checkSession('blocking'), [checkSession]);
  const refreshSession = useCallback(
    () => {
      // Operation completion must stale the affected session answers now, not
      // one identity round-trip later. The root still owns that broad
      // invalidation and the subsequent whoami check remains the only place an
      // operation-adjacent 401 can end the browser session.
      void snapshotRef.current.queries.invalidateQueries();
      return checkSession('refresh-and-publish');
    },
    [checkSession],
  );
  const reconcileTransition = useCallback(
    () => checkSession('blocking-and-publish'),
    [checkSession],
  );

  const captureTransition = useCallback(
    (): SessionTransitionGuard => ({ revision: transitionRevisionRef.current }),
    [],
  );

  const acceptSession = useCallback(
    (identity: WhoAmI, guard: SessionTransitionGuard) => {
      if (guard.revision !== transitionRevisionRef.current) {
        void reconcileTransition();
        return;
      }
      transitionRevisionRef.current += 1;
      const request = requestRef.current + 1;
      requestRef.current = request;
      const current = snapshotRef.current;
      commit({ ...current, state: { status: 'transitioning' }, failure: null });
      queueMicrotask(() => {
        if (requestRef.current === request) {
          settleIdentity(identity, true);
        }
      });
    },
    [commit, reconcileTransition, settleIdentity],
  );

  const endSession = useCallback(
    (guard: SessionTransitionGuard) => {
      if (guard.revision !== transitionRevisionRef.current) {
        void reconcileTransition();
        return;
      }
      transitionRevisionRef.current += 1;
      const request = requestRef.current + 1;
      requestRef.current = request;
      const current = snapshotRef.current;
      commit({ ...current, state: { status: 'transitioning' }, failure: null });
      queueMicrotask(() => {
        if (requestRef.current === request) {
          settleIdentity(null, true);
        }
      });
    },
    [commit, reconcileTransition, settleIdentity],
  );

  useEffect(() => {
    void revalidate();
  }, [revalidate]);

  useEffect(
    () => () => {
      const current = snapshotRef.current;
      void current.queries.cancelQueries();
      current.queries.clear();
    },
    [],
  );

  useEffect(() => {
    if (typeof BroadcastChannel !== 'function') {
      return;
    }
    const channel = new BroadcastChannel(CHANNEL_NAME);
    channelRef.current = channel;
    channel.addEventListener('message', (event) => {
      if (event.data === CHANNEL_MESSAGE) {
        void revalidate();
      }
    });
    return () => {
      channelRef.current = null;
      channel.close();
    };
  }, [revalidate]);

  useEffect(() => {
    const onFocus = () => void revalidate();
    globalThis.addEventListener?.('focus', onFocus);
    return () => globalThis.removeEventListener?.('focus', onFocus);
  }, [revalidate]);

  useEffect(() => {
    if (snapshot.state.status !== 'authenticated' || snapshot.identity === null) {
      return;
    }
    const idle = Date.parse(snapshot.identity.session.idle_expires_at);
    const absolute = Date.parse(snapshot.identity.session.absolute_expires_at);
    const expiresAt = Math.min(idle, absolute);
    const delay = Number.isFinite(expiresAt)
      ? Math.min(MAX_TIMEOUT_MS, Math.max(1_000, expiresAt - Date.now()))
      : 1_000;
    const timer = setTimeout(() => void revalidate(), delay);
    return () => clearTimeout(timer);
  }, [revalidate, snapshot.identity, snapshot.state.status]);

  const value = {
    state: snapshot.state,
    identity: snapshot.identity,
    failure: snapshot.failure,
    captureTransition,
    acceptSession,
    endSession,
    refreshSession,
    revalidate,
  };

  return (
    <QueryClientProvider client={snapshot.queries}>
      <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
    </QueryClientProvider>
  );
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (value === null) {
    throw new Error('useAuth must be rendered under AuthProvider');
  }
  return value;
}
