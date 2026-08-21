import { QueryClient } from '@tanstack/react-query';

/**
 * makeQueryClient builds the app's TanStack client with ONE set of defaults.
 *
 * There is more than one client in this app: the root client the SPA uses for
 * its own instance, and a fresh client per open workspace (#71) so a remote's
 * cache is structurally isolated and dies with the subtree — same-named
 * org/project on two instances can never collide because the caches are
 * different objects, not merely different keys. Both must behave identically,
 * so the defaults live here rather than being written twice.
 *
 * The choices are the architecture's, not taste:
 *
 *   - `staleTime` is short because authorization is evaluated per request at
 *     the server's chokepoint and never cached there. A long client cache
 *     would not be an authorization cache — the server still decides — but it
 *     would show a revoked reader stale data, so the window stays small.
 *   - `retry: false` because a refused request is an answer, not a blip: a 403
 *     retried three times is three denials in the audit trail for one act.
 *   - `refetchOnWindowFocus: false` because a focus event is not new
 *     information; the poller and explicit invalidations own freshness.
 */
export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5_000,
        refetchOnWindowFocus: false,
        retry: false,
      },
    },
  });
}
