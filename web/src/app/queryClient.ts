import { QueryClient } from '@tanstack/react-query';

/**
 * makeQueryClient builds the app's TanStack client with ONE set of defaults.
 *
 * There is more than one client in this app: AuthProvider owns and resets the
 * local root client, destroying all of its entries at each browser-session
 * epoch, and each open workspace gets another (#71). Both boundaries are
 * structural: cache contents die with their owning session, so same-named data
 * from different sessions or instances cannot collide merely because a query
 * key was reused. Their defaults live here once.
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
