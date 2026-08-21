import { createClient, createConfig, type Client } from '@hikyo/runtime-core';

import { dropWorkspaceValue, workspaceBearer, WorkspaceError } from './workspace.ts';

/**
 * The workspace tier's DATA transport (#71, multi-instance ADR § What the
 * workspace is, and is not).
 *
 * The shell renders a remote's data with its OWN components against the
 * remote's ordinary `/api/v1` — the same generated SDK the shell uses on
 * itself, pointed at another origin. That redirection is this file: a second
 * hey-api client, one per remote origin, that the api-wrapper hooks pass as
 * `options.client` so the exact same `listValues`/`setValue`/`revealValue`
 * call talks to the remote instead of home.
 *
 * It shares NOTHING with the same-origin singleton in `client.ts`, and the
 * differences are load-bearing, not stylistic:
 *
 *   - `credentials: 'omit'` — the workspace bearer rides an `Authorization`
 *     header precisely so cookies never cross the origin. Omit is what keeps
 *     the remote's CORS out of credentials mode and its CSRF posture untouched.
 *   - NO synchronizer-token interceptor — that token is a cookie-session
 *     defence and there is no cookie here; echoing this instance's CSRF token
 *     to a foreign server would leak it for nothing.
 *   - the bearer is read from the LIVE store at request time, never captured at
 *     client creation — a reconnect (or a step-up, which rotates the bearer in
 *     place) must be picked up by the very next call, not stranded behind a
 *     value frozen when the client was built.
 */

/**
 * createWorkspaceClient builds the origin-scoped transport for one remote.
 *
 * `origin` is a bare `https://host[:port]` — the same canonical origin the
 * bearer is stored under. Every call this client makes appends the contract's
 * own path to it; the origin itself is never taken from anything a foreign
 * server said.
 */
export function createWorkspaceClient(origin: string): Client {
  const client = createClient(
    createConfig({
      baseUrl: origin,
      // See the file comment: this is the whole reason the workspace tier can
      // exist without a server-side proxy and without touching CSRF.
      credentials: 'omit',
    }),
  );

  // Which bearer VALUE each in-flight request was sent under, so a 401 for a
  // credential that has since been rotated cannot drop its replacement. Keyed
  // by the Request object the interceptors share; entries fall away with the
  // request. The value, not the session id — a step-up rotates the value under
  // a stable session id, and only the exact value that was rejected is dead.
  const sentUnder = new WeakMap<Request, string>();

  client.interceptors.request.use((request) => {
    const bearer = workspaceBearer(origin);
    if (bearer === undefined) {
      // FAIL CLOSED. No bearer means no workspace: rather than let a call go
      // out unauthenticated (or, worse, pick up an ambient credential), refuse
      // it here. The provider renders the reconnect state whenever the bearer
      // is gone, so in practice a live view never reaches this — but a race
      // between a drop and an in-flight render must not leak an anonymous
      // request to a foreign origin.
      throw new WorkspaceError(
        'This workspace is no longer connected. Reconnect to the remote to continue.',
      );
    }
    request.headers.set('Authorization', `Bearer ${bearer.value}`);
    sentUnder.set(request, bearer.value);
    return request;
  });

  client.interceptors.response.use((response, request) => {
    if (response.status === 401 || response.status === 403) {
      const value = sentUnder.get(request);
      if (value !== undefined) {
        // The remote has stopped honouring this bearer. Drop it now — the
        // kill switch bites at the next request the ADR promises, and this is
        // that request — so the shell shows "reconnect" without waiting for
        // the liveness poll to notice.
        dropWorkspaceValue(origin, value);
      }
    }
    return response;
  });

  return client;
}
