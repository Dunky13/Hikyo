import {
  addRemote,
  addWorkspaceOrigin,
  listMySessions,
  listRemotes,
  listWorkspaceOrigins,
  removeRemote,
  removeWorkspaceOrigin,
  renameRemote,
  revokeMySession,
} from '@hikyo/client';
import {
  zRemote,
  zRemoteList,
  zSessionList,
  zWorkspaceOrigin,
  zWorkspaceOriginList,
  zWorkspaceOriginRemoved,
} from '@hikyo/zod';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { ok, parsed } from './client.ts';

/**
 * The multi-instance surfaces' same-origin data (#71).
 *
 * Everything here talks to THIS instance and nothing else. The two halves it
 * serves are deliberately different instances' concerns and only look alike:
 *
 *   - `useRemotes` is the VIEWING side — the entries this instance holds and
 *     the last-known directory of each. The fetch to the remote happens on the
 *     server, under a pinned connection; the browser never touches it.
 *   - `useWorkspaceOrigins` is the SERVING side — the origins this instance
 *     consents to be operated from. Removing one is the ADR's atomic kill
 *     switch, not a headers change.
 *
 * The cross-origin half of the workspace tier lives in `workspace.ts`, because
 * it must not go through this module's client at all: that one carries cookies
 * and a synchronizer token, and neither may cross an origin.
 */

export type Remote = z.infer<typeof zRemote>;
export type RemoteList = z.infer<typeof zRemoteList>;
export type WorkspaceOrigin = z.infer<typeof zWorkspaceOrigin>;
export type SessionList = z.infer<typeof zSessionList>;
export type ActiveSession = SessionList['items'][number];

export const remotesKey = ['remotes'] as const;
export const originsKey = ['workspace-origins'] as const;
export const sessionsKey = ['sessions'] as const;

/**
 * The directory refresh cadence.
 *
 * POLLING, and that is a locked decision rather than a shortcut: the update
 * channel is `EventSource`, native `EventSource` cannot set an `Authorization`
 * header, and the ADR's answer is the polling fallback the architecture already
 * ships — never a weakened SSE authentication.
 *
 * TWENTY seconds because the per-viewer trigger budget is 6/min and a human has
 * more than one tab: 3/min per tab keeps two tabs of the same human inside it.
 * A third tab, or jitter across the window edge, spends the budget — and that
 * degrades to a snapshot marked stale with its age, which is the freshness
 * model working, not an error. It is still a rate worth staying under: a card
 * that is quietly rate-limited refreshes no faster than one that is not.
 */
const DIRECTORY_POLL_MS = 20_000;

/** useRemotes is the directory card list, refreshed on a poll. */
export function useRemotes(): UseQueryResult<RemoteList> {
  return useQuery({
    queryKey: remotesKey,
    queryFn: () => parsed(listRemotes(), zRemoteList),
    refetchInterval: DIRECTORY_POLL_MS,
    retry: false,
  });
}

export function useAddRemote() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string; url: string; spkiPin: string; credential: string }) =>
      parsed(
        addRemote({
          body: {
            name: input.name,
            url: input.url,
            spki_pin: input.spkiPin,
            credential: input.credential,
          },
        }),
        zRemote,
      ),
    onSuccess: () => queries.invalidateQueries({ queryKey: remotesKey }),
  });
}

export function useRenameRemote() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { remote: string; name: string }) =>
      parsed(
        renameRemote({ path: { remote: input.remote }, body: { name: input.name } }),
        zRemote,
      ),
    onSuccess: () => queries.invalidateQueries({ queryKey: remotesKey }),
  });
}

export function useRemoveRemote() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (remote: string) => ok(removeRemote({ path: { remote } })),
    onSuccess: () => queries.invalidateQueries({ queryKey: remotesKey }),
  });
}

/** useWorkspaceOrigins is the serving side's consent list. */
export function useWorkspaceOrigins(): UseQueryResult<z.infer<typeof zWorkspaceOriginList>> {
  return useQuery({
    queryKey: originsKey,
    queryFn: () => parsed(listWorkspaceOrigins(), zWorkspaceOriginList),
    retry: false,
  });
}

export function useAddWorkspaceOrigin() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (origin: string) =>
      parsed(addWorkspaceOrigin({ body: { origin } }), zWorkspaceOrigin),
    onSuccess: () => queries.invalidateQueries({ queryKey: originsKey }),
  });
}

/**
 * useRemoveWorkspaceOrigin is the KILL SWITCH. The response carries the number
 * of workspace sessions it revoked, and the UI says that number out loud: an
 * operator pulling consent needs to see what it cost, and "removed" alone hides
 * whether anyone was mid-flight.
 */
export function useRemoveWorkspaceOrigin() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (origin: string) =>
      parsed(removeWorkspaceOrigin({ body: { origin } }), zWorkspaceOriginRemoved),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: originsKey });
      void queries.invalidateQueries({ queryKey: sessionsKey });
    },
  });
}

/** useSessions is the caller's OWN active sessions, workspace ones included. */
export function useSessions(): UseQueryResult<SessionList> {
  return useQuery({
    queryKey: sessionsKey,
    queryFn: () => parsed(listMySessions(), zSessionList),
    retry: false,
  });
}

export function useRevokeSession() {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (session: string) => ok(revokeMySession({ path: { session } })),
    onSuccess: () => queries.invalidateQueries({ queryKey: sessionsKey }),
  });
}

/** originOf is a remote's browser origin: the popup's destination. */
export function originOf(url: string): string {
  return new URL(url).origin;
}

/** safeOriginOf never throws on a stored URL the browser cannot parse. */
export function safeOriginOf(url: string): string {
  try {
    return originOf(url);
  } catch {
    return url;
  }
}

/**
 * remoteStateText is the human sentence for each of the seven closed states.
 *
 * The card must never carry a state by colour alone, so this text IS the state
 * — the colour is decoration on top of it. `credential-rejected` is called out
 * as its own loud sentence rather than folded into "unreachable": the two have
 * completely different fixes, and an operator who reads "unreachable" will go
 * and check the network.
 */
export function remoteStateText(remote: Remote): string {
  switch (remote.state) {
    case 'ok':
      return 'Reachable';
    case 'unreachable':
      return 'Unreachable';
    case 'credential-rejected':
      return 'Credential rejected — this instance is reachable and is refusing our credential. Mint a new one there and re-add the entry.';
    case 'pin-mismatch':
      return 'Certificate pin mismatch — the key at that URL is not the one this entry pinned. Do not re-add until you know why.';
    case 'redirect-refused':
      return 'Refused: that URL answered a redirect, and a directory fetch never follows one.';
    case 'identity-conflict':
      return 'Identity conflict — that URL now answers as a different instance than the one this entry was added for.';
    case 'self-connected':
      return 'This entry points at this instance itself.';
  }
}

/**
 * stalenessText is the "unreachable for Xh — showing last known" sentence.
 *
 * It is derived from `stale_for_seconds`, which the server computes from the
 * OUTCOME rather than from the age: a snapshot that is old because nothing
 * changed is not stale, and a snapshot that is one minute old because the last
 * fetch failed is.
 */
export function stalenessText(remote: Remote): string | null {
  if (!remote.stale) {
    return null;
  }
  const seconds = remote.stale_for_seconds ?? 0;
  return `Showing the last known directory, ${humanAge(seconds)} old.`;
}

function humanAge(seconds: number): string {
  if (seconds < 90) {
    return `${Math.max(seconds, 0)} seconds`;
  }
  if (seconds < 5400) {
    return `${Math.round(seconds / 60)} minutes`;
  }
  if (seconds < 172_800) {
    return `${Math.round(seconds / 3600)} hours`;
  }
  return `${Math.round(seconds / 86_400)} days`;
}
