import {
  listMyOrgsOp,
  localLoginOp,
  logoutOp,
} from '@hikyo/operations';
import { zLoginResult, zMyOrgList } from '@hikyo/zod';
import { useMutation, useQuery, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { ApiError, ok, parsed } from './client.ts';
import { useTransport } from './transport.tsx';
import { useAuth } from '../app/AuthProvider.tsx';

/**
 * loginFailureText turns a login failure into something true.
 *
 * Only a 401 is a credential refusal. Presenting a network outage, a 500 or a
 * schema violation as "wrong password" sends the human to reset a credential
 * that was never the problem — and hides a server regression behind the one
 * message nobody investigates.
 */
export function loginFailureText(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 401:
        // One sentence for every credential refusal: an unknown account and a
        // wrong password are the same fact from out here, and saying more
        // would be the account-existence oracle the server closed on purpose.
        return 'That username and password did not match. Check both and try again.';
      case 429:
        return 'Too many attempts right now. Wait a moment and try again.';
      default:
        return `Sign-in could not be completed (server error ${error.status}). Try again shortly.`;
    }
  }
  return 'Sign-in could not be completed: the server could not be reached, or it answered something this client does not understand.';
}

export type { WhoAmI } from '../app/AuthProvider.tsx';
export type LoginResult = z.infer<typeof zLoginResult>;
export type MyOrgList = z.infer<typeof zMyOrgList>;

export const orgsKey = ['orgs'] as const;

/**
 * useOrgs is the rail's data source: the organisations the caller's OWN grants
 * name.
 *
 * Deliberately NOT `listOrgs`. That one enumerates every org on the instance
 * under `instance-config`, which is MFA-mandatory — so a password-only session
 * was refused and the rail showed an empty shell with a "you need a second
 * factor" notice. That notice was the UI apologising for asking the wrong
 * question: navigation is not operator enumeration, and a member's own orgs
 * need no capability at all.
 */
export function useOrgs(enabled: boolean): UseQueryResult<MyOrgList> {
  // Transport-aware so the workspace project browser (#71) reads the REMOTE's
  // "my orgs" — the human's own grants over there — while the local nav rail,
  // rendered outside any workspace provider, still reads this instance's.
  const transport = useTransport();
  return useQuery({
    queryKey: orgsKey,
    queryFn: () => parsed(listMyOrgsOp, { ...transport }),
    enabled,
    retry: false,
  });
}

/**
 * useLogin asks for a BROWSER artifact explicitly. The server then delivers
 * the session token only on the HttpOnly cookie and its synchronizer token on
 * the readable companion — nothing replayable lands in JavaScript's hands.
 * The parsed response lets the root auth owner bind its cache epoch to the
 * returned session id without another request.
 */
export function useLogin() {
  const auth = useAuth();
  return useMutation({
    onMutate: auth.captureTransition,
    mutationFn: async (input: { username: string; password: string }) => {
      // Parsed, not discarded. The session itself arrives on cookies, but the
      // response body is still contract-bearing — a server that answered a
      // shape the document does not describe must fail here, naming the
      // member, rather than being ignored because the caller happened not to
      // need it.
      const result = await parsed(localLoginOp, {
          body: { username: input.username, password: input.password, artifact: 'browser' },
        });
      // B2 restated on the client: a browser artifact must never carry its
      // token in a script-readable body. If one ever does, that is a server
      // regression and it stops here rather than being quietly stored.
      if (result.session.artifact === 'browser' && result.session_token !== undefined) {
        throw new Error('the server returned a browser session token in the response body');
      }
      return result;
    },
    onSuccess: (identity, _input, guard) => auth.acceptSession(identity, guard),
  });
}

export function useLogout() {
  const auth = useAuth();
  return useMutation({
    onMutate: auth.captureTransition,
    mutationFn: () => ok(logoutOp, {}),
    onSuccess: (_result, _input, guard) => auth.endSession(guard),
  });
}
