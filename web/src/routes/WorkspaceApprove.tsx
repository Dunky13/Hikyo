import { approveWorkspaceHandoff } from '@hikyo/client';
import { zWorkspaceHandoffApproved } from '@hikyo/zod';
import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';

import { parsed } from '../api/client.ts';
import { useSession } from '../api/session.ts';
import { Login } from './Login.tsx';

/**
 * The SERVING instance's authorization page (registry surface
 * `workspace-approve`).
 *
 * This is the page the popup lands on, served by the instance being operated,
 * on that instance's own origin. Everything about the human's authentication
 * happens here and only here: this instance's password, its TOTP, its passkeys,
 * its OIDC — never the viewing instance's, which has no way to authenticate to
 * this one and no code path that could.
 *
 * Three details are load-bearing:
 *
 *  1. **It renders the sign-in form itself when there is no session.** A first
 *     establishment arrives with no cookies for this instance, and redirecting
 *     to `/login` would drop the `state` this transaction is addressed by.
 *  2. **Approval is an ordinary same-origin, cookie-authenticated POST** with
 *     the synchronizer token — the shared client's rules, unchanged. Nothing
 *     the viewing origin sent is trusted here beyond the opaque state value,
 *     which the server resolves against its own transaction row.
 *  3. **The redirect target comes from the SERVER**, never from the URL. The
 *     callback authority is the allowlist entry the transaction was opened
 *     against; a redirect URI supplied by whoever opened this page would be an
 *     open redirector with a fresh authorization code attached.
 */
export function WorkspaceApprove() {
  const session = useSession();
  const [state] = useState(() => new URLSearchParams(globalThis.location.search).get('state') ?? '');

  const approve = useMutation({
    mutationFn: async () => {
      const result = await parsed(
        approveWorkspaceHandoff({ body: { state } }),
        zWorkspaceHandoffApproved,
      );
      // The code goes to the pre-registered callback and nowhere else. Building
      // the URL from the SERVER's `redirect_uri` is what makes that true.
      const target = new URL(result.redirect_uri);
      target.searchParams.set('code', result.code);
      target.searchParams.set('state', state);
      globalThis.location.assign(target.toString());
    },
  });

  if (state === '') {
    return (
      <main className="login">
        <div className="login__card">
          <h1 className="login__title">Nothing to authorize</h1>
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>
              This page was opened without a handoff transaction. Start the workspace from the
              instance you were browsing.
            </span>
          </p>
        </div>
      </main>
    );
  }

  if (session.isPending) {
    return (
      <p className="login" role="status">
        Loading…
      </p>
    );
  }

  // No session on THIS instance: authenticate here, on this origin, with this
  // instance's own ceremonies. The URL — and with it the state — survives.
  if (session.isSuccess && session.data === null) {
    return <Login />;
  }

  const name = session.data?.principal.display_name ?? session.data?.principal.id ?? '';

  return (
    <main className="login">
      <div className="login__card">
        <h1 className="login__title">Authorize this workspace</h1>
        <p className="login__lede">
          Signed in as <span className="mono">{name}</span>. Approving lets the site you started
          from operate this instance <strong>as you</strong>, for as long as the session lives or
          until it is revoked. Everything it does will appear in this instance&apos;s audit trail
          under your name.
        </p>

        {approve.isError ? (
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>
              That authorization could not be completed. The transaction may have expired or been
              used already — close this window and start again.
            </span>
          </p>
        ) : null}

        <button
          className="btn btn--primary"
          type="button"
          onClick={() => approve.mutate()}
          disabled={approve.isPending}
        >
          {approve.isPending ? 'Authorizing…' : 'Authorize'}
        </button>
        <button className="btn" type="button" onClick={() => globalThis.close()}>
          Cancel
        </button>
      </div>
    </main>
  );
}
