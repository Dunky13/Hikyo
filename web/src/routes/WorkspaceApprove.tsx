import { approveWorkspaceHandoffOp, showWorkspaceHandoffOp } from '@hikyo/operations';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';

import { parsed } from '../api/client.ts';
import { useAuth } from '../app/AuthProvider.tsx';
import { ceremonyRefusalText, runPasskeyCeremony, runTOTPCeremony } from '../api/values.ts';
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
 * Two shapes land here, distinguished by the `purpose` the transaction was
 * opened under:
 *
 *  - **establishment** — a first workspace. The human is signed in (or signs in
 *    here, in place) and approves; the redemption mints a workspace session.
 *  - **step-up** — an ELEVATION of a workspace already open. A disclosure over
 *    there needs a fresh reauthentication over here first, so the human runs
 *    THIS instance's own #58 ceremony over the bound environment — which opens
 *    the reauth window the approval's server-side freshness gate then requires —
 *    and only then approves. The environment and key set ride the URL for the
 *    ceremony to name; the server validates the fresh window against the
 *    transaction's OWN bound environment, so a tampered parameter only fails
 *    closed.
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
  const auth = useAuth();
  const [query] = useState(() => new URLSearchParams(globalThis.location.search));
  const state = query.get('state') ?? '';
  const isStepUp = query.get('purpose') === 'step-up';

  // The step-up's operation, environment and enumerated key set come from the
  // SERVER-BOUND transaction, read by state — never from the URL, which carries
  // only the state and the tiny purpose flag. That is what keeps a large
  // reveal-all off the URL-length ceiling, and it makes the binding
  // authoritative: nothing the popup was handed decides the elevation's scope.
  // Gated on a session, because the read requires one (a step-up always has it).
  const transaction = useQuery({
    queryKey: ['workspace-handoff', state],
    queryFn: () => parsed(showWorkspaceHandoffOp, { path: { state } }),
    enabled: isStepUp && state !== '' && auth.state.status === 'authenticated',
    retry: false,
  });

  const approve = useMutation({
    mutationFn: async () => {
      const result = await parsed(approveWorkspaceHandoffOp, { body: { state } });
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

  if (auth.state.status === 'checking' || auth.state.status === 'transitioning') {
    return (
      <p className="login" role="status">
        Loading…
      </p>
    );
  }

  // No session on THIS instance: authenticate here, on this origin, with this
  // instance's own ceremonies. The URL — and with it the state — survives.
  if (auth.state.status === 'anonymous') {
    return <Login />;
  }

  const name = auth.identity?.principal.display_name ?? auth.identity?.principal.id ?? '';

  return (
    <main className="login">
      <div className="login__card">
        <h1 className="login__title">
          {isStepUp ? 'Authorize this disclosure' : 'Authorize this workspace'}
        </h1>
        <p className="login__lede">
          {isStepUp ? (
            <>
              Signed in as <span className="mono">{name}</span>. A workspace you have open elsewhere
              is asking to <strong>{transaction.data?.operation ?? 'disclose'}</strong> over{' '}
              {(transaction.data?.key_ids.length ?? 0) === 0
                ? 'this environment'
                : `${transaction.data?.key_ids.length} key${transaction.data?.key_ids.length === 1 ? '' : 's'}`}
              . Reauthenticate here to allow it — this is a disclosure, not a new sign-in, and it
              covers only this one act.
            </>
          ) : (
            <>
              Signed in as <span className="mono">{name}</span>. Approving lets the site you started
              from operate this instance <strong>as you</strong>, for as long as the session lives or
              until it is revoked. Everything it does will appear in this instance&apos;s audit trail
              under your name.
            </>
          )}
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

        {isStepUp ? (
          transaction.isError ? (
            <p className="alert" role="alert">
              <span className="alert__glyph" aria-hidden="true">
                !
              </span>
              <span>
                This authorization request could not be read — it may have expired or been used
                already. Close this window and start again from the instance you were browsing.
              </span>
            </p>
          ) : transaction.data === undefined ? (
            <p role="status">Loading…</p>
          ) : (
            <StepUpReauth
              operation={transaction.data.operation ?? 'reveal'}
              environmentId={transaction.data.environment ?? ''}
              keyIds={transaction.data.key_ids}
              onReauthed={() => approve.mutate()}
              approving={approve.isPending}
            />
          )
        ) : (
          <>
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
          </>
        )}
      </div>
    </main>
  );
}

/**
 * StepUpReauth runs THIS instance's own #58 reauthentication over the bound
 * environment, then hands off to the approval.
 *
 * It offers a passkey and a code both, and does not try to know in advance which
 * the environment allows: a protected environment refuses the code with a 409
 * the ceremony copy already explains, and asking the server is one more request
 * that can fail before the human has done anything. On success the reauth window
 * is open on this session and the approval's freshness gate will accept it.
 */
function StepUpReauth({
  operation,
  environmentId,
  keyIds,
  onReauthed,
  approving,
}: {
  operation: string;
  environmentId: string;
  keyIds: readonly string[];
  onReauthed: () => void;
  approving: boolean;
}) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const signed = operation === 'copy' ? 'copy' : operation === 'publish' ? 'publish' : 'reveal';

  const attempt = async (run: () => Promise<void>) => {
    setBusy(true);
    setFailure(null);
    try {
      await run();
      // Reauth is done; hand off to the approval and release our own busy flag
      // so `working` now reflects only the approve mutation. If that mutation
      // fails (an expired or already-consumed transaction), the buttons must
      // come back — leaving busy latched here would strand the human with Cancel
      // disabled and no way out but closing the window.
      setBusy(false);
      onReauthed();
    } catch (err) {
      setFailure(ceremonyRefusalText(err));
      setBusy(false);
    }
  };

  const onPasskey = () =>
    void attempt(() =>
      runPasskeyCeremony({ operation: signed, environmentId, keyIds: [...keyIds] }),
    );

  const onCode = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void attempt(() => runTOTPCeremony(environmentId, code));
  };

  const working = busy || approving;

  return (
    <>
      {failure === null ? null : (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{failure}</span>
        </p>
      )}
      <div className="ceremony__actions">
        <button className="btn btn--primary" type="button" onClick={onPasskey} disabled={working}>
          {working ? 'Working…' : 'Use a passkey'}
        </button>
        <button className="btn" type="button" onClick={() => globalThis.close()} disabled={working}>
          Cancel
        </button>
      </div>
      <form className="ceremony__totp" onSubmit={onCode}>
        <div className="field">
          <label htmlFor="approve-code">Or a code from your authenticator</label>
          <input
            id="approve-code"
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </div>
        <button className="btn" type="submit" disabled={working || code.length < 6}>
          Authorise with a code
        </button>
      </form>
    </>
  );
}
