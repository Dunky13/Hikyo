import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import {
  approveCLIReauth,
  cliReauthCallbackURL,
  loadCLIReauthTransaction,
} from '../api/cliReauth.ts';
import { useSession } from '../api/session.ts';
import { runAdapterPasskeyCeremony, runAdapterTOTPCeremony } from '../api/values.ts';
import { Login } from './Login.tsx';

/** Browser half of the CLI's state + PKCE reauthentication handoff. */
export function CLIReauth() {
  const session = useSession();
  const [state] = useState(
    () => new URLSearchParams(globalThis.location.search).get('transaction') ?? '',
  );
  const [totp, setTOTP] = useState('');
  const transaction = useQuery({
    queryKey: ['cli-reauth', state] as const,
    queryFn: () => loadCLIReauthTransaction(state),
    enabled: state !== '' && session.data !== null,
    retry: false,
  });
  const approve = useMutation({
    mutationFn: async () => {
      const handoff = transaction.data;
      if (handoff === undefined) {
        throw new Error('the CLI authorization transaction is unavailable');
      }
      const environmentIds = handoff.environments.map((environment) => environment.environment_id);
      if (handoff.environments.some((environment) => !environment.requires_webauthn)) {
        await runAdapterTOTPCeremony(handoff.operation, environmentIds, totp);
      }
      for (const environment of handoff.environments.filter(
        (candidate) => candidate.requires_webauthn,
      )) {
        await runAdapterPasskeyCeremony({
          operation: handoff.operation,
          environmentId: environment.environment_id,
          environmentIds,
        });
      }
      const approved = await approveCLIReauth(handoff.state);
      globalThis.location.assign(cliReauthCallbackURL(handoff, approved));
    },
  });

  if (state === '') {
    return <CLIReauthMessage title="Nothing to authorize" text="This page has no CLI transaction. Return to the terminal and start again." />;
  }
  if (session.isPending) {
    return <p className="login" role="status">Loading…</p>;
  }
  if (session.isSuccess && session.data === null) {
    return <Login />;
  }

  const requiresTOTP =
    transaction.data?.environments.some((environment) => !environment.requires_webauthn) ?? false;

  return (
    <main className="login">
      <div className="login__card">
        <h1 className="login__title">Authorize CLI</h1>
        {transaction.isPending ? <p role="status">Loading authorization policy…</p> : null}
        {transaction.isError ? (
          <p className="alert" role="alert"><span className="alert__glyph" aria-hidden="true">!</span><span>This CLI transaction is invalid, expired, or already used. Return to the terminal and start again.</span></p>
        ) : null}
        {transaction.data !== undefined ? (
          <>
            <p className="login__lede">
              Approve <span className="mono">{transaction.data.operation}</span> for the environments below.
            </p>
            <ul>
              {transaction.data.environments.map((environment) => (
                <li key={environment.environment_id}>
                  <span className="mono">{environment.environment_id}</span>{' '}
                  — {environment.requires_webauthn ? 'passkey required' : 'TOTP required'}
                </li>
              ))}
            </ul>
            {requiresTOTP ? (
              <div className="field">
                <label htmlFor="cli-reauth-totp">Authenticator code</label>
                <input id="cli-reauth-totp" inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={(event) => setTOTP(event.target.value)} required />
              </div>
            ) : null}
            {approve.isError ? <p className="alert" role="alert"><span className="alert__glyph" aria-hidden="true">!</span><span>Authorization failed. No CLI credential was disclosed; return to the terminal and try again.</span></p> : null}
            <button className="btn btn--primary" type="button" disabled={approve.isPending || (requiresTOTP && totp.trim() === '')} onClick={() => approve.mutate()}>
              {approve.isPending ? 'Authorizing…' : 'Authorize CLI'}
            </button>
            <button className="btn" type="button" onClick={() => globalThis.close()}>Cancel</button>
          </>
        ) : null}
      </div>
    </main>
  );
}

function CLIReauthMessage(input: { title: string; text: string }) {
  return (
    <main className="login"><div className="login__card"><h1 className="login__title">{input.title}</h1><p className="alert" role="alert"><span className="alert__glyph" aria-hidden="true">!</span><span>{input.text}</span></p></div></main>
  );
}
