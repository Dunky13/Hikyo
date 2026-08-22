import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import {
  approveCLIReauth,
  cliReauthCallbackURL,
  loadCLIReauthTransaction,
} from '../api/cliReauth.ts';
import { useTotpStatus } from '../api/account.ts';
import { useAuth } from '../app/AuthProvider.tsx';
import {
  runAdapterPasskeyCeremony,
  runAdapterTOTPCeremony,
  runPasskeyCeremony,
  runTOTPCeremony,
} from '../api/values.ts';
import { Login } from './Login.tsx';

/** Browser half of the CLI's state + PKCE reauthentication handoff. */
export function CLIReauth() {
  const auth = useAuth();
  const [state] = useState(
    () => new URLSearchParams(globalThis.location.search).get('transaction') ?? '',
  );
  const [totp, setTOTP] = useState('');
  const totpStatus = useTotpStatus();
  const transaction = useQuery({
    queryKey: ['cli-reauth', state] as const,
    queryFn: () => loadCLIReauthTransaction(state),
    enabled: state !== '' && auth.state.status === 'authenticated',
    retry: false,
  });
  const approve = useMutation({
    mutationFn: async () => {
      const handoff = transaction.data;
      if (handoff === undefined) {
        throw new Error('the CLI authorization transaction is unavailable');
      }
      const environmentIds = handoff.environments.map((environment) => environment.environment_id);
      if (handoff.purpose === 'adapter') {
        if (handoff.environments.some((environment) => !environment.requires_webauthn)) {
          await runAdapterTOTPCeremony(adapterOperation(handoff.operation), environmentIds, totp);
        }
        for (const environment of handoff.environments.filter(
          (candidate) => candidate.requires_webauthn,
        )) {
          await runAdapterPasskeyCeremony({
            operation: adapterOperation(handoff.operation),
            environmentId: environment.environment_id,
            environmentIds,
          });
        }
      } else {
        // A disclosure handoff: the SAME purpose-bound, enumerated-key-set
        // ceremony the Values page runs, one decision per environment over
        // exactly the keys the terminal named. A 0-window environment takes
        // the passkey; a sliding environment accepts the authenticator code.
        // A sliding environment takes the passkey too, or an authenticator
        // code where one was typed - the code opens the environment-wide
        // window TOTP always opens (human-auth ADR: TOTP is a per-step gate,
        // not a per-operation one), never a per-key decision.
        for (const environment of handoff.environments) {
          if (!environment.requires_webauthn && totp.trim() !== '') {
            await runTOTPCeremony(environment.environment_id, totp.trim());
          } else {
            await runPasskeyCeremony({
              operation: handoff.purpose,
              environmentId: environment.environment_id,
              keyIds: handoff.key_ids,
            });
          }
        }
      }
      const approved = await approveCLIReauth(handoff.state);
      globalThis.location.assign(cliReauthCallbackURL(handoff, approved));
    },
  });

  if (state === '') {
    return <CLIReauthMessage title="Nothing to authorize" text="This page has no CLI transaction. Return to the terminal and start again." />;
  }
  if (auth.state.status === 'checking' || auth.state.status === 'transitioning') {
    return <p className="login" role="status">Loading…</p>;
  }
  if (auth.state.status === 'anonymous') {
    return <Login />;
  }

  const disclosure = transaction.data !== undefined && transaction.data.purpose !== 'adapter';
  const slidingEnvironments =
    transaction.data?.environments.filter((environment) => !environment.requires_webauthn) ?? [];
  // An adapter handoff needs a code for every sliding environment (its
  // ceremony is TOTP-or-passkey per policy, as before). A disclosure handoff
  // offers the code only where it can do anything - a sliding environment and
  // an enrolled authenticator - and the passkey otherwise.
  const hasTotp = totpStatus.isSuccess && totpStatus.data.confirmed;
  const requiresTOTP = !disclosure && slidingEnvironments.length > 0;
  const offersTOTP = disclosure && slidingEnvironments.length > 0 && hasTotp;

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
              {transaction.data.purpose === 'adapter' ? (
                <>
                  Approve <span className="mono">{transaction.data.operation}</span> for the
                  environments below.
                </>
              ) : (
                <>
                  The terminal asks to <strong>{transaction.data.purpose}</strong>{' '}
                  {transaction.data.key_ids.length} key
                  {transaction.data.key_ids.length === 1 ? '' : 's'} in the environments below.
                  {offersTOTP
                    ? ' A passkey authorises one decision over exactly those keys. A code from your authenticator instead opens the environment-wide window the policy allows, for its duration.'
                    : ' A passkey authorises one decision over exactly those keys; nothing else.'}
                </>
              )}
            </p>
            {transaction.data.purpose !== 'adapter' ? (
              <ul className="mono">
                {transaction.data.key_ids.map((keyId) => (
                  <li key={keyId}>{keyId}</li>
                ))}
              </ul>
            ) : null}
            <ul>
              {transaction.data.environments.map((environment) => (
                <li key={environment.environment_id}>
                  <span className="mono">{environment.environment_id}</span>{' '}
                  — {environment.requires_webauthn ? 'passkey required' : 'TOTP required'}
                </li>
              ))}
            </ul>
            {requiresTOTP || offersTOTP ? (
              <div className="field">
                <label htmlFor="cli-reauth-totp">
                  {requiresTOTP ? 'Authenticator code' : 'Authenticator code (optional; leave empty to use a passkey)'}
                </label>
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

type AdapterOperation = 'adapter.configure' | 'adapter.credential-set' | 'adapter.adopt' | 'adapter.sync';

/** adapterOperation narrows the transaction's operation to the adapter set without a cast. */
function adapterOperation(operation: string): AdapterOperation {
  switch (operation) {
    case 'adapter.configure':
    case 'adapter.credential-set':
    case 'adapter.adopt':
    case 'adapter.sync':
      return operation;
    default:
      throw new Error(`an adapter handoff named a non-adapter operation: ${operation}`);
  }
}
