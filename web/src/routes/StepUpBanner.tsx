import { useState, type FormEvent } from 'react';

import { usePasskeys, useTotpStatus } from '../api/account.ts';
import type { WhoAmI } from '../api/session.ts';
import {
  hasSecondFactor,
  passkeysAvailable,
  stepUpFailureText,
  useStepUpPasskey,
  useStepUpTotp,
} from '../api/stepup.ts';

/**
 * StepUpBanner is the shell's second-factor affordance.
 *
 * A browser session is minted at password assurance (the login page asks for
 * nothing else, by design: the local floor must work with no second factor
 * enrolled). Every MFA-mandatory surface then refuses it — instance
 * administration, grants, reveal — and the refusal used to say "sign in again
 * and present a passkey or authenticator code", an instruction no page could
 * satisfy. This banner is that page: it sits above the content while the
 * session is short of a second factor AND the account has one to present, and
 * disappears once the step-up lands. An account with no factor enrolled sees
 * nothing here; Account & security is where a factor is enrolled, and the
 * banner must not send people there pretending a code exists.
 */
export function StepUpBanner({ session }: { session: WhoAmI }) {
  const elevated = hasSecondFactor(session);
  const totp = useTotpStatus();
  const passkeys = usePasskeys();
  const stepUpTotp = useStepUpTotp();
  const stepUpPasskey = useStepUpPasskey();
  const [code, setCode] = useState('');

  if (elevated) {
    return null;
  }
  const hasTotp = totp.isSuccess && totp.data.confirmed;
  const hasPasskey = passkeys.isSuccess && passkeys.data.passkeys.length > 0 && passkeysAvailable();
  if (!hasTotp && !hasPasskey) {
    return null;
  }
  const busy = stepUpTotp.isPending || stepUpPasskey.isPending;
  const failure = stepUpTotp.isError
    ? stepUpFailureText(stepUpTotp.error)
    : stepUpPasskey.isError
      ? stepUpFailureText(stepUpPasskey.error)
      : null;

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    stepUpTotp.mutate(code.trim(), { onSuccess: () => setCode('') });
  };

  return (
    <section className="stepup" aria-labelledby="stepup-title">
      <div className="stepup__text">
        <h2 className="stepup__title" id="stepup-title">
          This session is password-only
        </h2>
        <p className="stepup__lede">
          Instance administration, grants and secret disclosure need a second factor presented in
          this session. Present it here; nothing else about the session changes.
        </p>
      </div>
      <div className="stepup__controls">
        {hasTotp ? (
          <form className="stepup__form" onSubmit={onSubmit}>
            <label htmlFor="stepup-code">Authenticator code</label>
            <input
              id="stepup-code"
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6,10}"
              required
              value={code}
              onChange={(event) => setCode(event.target.value)}
              disabled={busy}
            />
            <button className="btn btn--primary" type="submit" disabled={busy || code.trim() === ''}>
              {stepUpTotp.isPending ? 'Checking…' : 'Present code'}
            </button>
          </form>
        ) : null}
        {hasPasskey ? (
          <button
            className="btn"
            type="button"
            onClick={() => stepUpPasskey.mutate()}
            disabled={busy}
          >
            {stepUpPasskey.isPending ? 'Waiting for the passkey…' : 'Use a passkey'}
          </button>
        ) : null}
      </div>
      {failure !== null ? (
        <p className="alert" role="alert">
          <span className="alert__glyph" aria-hidden="true">
            !
          </span>
          <span>{failure}</span>
        </p>
      ) : null}
    </section>
  );
}
