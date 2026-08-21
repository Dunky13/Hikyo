import { useState, type FormEvent } from 'react';

import { loginFailureText, useLogin } from '../api/session.ts';
import { passkeysAvailable, stepUpFailureText, usePasskeyLogin } from '../api/stepup.ts';

/**
 * The local password login page.
 *
 * Scope is the local floor and nothing else: #54 shipped OIDC, passkeys, TOTP
 * and recovery, and each of those gets its own surface in its own ticket. What
 * this page owes the rest of the system is a browser session established the
 * way the server actually mints one.
 *
 * Refusal presentation follows the locked rule that no state is carried by
 * colour alone: the message is text, it is announced through `role="alert"`,
 * and it carries a glyph. The wording never distinguishes an unknown account
 * from a wrong password, because the server deliberately does not either.
 */
export function Login() {
  const login = useLogin();
  const passkey = usePasskeyLogin();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    login.mutate({ username, password });
  };

  return (
    <main className="login">
      <form className="login__card" onSubmit={onSubmit} noValidate>
        <h1 className="login__title">Sign in to Hikyo</h1>
        <p className="login__lede">Use the credential you established with your setup authority.</p>

        {login.isError ? (
          <p className="alert" role="alert">
            <span className="alert__glyph" aria-hidden="true">
              !
            </span>
            <span>{loginFailureText(login.error)}</span>
          </p>
        ) : null}

        <div className="field">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>

        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <button className="btn btn--primary" type="submit" disabled={login.isPending}>
          {login.isPending ? 'Signing in…' : 'Sign in'}
        </button>
        {passkeysAvailable() ? (
          <>
            <p className="login__or" aria-hidden="true">
              or
            </p>
            <button
              className="btn"
              type="button"
              onClick={() => passkey.mutate()}
              disabled={login.isPending || passkey.isPending}
            >
              {passkey.isPending ? 'Waiting for the passkey…' : 'Use a passkey instead'}
            </button>
            {passkey.isError ? (
              <p className="alert" role="alert">
                <span className="alert__glyph" aria-hidden="true">
                  !
                </span>
                <span>{stepUpFailureText(passkey.error)}</span>
              </p>
            ) : null}
          </>
        ) : null}
      </form>
    </main>
  );
}
