import { describe, expect, it } from 'vitest';

import { cliReauthCallbackURL } from './cliReauth.ts';

describe('CLI reauthentication callback binding', () => {
  const transaction = {
    state: 'hik_1_hs_opaque',
    operation: 'adapter.sync' as const,
    environments: [
      { environment_id: 'env_one', effective_window_seconds: 0, requires_webauthn: true },
    ],
    purpose: 'adapter' as const,
    key_ids: [] as string[],
    redirect_uri: 'http://127.0.0.1:43123/callback',
    expires_at: '2026-08-17T22:10:00Z',
  };

  it('redirects only code and the exact same opaque state to the bound loopback URI', () => {
    expect(
      cliReauthCallbackURL(transaction, {
        code: 'hik_1_hc_single_use',
        state: transaction.state,
        redirect_uri: transaction.redirect_uri,
      }),
    ).toBe(
      'http://127.0.0.1:43123/callback?code=hik_1_hc_single_use&state=hik_1_hs_opaque',
    );
  });

  it('refuses state or redirect substitution', () => {
    expect(() =>
      cliReauthCallbackURL(transaction, {
        code: 'code',
        state: 'different',
        redirect_uri: transaction.redirect_uri,
      }),
    ).toThrow(/did not match/);
    expect(() =>
      cliReauthCallbackURL(transaction, {
        code: 'code',
        state: transaction.state,
        redirect_uri: 'http://127.0.0.1:9/callback',
      }),
    ).toThrow(/did not match/);
  });
});
