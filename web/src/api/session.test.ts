import { describe, expect, it } from 'vitest';

import { ApiError } from './client.ts';
import { loginFailureText } from './session.ts';

// Presenting every failure as "wrong password" is the bug this maps around: it
// sends the human to reset a credential that was never the problem, and it
// hides a server regression behind the one message nobody investigates.
describe('loginFailureText', () => {
  it('calls a 401 a credential refusal, without saying which half was wrong', () => {
    const text = loginFailureText(new ApiError(401, 'nope'));
    expect(text).toContain('username and password');
    expect(text).not.toMatch(/unknown|no such|does not exist/i);
  });

  it('calls a 429 a throttle', () => {
    expect(loginFailureText(new ApiError(429, 'slow down'))).toContain('Too many attempts');
  });

  it('does not blame the credential for a server error', () => {
    const text = loginFailureText(new ApiError(500, 'boom'));
    expect(text).toContain('500');
    expect(text).not.toContain('username and password');
  });

  it('does not blame the credential for a network or schema failure', () => {
    for (const err of [new TypeError('Failed to fetch'), new Error('zod: invalid_type')]) {
      const text = loginFailureText(err);
      expect(text).not.toContain('username and password');
      expect(text).toContain('could not be completed');
    }
  });
});
