import { describe, expect, it } from 'vitest';

import { z } from 'zod';

import { ApiError, parsed, readCsrfToken } from './client.ts';

// The synchronizer token is read out of a cookie string by hand, which is one
// of the few pieces of parsing the SPA does itself. A cookie header is a
// hostile little format — leading spaces, other cookies with overlapping
// prefixes, values containing '=' — and getting it wrong means every mutation
// is refused with no obvious cause.
describe('readCsrfToken', () => {
  it('finds the token among other cookies', () => {
    expect(readCsrfToken('a=1; __Host-hikyo-csrf=hik_1_cs_abc; b=2')).toBe('hik_1_cs_abc');
  });

  it('is not fooled by a cookie whose name merely starts the same', () => {
    // `__Host-hikyo` is the session cookie and is HttpOnly, so it should never
    // appear here — but a prefix match would also pick up anything named
    // `__Host-hikyo-csrf-something`.
    expect(readCsrfToken('__Host-hikyo-csrf-other=nope; __Host-hikyo-csrf=yes')).toBe('yes');
  });

  it('keeps a value containing an equals sign intact', () => {
    expect(readCsrfToken('__Host-hikyo-csrf=aa=bb')).toBe('aa=bb');
  });

  it('answers empty when there is no token, rather than undefined', () => {
    // The caller sends no header on empty; `undefined` would be stringified
    // into the header as the word "undefined".
    expect(readCsrfToken('')).toBe('');
    expect(readCsrfToken('other=1')).toBe('');
  });
});

describe('parsed', () => {
  it('fails loudly when the SDK completes without an HTTP response', async () => {
    await expect(parsed(Promise.resolve({ data: 'untrusted' }), z.string())).rejects.toThrow(
      'SDK call completed without an HTTP response',
    );
  });

  it('preserves only contract-validated safe refusal detail', async () => {
    const call = Promise.resolve({
      error: {
        error: {
          code: 'bad_request',
          message: 'The request was invalid.',
          detail: 'key "LOG_LEVEL" is invalid in environment env_prod',
        },
      },
      response: new Response(null, { status: 400 }),
    });

    await expect(parsed(call, z.string())).rejects.toMatchObject({
      name: 'ApiError',
      status: 400,
      detail: 'key "LOG_LEVEL" is invalid in environment env_prod',
    } satisfies Partial<ApiError>);
  });

  it('drops malformed error bodies instead of treating prose as safe detail', async () => {
    const call = Promise.resolve({
      error: { detail: 'not the contract error shape' },
      response: new Response(null, { status: 400 }),
    });

    await expect(parsed(call, z.string())).rejects.toMatchObject({
      name: 'ApiError',
      status: 400,
      detail: undefined,
    } satisfies Partial<ApiError>);
  });
});
