import { describe, expect, it } from 'vitest';

import { ApiError } from './client.ts';
import { accountFailureText, passkeyCreationOptions } from './account.ts';

const bytes = (source: BufferSource): number[] =>
  Array.from(
    source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength),
  );

describe('passkeyCreationOptions', () => {
  it('preserves the server policy and converts every supplied binary field', () => {
    const options = passkeyCreationOptions({
      publicKey: {
        challenge: 'AQID',
        rp: { id: 'example.test', name: 'Example RP' },
        user: { id: 'BAUG', name: 'admin', displayName: 'Administrator' },
        pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
        timeout: 12_345,
        attestation: 'direct',
        authenticatorSelection: {
          authenticatorAttachment: 'cross-platform',
          residentKey: 'preferred',
          requireResidentKey: false,
          userVerification: 'discouraged',
        },
        excludeCredentials: [
          { id: 'BwgJ', type: 'public-key', transports: ['hybrid', 'usb'] },
        ],
        extensions: {
          appid: 'https://example.test',
          credProps: true,
          hmacCreateSecret: true,
          minPinLength: true,
          largeBlob: { read: true, support: 'required', write: 'CgsM' },
          prf: { eval: { first: 'DQ4P', second: 'EBES' } },
        },
      },
    });

    expect(bytes(options.challenge)).toEqual([1, 2, 3]);
    expect(bytes(options.user.id)).toEqual([4, 5, 6]);
    expect(options.rp).toEqual({ id: 'example.test', name: 'Example RP' });
    expect(options.pubKeyCredParams).toEqual([{ type: 'public-key', alg: -8 }]);
    expect(options.timeout).toBe(12_345);
    expect(options.attestation).toBe('direct');
    expect(options.authenticatorSelection).toEqual({
      authenticatorAttachment: 'cross-platform',
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'discouraged',
    });
    expect(options.excludeCredentials?.[0]?.transports).toEqual(['hybrid', 'usb']);
    expect(bytes(options.excludeCredentials?.[0]?.id ?? new ArrayBuffer())).toEqual([7, 8, 9]);
    expect(options.extensions?.appid).toBe('https://example.test');
    expect(bytes(options.extensions?.largeBlob?.write ?? new ArrayBuffer())).toEqual([10, 11, 12]);
    expect(bytes(options.extensions?.prf?.eval?.first ?? new ArrayBuffer())).toEqual([13, 14, 15]);
    expect(bytes(options.extensions?.prf?.eval?.second ?? new ArrayBuffer())).toEqual([16, 17, 18]);
  });

  it('rejects malformed excluded credentials instead of silently dropping them', () => {
    expect(() =>
      passkeyCreationOptions({
        challenge: 'AQID',
        rp: { name: 'Example RP' },
        user: { id: 'BAUG', name: 'admin', displayName: 'Administrator' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        excludeCredentials: [{ type: 'public-key' }],
      }),
    ).toThrow(/excluded credential.*id/i);
  });

  it('rejects missing required policy instead of inventing defaults', () => {
    expect(() =>
      passkeyCreationOptions({
        challenge: 'AQID',
        rp: { name: 'Example RP' },
        user: { id: 'BAUG', name: 'admin', displayName: 'Administrator' },
      }),
    ).toThrow(/public-key parameters/i);
  });
});

describe('accountFailureText', () => {
  it.each([
    [400, 'request was invalid'],
    [401, 'did not authorise'],
    [403, 'not permitted'],
    [404, 'nothing here'],
    [409, 'conflicts with the account'],
  ])('maps status %i honestly', (status, expected) => {
    expect(accountFailureText(new ApiError(status, 'failed'))).toContain(expected);
  });

  it('does not claim a failed server attempt was unchanged', () => {
    expect(accountFailureText(new ApiError(500, 'failed'))).toContain(
      'whether the change applied is unknown — reload to check',
    );
  });
});
