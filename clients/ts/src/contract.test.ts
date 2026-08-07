import assert from 'node:assert/strict';
import test from 'node:test';

import { zCreateOrgRequest, zErrorCode, zMeta, zProtocolCapability } from './generated/zod.gen.ts';

// The TypeScript half of the bound 3.1 profile (system-architecture ADR,
// 2026-08-07 amendment): the round-trip fixtures must run through the Zod
// consumer as well as the Go one, because the two generators read the same
// document and could still disagree about what it means.

test('nullable members round-trip absent, null and value distinctly', () => {
  // `type: [object, "null"]` - three states, three outcomes, none collapsed.
  assert.deepEqual(zCreateOrgRequest.parse({ name: 'acme' }).metadata, undefined);
  assert.equal(zCreateOrgRequest.parse({ name: 'acme', metadata: null }).metadata, null);
  assert.deepEqual(
    zCreateOrgRequest.parse({ name: 'acme', metadata: { team: 'platform' } }).metadata,
    { team: 'platform' },
  );
});

test('an open enum tolerates a value this client has never heard of', () => {
  // The whole point of x-extensible-enum: an older client must not reject a
  // newer server's response. If this ever throws, every client in the field
  // breaks the day a new auth flow ships.
  assert.equal(zProtocolCapability.parse('local-password'), 'local-password');
  assert.equal(zProtocolCapability.parse('some-flow-from-2030'), 'some-flow-from-2030');

  const meta = zMeta.parse({
    server_version: '1.4.0',
    api_revision: 7,
    protocol_capabilities: ['local-password', 'a-flow-we-do-not-know'],
  });
  assert.deepEqual(meta.protocol_capabilities, ['local-password', 'a-flow-we-do-not-know']);
});

test('a closed enum refuses an unknown value', () => {
  // Closed enums never grow, so tolerating one would hide a server speaking
  // a contract this client does not have.
  assert.equal(zErrorCode.parse('not_found'), 'not_found');
  assert.throws(() => zErrorCode.parse('teapot'));
});

test('a request missing a required member is refused before it is sent', () => {
  assert.throws(() => zCreateOrgRequest.parse({}));
});
