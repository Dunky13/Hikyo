import { expect, test } from 'vitest';

import { withRemote } from './transport.tsx';

test('withRemote appends the marker with the right separator', () => {
  // No remote → untouched (the local path must not grow a stray parameter).
  expect(withRemote('/orgs/o/projects/p/matrix', '')).toBe('/orgs/o/projects/p/matrix');
  // A clean path takes `?`.
  expect(withRemote('/orgs/o/projects/p/matrix', 'peer-b')).toBe(
    '/orgs/o/projects/p/matrix?remote=peer-b',
  );
  // A path that already carries a query takes `&`, so the history drawer's
  // env/key/rev parameters survive alongside the remote marker.
  expect(withRemote('/orgs/o/projects/p/matrix/history?env=e&key=k', 'peer-b')).toBe(
    '/orgs/o/projects/p/matrix/history?env=e&key=k&remote=peer-b',
  );
  // The name is encoded — a remote name is a display string, not a URL token.
  expect(withRemote('/x', 'a b')).toBe('/x?remote=a%20b');
});
