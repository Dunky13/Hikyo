import { afterEach, expect, test, vi } from 'vitest';
import { z } from 'zod';

import { assertCompatible, prepareWorkspace, WorkspaceError } from './workspace.ts';

const ORIGIN = 'https://b.example';

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** The start body is parsed, not cast — the house rule holds in tests too. */
const zStartBody = z.record(z.string(), z.unknown());
const startBody = (init?: RequestInit): Record<string, unknown> =>
  zStartBody.parse(JSON.parse(String(init?.body)));

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

test('a step-up prepare binds the decision into the start body and the approve URL', async () => {
  vi.stubGlobal('location', { origin: 'https://a.example' });
  const starts: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/meta')) {
        return Promise.resolve(
          json({ server_version: '1.0.0', api_revision: 1, protocol_capabilities: [] }),
        );
      }
      if (url.endsWith('/api/v1/auth/workspace/start')) {
        starts.push(startBody(init));
        return Promise.resolve(
          json({
            handoff: 'ic_00000000-0000-4000-8000-000000000001',
            state: 'hik_1_hs_abc',
            expires_at: '2099-01-01T00:00:00Z',
          }),
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    }),
  );

  const prepared = await prepareWorkspace(ORIGIN, {
    session: 'ses_1',
    operation: 'reveal',
    environment: 'env_1',
    keySet: ['k1', 'k2'],
  });

  // The bound fields reach the remote's transaction row.
  expect(starts[0]).toMatchObject({
    purpose: 'step-up',
    session: 'ses_1',
    operation: 'reveal',
    environment: 'env_1',
    key_set: ['k1', 'k2'],
    origin: 'https://a.example',
    redirect_uri: 'https://a.example/workspace/callback',
  });

  // And ride the approve URL so the popup can name them when it runs the
  // remote's own reauthentication ceremony.
  const url = new URL(prepared.approveURL);
  expect(url.origin).toBe(ORIGIN);
  expect(url.pathname).toBe('/workspace/approve');
  expect(url.searchParams.get('state')).toBe('hik_1_hs_abc');
  expect(url.searchParams.get('purpose')).toBe('step-up');
  expect(url.searchParams.get('operation')).toBe('reveal');
  expect(url.searchParams.get('environment')).toBe('env_1');
  expect(url.searchParams.getAll('key')).toEqual(['k1', 'k2']);
});

test('assertCompatible resolves against a well-formed meta at the floor', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(json({ server_version: '1.0.0', api_revision: 1, protocol_capabilities: [] }))),
  );
  await expect(assertCompatible(ORIGIN)).resolves.toBeUndefined();
});

test('assertCompatible REFUSES a remote whose meta does not parse as this protocol', async () => {
  // The live skew/incompatibility protection: a downgraded or foreign server
  // whose meta shape does not match is refused before any workspace call. This
  // is the reachable half of the version-skew gate (the numeric floor check is
  // dormant while this shell's floor equals the meta contract's own).
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(json({ not: 'a hikyo meta' }))),
  );
  await expect(assertCompatible(ORIGIN)).rejects.toThrow();
});

test('assertCompatible REFUSES an unreachable or non-allowlisting remote', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
  );
  await expect(assertCompatible(ORIGIN)).rejects.toBeInstanceOf(WorkspaceError);
});

test('an establishment prepare carries no step-up parameters', async () => {
  vi.stubGlobal('location', { origin: 'https://a.example' });
  const starts: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/api/v1/meta')) {
        return Promise.resolve(
          json({ server_version: '1.0.0', api_revision: 1, protocol_capabilities: [] }),
        );
      }
      if (url.endsWith('/api/v1/auth/workspace/start')) {
        starts.push(startBody(init));
        return Promise.resolve(
          json({
            handoff: 'ic_00000000-0000-4000-8000-000000000001',
            state: 'hik_1_hs_abc',
            expires_at: '2099-01-01T00:00:00Z',
          }),
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    }),
  );

  const prepared = await prepareWorkspace(ORIGIN);

  expect(starts[0]).toMatchObject({ purpose: 'establishment' });
  expect(starts[0]).not.toHaveProperty('session');
  const url = new URL(prepared.approveURL);
  expect(url.searchParams.get('purpose')).toBeNull();
  expect(url.searchParams.getAll('key')).toEqual([]);
});
