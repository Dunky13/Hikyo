import { afterEach, expect, test, vi } from 'vitest';

import { prepareWorkspace } from './workspace.ts';

const ORIGIN = 'https://b.example';

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

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
        starts.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
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
        starts.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
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
