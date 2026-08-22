import { listValues } from '@hikyo/client';
import { afterEach, expect, test, vi } from 'vitest';

import { createWorkspaceClient } from './workspaceClient.ts';
import { forgetWorkspace, rememberWorkspace, workspaceBearer, WorkspaceError } from './workspace.ts';

const ORIGIN = 'https://remote.example';

function seed(value: string, session: string): void {
  rememberWorkspace({
    origin: ORIGIN,
    value,
    session,
    idleExpiresAt: '2099-01-01T00:00:00Z',
    absoluteExpiresAt: '2099-01-01T00:00:00Z',
  });
}

afterEach(() => {
  forgetWorkspace(ORIGIN);
  vi.restoreAllMocks();
});

test('the bearer rides an Authorization header and nothing ambient travels', async () => {
  seed('secret-1', 'ses_1');
  let seen: Request | undefined;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    seen = input as Request;
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  });

  await createWorkspaceClient(ORIGIN).get({ url: '/api/v1/me/sessions' });

  expect(seen?.headers.get('Authorization')).toBe('Bearer secret-1');
  // credentials: 'omit' is load-bearing — it keeps the remote's CORS out of
  // credentials mode and cookies from ever crossing the origin.
  expect(seen?.credentials).toBe('omit');
  expect(seen?.url).toBe('https://remote.example/api/v1/me/sessions');
});

test('a real generated call routes to the remote with the bearer and no cookies', async () => {
  seed('secret-1', 'ses_1');
  let seen: Request | undefined;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    seen = input as Request;
    return new Response('{"values":[]}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  });

  // The whole seam as the wrappers use it: a generated SDK fn, its path
  // templated, its `security: bearer` resolved, pointed at the remote by the
  // per-call client. Not `client.get` — that skips the parts a real call hits.
  await listValues({
    path: { org: 'org_a', project: 'proj_b', environment: 'env_c' },
    client: createWorkspaceClient(ORIGIN),
  });

  expect(seen?.url).toBe(
    'https://remote.example/api/v1/orgs/org_a/projects/proj_b/environments/env_c/values',
  );
  expect(seen?.headers.get('Authorization')).toBe('Bearer secret-1');
  expect(seen?.credentials).toBe('omit');
});

test('the bearer is read LIVE per request, not frozen at client creation', async () => {
  seed('secret-1', 'ses_1');
  const client = createWorkspaceClient(ORIGIN);
  const seen: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    seen.push((input as Request).headers.get('Authorization') ?? '');
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  });

  await client.get({ url: '/api/v1/x' });
  // A step-up rotates the bearer in place under the same origin; the very next
  // call must carry the new value, not the one held when the client was built.
  seed('secret-2', 'ses_1');
  await client.get({ url: '/api/v1/x' });

  expect(seen).toEqual(['Bearer secret-1', 'Bearer secret-2']);
});

test('no bearer fails closed rather than leaking an anonymous cross-origin call', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch');
  // The client resolves the refusal into a result (throwOnError is off, so an
  // interceptor throw becomes `{ error }` with no response) rather than
  // rejecting — the guarantee that matters is that NO request left the browser.
  const result = await createWorkspaceClient(ORIGIN).get({ url: '/api/v1/x' });
  expect(result.error).toBeInstanceOf(WorkspaceError);
  expect(result.response).toBeUndefined();
  expect(fetchSpy).not.toHaveBeenCalled();
});

test('a 401 drops the bearer at once — the kill switch does not wait for the poll', async () => {
  seed('secret-1', 'ses_1');
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    new Response('{}', { status: 401, headers: { 'Content-Type': 'application/json' } }),
  );

  await createWorkspaceClient(ORIGIN).get({ url: '/api/v1/x' });

  expect(workspaceBearer(ORIGIN)).toBeUndefined();
});

test('a 401 for a value that was already rotated leaves the replacement alone', async () => {
  seed('secret-1', 'ses_1');
  // Reseed INSIDE fetch — which runs only after the request interceptor has
  // already captured secret-1 — so this is the real ordering: the credential is
  // rotated (a step-up: same session id, new value) while its old value's 401
  // is in flight. The stale 401 is for secret-1; the live secret-2 must survive.
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    expect((input as Request).headers.get('Authorization')).toBe('Bearer secret-1');
    seed('secret-2', 'ses_1');
    return new Response('{}', { status: 401, headers: { 'Content-Type': 'application/json' } });
  });

  await createWorkspaceClient(ORIGIN).get({ url: '/api/v1/x' });

  expect(workspaceBearer(ORIGIN)?.session).toBe('ses_1');
  expect(workspaceBearer(ORIGIN)?.value).toBe('secret-2');
});

test('a stale 401 cannot drop a replacement epoch even if bearer text matches', async () => {
  seed('secret-1', 'ses_1');
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    expect((input as Request).headers.get('Authorization')).toBe('Bearer secret-1');
    seed('secret-1', 'ses_2');
    return new Response('{}', { status: 401, headers: { 'Content-Type': 'application/json' } });
  });

  await createWorkspaceClient(ORIGIN).get({ url: '/api/v1/x' });

  expect(workspaceBearer(ORIGIN)?.session).toBe('ses_2');
  expect(workspaceBearer(ORIGIN)?.value).toBe('secret-1');
});
