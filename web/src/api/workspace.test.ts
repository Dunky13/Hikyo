import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  forgetWorkspace,
  probeWorkspace,
  rememberWorkspace,
  workspaceBearer,
  type WorkspaceBearer,
} from './workspace.ts';

const bearer: WorkspaceBearer = {
  origin: 'https://peer.example',
  value: 'hik_ws_value',
  session: 'ses_1',
  idleExpiresAt: '2026-01-01T00:00:00Z',
  absoluteExpiresAt: '2026-02-01T00:00:00Z',
};

/** A well-formed answer from the session listing, which is what "alive" means. */
function sessionList(): Response {
  return new Response(
    JSON.stringify({
      sessions: [
        {
          id: 'ses_1',
          artifact: 'workspace',
          auth_method: 'workspace-handoff',
          created_at: '2026-01-01T00:00:00Z',
          last_seen_at: '2026-01-01T00:00:00Z',
          idle_expires_at: '2026-01-01T00:00:00Z',
          absolute_expires_at: '2026-02-01T00:00:00Z',
        },
      ],
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  forgetWorkspace(bearer.origin);
});

// A blip must not cost a ceremony, and a re-established workspace is a NEW
// session: it gets its own two strikes. Carrying the old count over kills the
// reconnected workspace on its first blip, which reads to the human as "the
// reconnect did not work".
describe('probeWorkspace strike counting', () => {
  it('gives a re-established workspace its full strike allowance again', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    );
    rememberWorkspace(bearer);

    // First unreachable probe: survived, because one failure is a blip.
    expect(await probeWorkspace(bearer)).toBe(true);
    // Second: the workspace dies and is forgotten.
    expect(await probeWorkspace(bearer)).toBe(false);
    // The human reconnects and the very next blip arrives. It must be strike
    // ONE again, not strike three.
    rememberWorkspace(bearer);
    expect(await probeWorkspace(bearer)).toBe(true);
  });

  it('drops the workspace when the remote refuses the bearer, blips or not', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response(null, { status: 401 }))),
    );
    rememberWorkspace(bearer);
    expect(await probeWorkspace(bearer)).toBe(false);
    expect(workspaceBearer(bearer.origin)).toBeUndefined();
  });
});

// A probe is asynchronous and the human is not. Closing a workspace and opening
// a new one to the same origin while the old probe is still in flight used to
// let the old probe's verdict delete the NEW session.
describe('probeWorkspace session identity', () => {
  it('ignores a completion about a session that has been replaced', async () => {
    let settle: (r: Response) => void = () => {};
    vi.stubGlobal(
      'fetch',
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            settle = resolve;
          }),
      ),
    );
    rememberWorkspace(bearer);
    const inFlight = probeWorkspace(bearer);

    // The human closes S1 and establishes S2 to the same origin.
    const replacement: WorkspaceBearer = { ...bearer, session: 'ses_2', value: 'hik_ws_second' };
    rememberWorkspace(replacement);

    // S1's probe now fails. It must not touch S2.
    settle(new Response(null, { status: 401 }));
    expect(await inFlight).toBe(false);
    expect(workspaceBearer(bearer.origin)?.session).toBe('ses_2');
  });
});

// A response the shell cannot recognise is not evidence of life. Before this a
// 404, a 500 or an HTML error page from something in the path all cleared the
// strike counter and kept the card claiming "workspace open".
describe('probeWorkspace response validation', () => {
  it.each([
    ['a 404', new Response(null, { status: 404 })],
    ['a 500', new Response(null, { status: 500 })],
    ['a 200 carrying HTML', new Response('<html>captive portal</html>', { status: 200 })],
    ['a 200 carrying the wrong JSON', new Response('{"ok":true}', { status: 200 })],
  ])('counts %s as a strike rather than as life', async (_name, response) => {
    const responses = [response.clone(), response.clone()];
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(responses.shift() as Response)),
    );
    rememberWorkspace(bearer);
    expect(await probeWorkspace(bearer)).toBe(true); // strike one
    expect(await probeWorkspace(bearer)).toBe(false); // strike two ends it
    expect(workspaceBearer(bearer.origin)).toBeUndefined();
  });

  it('accepts a well-formed session listing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(sessionList())),
    );
    rememberWorkspace(bearer);
    expect(await probeWorkspace(bearer)).toBe(true);
    expect(workspaceBearer(bearer.origin)?.session).toBe('ses_1');
  });

  it('sets a deadline so a hung probe cannot stall the poll forever', async () => {
    const seen: RequestInit[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        seen.push(init);
        return Promise.resolve(sessionList());
      }),
    );
    rememberWorkspace(bearer);
    await probeWorkspace(bearer);
    expect(seen[0]?.signal).toBeInstanceOf(AbortSignal);
  });
});
