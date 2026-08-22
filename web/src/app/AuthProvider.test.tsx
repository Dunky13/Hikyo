// @vitest-environment happy-dom
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { act, useState, type ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { renderForm, settle } from '../testkit/renderForm.tsx';
import { AuthProvider, useAuth, type WhoAmI } from './AuthProvider.tsx';

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
};

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = (_value) => {
    throw new Error('deferred promise was resolved before construction');
  };
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

const id = (prefix: string, suffix: string) =>
  `${prefix}_123e4567-e89b-12d3-a456-4266141740${suffix}`;

function identity(
  sessionSuffix: string,
  principalSuffix: string,
  factors = ['password'],
): WhoAmI {
  return {
    session: {
      id: id('ses', sessionSuffix),
      artifact: 'browser',
      created_at: '2026-08-22T10:00:00Z',
      idle_expires_at: '2099-08-22T10:30:00Z',
      absolute_expires_at: '2099-08-22T18:00:00Z',
      assurance: {
        method: 'local-password',
        factors,
        authenticated_at: '2026-08-22T10:00:00Z',
      },
    },
    principal: {
      id: id('prn', principalSuffix),
      kind: 'human',
      display_name: `Person ${principalSuffix}`,
    },
  };
}

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function Probe({
  oldResult,
  mutationResult,
}: {
  oldResult?: Deferred<string>;
  mutationResult?: Deferred<WhoAmI>;
}) {
  const auth = useAuth();
  const queries = useQueryClient();
  const [, renderMarker] = useState(0);
  const epoch = auth.state.status === 'authenticated' ? auth.state.sessionEpoch : '';
  const privateQuery = useQuery({
    queryKey: ['private'],
    queryFn: () =>
      epoch.endsWith('00') && oldResult !== undefined
        ? oldResult.promise
        : Promise.resolve(`fresh:${epoch}`),
    enabled: epoch !== '',
    retry: false,
  });

  return (
    <>
      <output data-testid="state">
        {auth.state.status}
        {epoch === '' ? '' : `:${epoch}`}
      </output>
      <output data-testid="private">
        {auth.state.status === 'authenticated' ? (privateQuery.data ?? '') : ''}
      </output>
      <output data-testid="marker">{String(queries.getQueryData(['marker']) ?? '')}</output>
      <button type="button" onClick={() => void auth.revalidate()}>
        Revalidate
      </button>
      <button
        type="button"
        onClick={() => {
          queries.setQueryData(['marker'], 'owned');
          renderMarker((value) => value + 1);
        }}
      >
        Mark cache
      </button>
      <button
        type="button"
        onClick={() => {
          const guard = auth.captureTransition();
          void mutationResult?.promise.then((result) => auth.acceptSession(result, guard));
        }}
      >
        Start mutation
      </button>
    </>
  );
}

function text(container: HTMLElement, testId: string): string {
  return container.querySelector(`[data-testid="${testId}"]`)?.textContent ?? '';
}

const unmounts: Array<() => Promise<void>> = [];

async function renderAuth(node: ReactNode) {
  const rendered = await renderForm(node);
  unmounts.push(rendered.unmount);
  return rendered;
}

afterEach(async () => {
  await Promise.all(unmounts.splice(0).map((unmount) => unmount()));
  vi.unstubAllGlobals();
});

describe('AuthProvider', () => {
  it('drops deferred results from the previous session before rendering a replacement', async () => {
    const oldResult = deferred<string>();
    const replacement = deferred<Response>();
    const fetchMock = vi
      .fn<(...args: Parameters<typeof fetch>) => Promise<Response>>()
      .mockResolvedValueOnce(json(identity('00', '10')))
      .mockReturnValueOnce(replacement.promise);
    vi.stubGlobal('fetch', fetchMock);

    const { container } = await renderAuth(
      <AuthProvider>
        <Probe oldResult={oldResult} />
      </AuthProvider>,
    );
    await settle();
    expect(text(container, 'state')).toContain(`authenticated:${id('ses', '00')}`);

    const buttons = container.querySelectorAll('button');
    await act(async () => buttons[1]?.click());
    expect(text(container, 'marker')).toBe('owned');
    await act(async () => buttons[0]?.click());
    expect(text(container, 'state')).toBe('transitioning');
    expect(text(container, 'private')).toBe('');

    await act(async () => replacement.resolve(json(identity('01', '11'))));
    await settle(30);
    expect(text(container, 'state')).toContain(`authenticated:${id('ses', '01')}`);
    expect(text(container, 'marker')).toBe('');

    oldResult.resolve('old-session-secret');
    await settle();
    expect(container.textContent).not.toContain('old-session-secret');
  });

  it('preserves the session cache for a same-epoch assurance refresh', async () => {
    const current = identity('00', '10');
    const elevated = identity('00', '10', ['password', 'totp']);
    const fetchMock = vi
      .fn<(...args: Parameters<typeof fetch>) => Promise<Response>>()
      .mockResolvedValueOnce(json(current))
      .mockResolvedValueOnce(json(elevated));
    vi.stubGlobal('fetch', fetchMock);

    const { container } = await renderAuth(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await settle();

    const buttons = container.querySelectorAll('button');
    await act(async () => buttons[1]?.click());
    expect(text(container, 'marker')).toBe('owned');
    await act(async () => buttons[0]?.click());
    await settle();

    expect(text(container, 'state')).toContain(`authenticated:${id('ses', '00')}`);
    expect(text(container, 'marker')).toBe('owned');
  });

  it('moves an expired session to anonymous and discards its cache', async () => {
    const fetchMock = vi
      .fn<(...args: Parameters<typeof fetch>) => Promise<Response>>()
      .mockResolvedValueOnce(json(identity('00', '10')))
      .mockResolvedValueOnce(json({ error: { code: 'unauthenticated', message: 'no session' } }, 401));
    vi.stubGlobal('fetch', fetchMock);

    const { container } = await renderAuth(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await settle();

    const buttons = container.querySelectorAll('button');
    await act(async () => buttons[1]?.click());
    await act(async () => buttons[0]?.click());
    await settle();

    expect(text(container, 'state')).toBe('anonymous');
    expect(text(container, 'marker')).toBe('');
  });

  it('suspends authenticated routes while focus discovers a replacement session', async () => {
    const replacement = deferred<Response>();
    const fetchMock = vi
      .fn<(...args: Parameters<typeof fetch>) => Promise<Response>>()
      .mockResolvedValueOnce(json(identity('00', '10')))
      .mockReturnValueOnce(replacement.promise);
    vi.stubGlobal('fetch', fetchMock);

    const { container } = await renderAuth(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );
    await vi.waitFor(() => {
      expect(text(container, 'private')).toContain(id('ses', '00'));
    });

    await act(async () => globalThis.dispatchEvent(new Event('focus')));
    expect(text(container, 'state')).toBe('transitioning');
    expect(text(container, 'private')).toBe('');

    await act(async () => replacement.resolve(json(identity('01', '11'))));
    await settle();
    expect(text(container, 'state')).toContain(`authenticated:${id('ses', '01')}`);
  });

  it('ignores a mutation result captured before a newer session replacement', async () => {
    const mutationResult = deferred<WhoAmI>();
    const authoritativeIdentity = deferred<Response>();
    const fetchMock = vi
      .fn<(...args: Parameters<typeof fetch>) => Promise<Response>>()
      .mockResolvedValueOnce(json(identity('00', '10')))
      .mockResolvedValueOnce(json(identity('01', '11')))
      .mockReturnValueOnce(authoritativeIdentity.promise);
    vi.stubGlobal('fetch', fetchMock);

    const { container } = await renderAuth(
      <AuthProvider>
        <Probe mutationResult={mutationResult} />
      </AuthProvider>,
    );
    await settle();

    const buttons = container.querySelectorAll('button');
    await act(async () => buttons[2]?.click());
    await act(async () => buttons[0]?.click());
    await settle();
    expect(text(container, 'state')).toContain(`authenticated:${id('ses', '01')}`);

    await act(async () => mutationResult.resolve(identity('02', '12')));
    expect(text(container, 'state')).toBe('transitioning');
    expect(container.textContent).not.toContain(id('ses', '02'));

    await act(async () => authoritativeIdentity.resolve(json(identity('01', '11'))));
    await settle();
    expect(text(container, 'state')).toContain(`authenticated:${id('ses', '01')}`);
    expect(container.textContent).not.toContain(id('ses', '02'));
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
