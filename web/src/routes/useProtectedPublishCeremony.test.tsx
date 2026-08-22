// @vitest-environment happy-dom
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { RevealWindow } from '../api/values.ts';
import { deferred, revealWindow } from '../testkit/ceremony.ts';
import { settle } from '../testkit/renderForm.tsx';
import { useProtectedPublishCeremony } from './useProtectedPublishCeremony.ts';

const mocks = vi.hoisted(() => ({
  fetchRevealWindow: vi.fn(),
}));

vi.mock('../api/values.ts', async (importActual) => {
  const actual = await importActual<typeof import('../api/values.ts')>();
  return { ...actual, fetchRevealWindow: mocks.fetchRevealWindow };
});

vi.mock('../api/transport.tsx', () => ({
  useTransport: () => ({ client: undefined }),
}));

type Guard = ReturnType<typeof useProtectedPublishCeremony>;
let latestGuard: Guard | undefined;

function Harness() {
  latestGuard = useProtectedPublishCeremony({ org: 'org-a', project: 'project-a' }, ['values']);
  return <output>{latestGuard.request?.environmentName ?? 'idle'}</output>;
}

function guard(): Guard {
  if (latestGuard === undefined) throw new Error('ceremony guard is not mounted');
  return latestGuard;
}

beforeEach(() => {
  latestGuard = undefined;
  mocks.fetchRevealWindow.mockReset();
});

describe('useProtectedPublishCeremony latest-run ownership', () => {
  it('does not let an older guard completion replace a newer successful run', async () => {
    const firstWindow = deferred<RevealWindow>();
    const secondWindow = deferred<RevealWindow>();
    mocks.fetchRevealWindow
      .mockImplementationOnce(() => firstWindow.promise)
      .mockImplementationOnce(() => secondWindow.promise);
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => root.render(<Harness />));
    const firstComplete = vi.fn();
    const secondComplete = vi.fn();
    const target = [{
      environmentId: 'production',
      environmentName: 'Production',
      keys: [{ id: 'key-a', name: 'KEY_A' }],
    }];

    await act(async () => {
      void guard().run(target, firstComplete, 'first failed');
      void guard().run(target, secondComplete, 'second failed');
    });
    expect(mocks.fetchRevealWindow.mock.calls[0]?.[2]?.aborted).toBe(true);
    await act(async () => secondWindow.resolve(revealWindow(true)));
    await settle();
    await act(async () => firstWindow.resolve(revealWindow(false)));
    await settle();

    expect(secondComplete).toHaveBeenCalledTimes(1);
    expect(firstComplete).not.toHaveBeenCalled();
    expect(container.textContent).toBe('idle');
    await act(async () => root.unmount());
  });

  it('keeps current-task ceremony success behavior', async () => {
    mocks.fetchRevealWindow.mockResolvedValueOnce(revealWindow(false));
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => root.render(<Harness />));
    const complete = vi.fn();

    await act(async () => {
      await guard().run([{
        environmentId: 'production',
        environmentName: 'Production',
        keys: [{ id: 'key-a', name: 'KEY_A' }],
      }], complete, 'guard failed');
    });
    expect(container.textContent).toBe('Production');
    await act(async () => guard().onAuthorised());

    expect(complete).toHaveBeenCalledTimes(1);
    expect(container.textContent).toBe('idle');
    await act(async () => root.unmount());
  });

  it('keeps current-task refusal feedback', async () => {
    mocks.fetchRevealWindow.mockRejectedValueOnce(new Error('window unavailable'));
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => root.render(<Harness />));

    await act(async () => {
      await guard().run([{
        environmentId: 'production',
        environmentName: 'Production',
        keys: [{ id: 'key-a', name: 'KEY_A' }],
      }], vi.fn(), 'guard failed');
    });

    expect(guard().error).toBe('guard failed: window unavailable');
    await act(async () => root.unmount());
  });
});
