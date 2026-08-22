// @vitest-environment happy-dom
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ceremonyRequest, deferred } from '../testkit/ceremony.ts';
import { settle } from '../testkit/renderForm.tsx';
import { Ceremony } from './Ceremony.tsx';
import { useCeremonyTask } from './useCeremonyTask.ts';

const mocks = vi.hoisted(() => ({
  runPasskeyCeremony: vi.fn(),
}));

vi.mock('../api/values.ts', async (importActual) => {
  const actual = await importActual<typeof import('../api/values.ts')>();
  return { ...actual, runPasskeyCeremony: mocks.runPasskeyCeremony };
});

vi.mock('../api/transport.tsx', () => ({
  useWorkspaceContext: () => null,
}));

type Controller = ReturnType<typeof useCeremonyTask>;
let latestController: Controller | undefined;

function Harness() {
  const ceremony = useCeremonyTask(['values']);
  latestController = ceremony;
  return ceremony.request === null ? null : (
    <Ceremony
      key={ceremony.requestKey}
      request={ceremony.request}
      onAuthorised={ceremony.onAuthorised}
      onCancel={ceremony.onCancel}
    />
  );
}

function controller(): Controller {
  if (latestController === undefined) throw new Error('ceremony controller is not mounted');
  return latestController;
}

function button(container: HTMLElement, name: string): HTMLButtonElement {
  const match = [...container.querySelectorAll('button')].find(
    (candidate) => candidate.textContent === name,
  );
  if (match === undefined) throw new Error(`button ${name} is missing`);
  return match;
}

async function stage(name: string, committed: string[]): Promise<void> {
  const active = controller();
  await act(async () => {
    // Deliberately identical: a double-click/newer retry of the same protected
    // operation must still get a fresh modal executor.
    const task = active.begin(['same-operation']);
    active.stage(task, ceremonyRequest(name), () => {
      committed.push(name);
      active.finish(task);
    });
  });
}

beforeEach(() => {
  latestController = undefined;
  mocks.runPasskeyCeremony.mockReset();
});

describe('Ceremony task identity', () => {
  it('remounts executor state and ignores completion retained by the obsolete modal', async () => {
    const obsoleteAttempt = deferred<void>();
    mocks.runPasskeyCeremony
      .mockImplementationOnce(() => obsoleteAttempt.promise)
      .mockResolvedValueOnce(undefined);
    const committed: string[] = [];
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => root.render(<Harness />));

    await stage('first', committed);
    await act(async () => button(container, 'Use a passkey').click());
    expect(container.textContent).toContain('Waiting for your passkey…');

    await stage('second', committed);
    expect(container.textContent).toContain('reveal · second');
    expect(container.textContent).toContain('Use a passkey');
    expect(container.textContent).not.toContain('Waiting for your passkey…');

    await act(async () => obsoleteAttempt.resolve(undefined));
    await settle();
    expect(container.textContent).toContain('reveal · second');
    expect(committed).toEqual([]);

    await act(async () => button(container, 'Use a passkey').click());
    await settle();
    expect(committed).toEqual(['second']);
    await act(async () => root.unmount());
  });
});
