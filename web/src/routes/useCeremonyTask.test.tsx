// @vitest-environment happy-dom
import { act, StrictMode, useEffect, useRef } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { describe, expect, it } from 'vitest';

import {
  ceremonyRequest,
  deferred,
  type Deferred,
} from '../testkit/ceremony.ts';
import { useCeremonyTask } from './useCeremonyTask.ts';

type CeremonyController = ReturnType<typeof useCeremonyTask>;

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });

function Harness({
  scope,
  pending,
  committed,
  onReady,
}: {
  scope: string;
  pending: Deferred<void>;
  committed: string[];
  onReady?: (controller: CeremonyController) => void;
}) {
  const ceremony = useCeremonyTask([scope]);
  onReady?.(ceremony);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const task = ceremony.begin(['reveal']);
    void pending.promise.then(() => {
      ceremony.stage(task, ceremonyRequest(scope), () => {
        committed.push(scope);
        ceremony.finish(task);
      });
    });
  }, [ceremony, committed, pending.promise, scope]);

  return <output>{ceremony.request?.environmentName ?? 'idle'}</output>;
}

function ManualHarness({ onReady }: { onReady: (controller: CeremonyController) => void }) {
  const ceremony = useCeremonyTask(['strict-scope']);
  onReady(ceremony);
  return <output>{ceremony.request?.environmentName ?? 'idle'}</output>;
}

async function render(
  scope: string,
  pending: Deferred<void>,
  committed: string[],
  onReady?: (controller: CeremonyController) => void,
): Promise<{ container: HTMLElement; root: Root }> {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(
      <Harness scope={scope} pending={pending} committed={committed} onReady={onReady} />,
    );
  });
  return { container, root };
}

describe('useCeremonyTask scope ownership', () => {
  it('ignores a deferred completion after navigation changes the scope', async () => {
    const pending = deferred<void>();
    const committed: string[] = [];
    const { container, root } = await render('environment-a', pending, committed);

    await act(async () => {
      root.render(
        <Harness scope="environment-b" pending={pending} committed={committed} />,
      );
    });
    await act(async () => pending.resolve(undefined));

    expect(container.textContent).toBe('idle');
    expect(committed).toEqual([]);
    await act(async () => root.unmount());
  });

  it('ignores a deferred completion after the owning surface unmounts', async () => {
    const pending = deferred<void>();
    const committed: string[] = [];
    const { root } = await render('environment-a', pending, committed);

    await act(async () => root.unmount());
    await act(async () => pending.resolve(undefined));

    expect(committed).toEqual([]);
  });

  it('clears a staged continuation on cancellation without replay', async () => {
    const pending = deferred<void>();
    const committed: string[] = [];
    let controller: CeremonyController | undefined;
    const { container, root } = await render(
      'environment-a',
      pending,
      committed,
      (next) => {
        controller = next;
      },
    );
    await act(async () => pending.resolve(undefined));
    const active = controller;
    if (active === undefined) throw new Error('ceremony controller was not exposed');
    expect(container.textContent).toBe('environment-a');

    await act(async () => active.onCancel());
    await act(async () => active.onAuthorised());

    expect(container.textContent).toBe('idle');
    expect(committed).toEqual([]);
    await act(async () => root.unmount());
  });

  it('executes the current staged continuation once', async () => {
    const pending = deferred<void>();
    const committed: string[] = [];
    let controller: CeremonyController | undefined;
    const { container, root } = await render(
      'environment-a',
      pending,
      committed,
      (next) => {
        controller = next;
      },
    );
    await act(async () => pending.resolve(undefined));
    const active = controller;
    if (active === undefined) throw new Error('ceremony controller was not exposed');

    await act(async () => active.onAuthorised());
    await act(async () => active.onAuthorised());

    expect(container.textContent).toBe('idle');
    expect(committed).toEqual(['environment-a']);
    await act(async () => root.unmount());
  });

  it('remains live after the StrictMode effect probe', async () => {
    let controller: CeremonyController | undefined;
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => {
      root.render(
        <StrictMode>
          <ManualHarness onReady={(next) => { controller = next; }} />
        </StrictMode>,
      );
    });
    const active = controller;
    if (active === undefined) throw new Error('ceremony controller was not exposed');

    await act(async () => {
      const task = active.begin(['reveal']);
      active.stage(task, ceremonyRequest('strict-scope'), () => active.finish(task));
    });

    expect(container.textContent).toBe('strict-scope');
    await act(async () => root.unmount());
  });

  it('does not let an obsolete modal callback authorise the newer task', async () => {
    let controller: CeremonyController | undefined;
    const committed: string[] = [];
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => {
      root.render(<ManualHarness onReady={(next) => { controller = next; }} />);
    });
    const firstController = controller;
    if (firstController === undefined) throw new Error('ceremony controller was not exposed');
    await act(async () => {
      const task = firstController.begin(['first']);
      firstController.stage(task, ceremonyRequest('first'), () => {
        committed.push('first');
        firstController.finish(task);
      });
    });
    const stagedFirstController = controller;
    if (stagedFirstController === undefined) throw new Error('first ceremony controller was lost');
    const obsoleteAuthorise = stagedFirstController.onAuthorised;

    const secondController = stagedFirstController;
    await act(async () => {
      const task = secondController.begin(['second']);
      secondController.stage(task, ceremonyRequest('second'), () => {
        committed.push('second');
        secondController.finish(task);
      });
    });
    await act(async () => obsoleteAuthorise());

    expect(container.textContent).toBe('second');
    expect(committed).toEqual([]);
    const stagedSecondController = controller;
    if (stagedSecondController === undefined) throw new Error('second ceremony controller was lost');
    await act(async () => stagedSecondController.onAuthorised());
    expect(committed).toEqual(['second']);
    await act(async () => root.unmount());
  });
});
