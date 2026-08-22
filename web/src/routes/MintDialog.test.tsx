// @vitest-environment happy-dom
import { act, useRef, useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { renderForm, settle } from '../testkit/renderForm.tsx';
import { MintDialog } from './MachineAccess.tsx';
import {
  transitionMintLifecycle,
  type MintLifecycle,
  type MintLifecycleEvent,
  type MintRequest,
} from './mintLifecycle.ts';

const SENTINEL = 'hik_1_wl_SENTINEL_PLAINTEXT';

afterEach(() => {
  vi.unstubAllGlobals();
});

const REQUEST: MintRequest = {
  id: 1,
  sessionId: 'ses_first',
  org: 'org_acme',
  project: 'prj_payments',
  accountId: 'mch_worker',
  accountName: 'worker',
  rotating: false,
  reach: [],
};

function MintHarness() {
  const [lifecycle, setLifecycle] = useState<MintLifecycle>({
    kind: 'reviewing',
    request: REQUEST,
  });
  const lifecycleRef = useRef<MintLifecycle>(lifecycle);
  const move = (event: MintLifecycleEvent) => {
    const current = lifecycleRef.current;
    const next = transitionMintLifecycle(current, event);
    lifecycleRef.current = next;
    if (next !== current) {
      setLifecycle(next);
    }
    return { state: next, accepted: next !== current };
  };
  const isSubmitting = (requestId: number) =>
    lifecycleRef.current.kind === 'submitting' && lifecycleRef.current.request.id === requestId;

  return lifecycle.kind === 'idle' ? null : (
    <MintDialog lifecycle={lifecycle} move={move} isSubmitting={isSubmitting} />
  );
}

describe('MintDialog', () => {
  it('renders display-once plaintext without entering its QueryCache or MutationCache', async () => {
    const fetchMock = vi.fn((..._args: Parameters<typeof fetch>) =>
      Promise.resolve(
        new Response(JSON.stringify({ value: SENTINEL, clamped: false }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { container, client } = await renderForm(<MintHarness />);
    const button = container.querySelector('button');
    if (!(button instanceof HTMLButtonElement)) {
      throw new Error('the mint dialog has no submit button');
    }
    await act(async () => button.click());
    await settle();

    expect(container.querySelector('.machine__token')?.textContent).toBe(SENTINEL);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(client.getQueryCache().getAll()).toEqual([]);
    expect(client.getMutationCache().getAll()).toEqual([]);
  });
});
