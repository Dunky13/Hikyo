// @vitest-environment happy-dom
import { act, useState } from 'react';
import type { RetentionConsequence } from '@hikyo/client';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { renderForm, settle } from '../testkit/renderForm.tsx';
import { useReleaseRevisionPin } from './history.ts';

afterEach(() => {
  vi.unstubAllGlobals();
});

function ReleaseHarness() {
  const release = useReleaseRevisionPin({
    org: 'org_a',
    project: 'prj_a',
    environment: 'env_a',
  });
  const [outcome, setOutcome] = useState<{
    revision: bigint;
    retention_consequence: RetentionConsequence;
  } | null>(null);
  return (
    <>
      <button type="button" onClick={() => release.mutate('mch_workload', { onSuccess: setOutcome })}>
        Release
      </button>
      <output>{outcome === null ? '' : `${String(outcome.revision)}:${outcome.retention_consequence}`}</output>
    </>
  );
}

describe('useReleaseRevisionPin', () => {
  it('returns the parsed server consequence and refreshes both pins and history', async () => {
    const fetchMock = vi.fn((..._args: Parameters<typeof fetch>) => Promise.resolve(
      new Response(JSON.stringify({ revision: 3, retention_consequence: 'collection_eligible' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ));
    vi.stubGlobal('fetch', fetchMock);
    const { container, client } = await renderForm(<ReleaseHarness />);
    const invalidate = vi.spyOn(client, 'invalidateQueries');

    await act(async () => container.querySelector('button')?.click());
    await settle();

    expect(container.querySelector('output')?.textContent).toBe('3:collection_eligible');
    expect(invalidate).toHaveBeenCalledTimes(2);
    expect(invalidate.mock.calls.map(([filters]) => filters?.queryKey ?? [])).toEqual([
      ['revision-pins', 'org_a', 'prj_a', 'env_a'],
      ['revisions', 'org_a', 'prj_a', 'env_a'],
    ]);
    const request = fetchMock.mock.calls[0]?.[0];
    if (!(request instanceof Request)) {
      throw new Error('release did not issue a Request');
    }
    expect(request.method).toBe('DELETE');
  });
});
