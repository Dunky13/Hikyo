// @vitest-environment happy-dom
import { act, createRef } from 'react';
import { MemoryRouter } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { renderForm, settle } from '../testkit/renderForm.tsx';
import { HistoryDrawer, PinReleaseOutcome } from './HistoryDrawer.tsx';

const mocks = vi.hoisted(() => ({
  preview: 'retained' as 'retained' | 'collection_eligible' | 'already_collected',
  releaseMutate: vi.fn(),
}));

vi.mock('../api/history.ts', async (importActual) => {
  const actual = await importActual<typeof import('../api/history.ts')>();
  return {
    ...actual,
    useRevisionHistory: () => ({
      data: {
        items: [4n, 3n].map((revision) => ({
          revision,
          schema_revision: 1n,
          published_by: 'usr_admin',
          published_at: '2026-08-01T00:00:00Z',
          changed_keys: [],
          payload_present: true,
        })),
        count: 2,
      },
      isSuccess: true,
    }),
    useRevisionPins: () => ({
      data: {
        items: [{
          id: 'pin_a',
          workload_principal_id: 'mch_workload',
          revision: 3n,
          authority_principal_id: 'usr_admin',
          expires_at: '2026-09-01T00:00:00Z',
          created_at: '2026-08-01T00:00:00Z',
          authorized_at: '2026-08-01T00:00:00Z',
          history_authorized: true,
          schema_override: false,
          expired: false,
          release_retention_consequence: mocks.preview,
        }],
        count: 1,
      },
    }),
    useProjectRetention: () => ({
      data: { inherited: false, mode: 'keep-if-either', max_age_seconds: 3600, last_revisions: 1 },
      isError: false,
    }),
    useRevisionDetail: () => ({ data: { keys: [] }, isSuccess: true, isError: false }),
    useRestoreRevision: () => ({ mutate: vi.fn(), isPending: false }),
    useSetRevisionPin: () => ({ mutate: vi.fn(), isPending: false }),
    useReleaseRevisionPin: () => ({ mutate: mocks.releaseMutate, isPending: false }),
  };
});

vi.mock('../api/identities.ts', async (importActual) => {
  const actual = await importActual<typeof import('../api/identities.ts')>();
  return {
    ...actual,
    useServiceAccounts: () => ({
      data: {
        items: [{
          id: 'svc_a',
          principal_id: 'mch_workload',
          name: 'worker',
          kind: 'workload',
          created_at: '2026-08-01T00:00:00Z',
          created_by: 'usr_admin',
          live_credentials: 1,
        }],
        count: 1,
      },
    }),
  };
});

vi.mock('../api/matrix.ts', async (importActual) => {
  const actual = await importActual<typeof import('../api/matrix.ts')>();
  return { ...actual, usePublishMatrix: () => ({ mutate: vi.fn(), isPending: false }) };
});

vi.mock('./useProtectedPublishCeremony.ts', () => ({
  useProtectedPublishCeremony: () => ({
    request: null,
    error: null,
    run: vi.fn(),
    onAuthorised: vi.fn(),
    onCancel: vi.fn(),
  }),
}));

beforeEach(() => {
  mocks.preview = 'retained';
  mocks.releaseMutate.mockReset();
});

describe('PinReleaseOutcome', () => {
  for (const [consequence, expected] of [
    ['retained', "r3's values remain retained"],
    ['collection_eligible', "r3's values became eligible for collection"],
    ['already_collected', "r3's values were already collected"],
  ] as const) {
    it(`renders server consequence ${consequence}`, async () => {
      const { container } = await renderForm(
        <PinReleaseOutcome
          consequence={consequence}
          revision={3n}
        />,
      );

      expect(container.textContent).toContain(expected);
      expect(container.textContent).toContain('resumes latest on its next fetch');
    });
  }
});

function drawer() {
  return (
    <MemoryRouter initialEntries={['/orgs/org_a/projects/prj_a/matrix/history?env=env_a&rev=4']}>
      <HistoryDrawer
        refData={{ org: 'org_a', project: 'prj_a' }}
        environments={[{
          id: 'env_a',
          org_id: 'org_a',
          project_id: 'prj_a',
          name: 'production',
          display_order: 0,
          created_at: '2026-08-01T00:00:00Z',
        }]}
        keys={[]}
        currentRevisions={new Map([['env_a', 7n]])}
        protectedEnvironmentIds={[]}
        cellsByEnvironment={new Map()}
        pendingByEnvironment={new Map()}
        pendingByOthersByEnvironment={new Map()}
        currentValuesByEnvironment={new Map()}
        openerRef={createRef<HTMLAnchorElement>()}
      />
    </MemoryRouter>
  );
}

function buttonNamed(container: HTMLElement, name: string): HTMLButtonElement {
  const button = [...container.querySelectorAll('button')].find((candidate) => candidate.textContent === name);
  if (button === undefined) {
    throw new Error(`button ${name} is missing`);
  }
  return button;
}

describe('HistoryDrawer pin release flow', () => {
  it('passes the server response into the outcome instead of stale drawer state', async () => {
    mocks.releaseMutate.mockImplementation((_workload, options) => {
      options.onSuccess({ revision: 11n, retention_consequence: 'already_collected' });
    });
    const { container } = await renderForm(drawer());

    await act(async () => buttonNamed(container, 'Release').click());
    await settle();

    expect(mocks.releaseMutate).toHaveBeenCalledTimes(1);
    expect(container.querySelector('[role="status"]')?.textContent).toContain(
      "r11's values were already collected",
    );
    expect(container.textContent).not.toContain("r3's values were already collected");
  });

  it('keeps confirmation only for a server-previewed collection risk', async () => {
    mocks.preview = 'collection_eligible';
    mocks.releaseMutate.mockImplementation((_workload, options) => {
      options.onSuccess({ revision: 3n, retention_consequence: 'collection_eligible' });
    });
    const { container } = await renderForm(drawer());

    expect(container.textContent).toContain("This pin currently keeps r3's values retained");
    await act(async () => buttonNamed(container, 'Release').click());
    expect(mocks.releaseMutate).not.toHaveBeenCalled();

    await act(async () => buttonNamed(container, 'Release pin').click());
    await settle();
    expect(mocks.releaseMutate).toHaveBeenCalledTimes(1);
    expect(container.querySelector('[role="status"]')?.textContent).toContain(
      "r3's values became eligible for collection",
    );
  });

  it('warns and confirms when moving a server-previewed sole-keeper pin', async () => {
    mocks.preview = 'collection_eligible';
    const { container } = await renderForm(drawer());

    await act(async () => buttonNamed(container, 'Pin r4…').click());

    expect(container.querySelector('#history-pin-move-collection-warning')?.textContent).toContain(
      "make r3's values eligible for immediate collection",
    );
    expect(buttonNamed(container, 'Move pin from r3 to r4 — old values may be collected')).toBeTruthy();
  });
});
