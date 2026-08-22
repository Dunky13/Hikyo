// @vitest-environment happy-dom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { useMatrixProject } from './matrix.ts';
import { pendingDraftsKey, signalsKey, valuesKey } from './keys.ts';

const ref = { org: 'org_a', project: 'project_a' };
const devId = 'env_01989abc-def0-7123-8123-123456789abc';
const prodId = 'env_01989abc-def0-7123-8123-123456789abd';
const keyId = 'key_01989abc-def0-7123-8123-123456789abc';
const environmentBase = {
  org_id: 'org_01989abc-def0-7123-8123-123456789abc',
  project_id: 'prj_01989abc-def0-7123-8123-123456789abc',
  created_at: '2026-08-22T08:00:00Z',
};
const development = {
  ...environmentBase,
  id: devId,
  name: 'development',
  display_order: 0,
};
const production = {
  ...environmentBase,
  id: prodId,
  name: 'production',
  display_order: 1,
};

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

describe('useMatrixProject query ownership', () => {
  it('renders keyed reorder/removal with one observer per unchanged query', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const path = new URL(url, 'http://localhost').pathname;
      const body = matrixResponse(path);
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }));

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: Number.POSITIVE_INFINITY } },
    });
    const container = document.createElement('div');
    document.body.appendChild(container);
    const root = createRoot(container);

    try {
      await act(async () => {
        root.render(
          <QueryClientProvider client={client}>
            <MatrixRows />
          </QueryClientProvider>,
        );
      });
      await settleTasks();

      expect(renderedRows(container)).toEqual(['development:debug', 'production:warn']);
      expect(activeQueries(client)).toHaveLength(3 + 4 * 2);
      expect(activeQueries(client).every((query) => query.getObserversCount() === 1)).toBe(true);
      expect(client.getQueryData(valuesKey({ ...ref, environment: devId }))).toEqual({
        items: [
          {
            key_id: keyId,
            name: 'LOG_LEVEL',
            classification: 'config',
            set: true,
            revealed: true,
            value: 'debug',
          },
        ],
        count: 1,
      });
      expect(client.getQueryData(signalsKey(ref, devId))).toEqual({
        environment_id: devId,
        revision: 2n,
        cells: [],
      });
      expect(client.getQueryData(pendingDraftsKey(ref, devId))).toEqual({ items: [], count: 0 });

      await act(async () => {
        client.setQueryData(['environments', ref.org, ref.project], {
          items: [production, development],
          count: 2,
        });
      });
      await settleTasks();

      expect(renderedRows(container)).toEqual(['production:warn', 'development:debug']);
      expect(activeQueries(client)).toHaveLength(3 + 4 * 2);
      expect(activeQueries(client).every((query) => query.getObserversCount() === 1)).toBe(true);

      await act(async () => {
        client.setQueryData(['environments', ref.org, ref.project], {
          items: [production],
          count: 1,
        });
      });
      await settleTasks();

      expect(renderedRows(container)).toEqual(['production:warn']);
      expect(activeQueries(client)).toHaveLength(3 + 4);
      expect(activeQueries(client).every((query) => query.getObserversCount() === 1)).toBe(true);
    } finally {
      await act(async () => root.unmount());
      client.clear();
    }
  });
});

function MatrixRows() {
  const matrix = useMatrixProject(ref);
  return (
    <ol>
      {matrix.environmentRows.map((row) => (
        <li key={row.environmentId}>
          {`${row.environment.name}:${row.values.data?.items[0]?.value ?? 'pending'}`}
        </li>
      ))}
    </ol>
  );
}

function renderedRows(container: HTMLElement): readonly string[] {
  return [...container.querySelectorAll('li')].map((row) => row.textContent ?? '');
}

function activeQueries(client: QueryClient) {
  return client.getQueryCache().getAll().filter((query) => query.getObserversCount() > 0);
}

async function settleTasks(rounds = 20): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
}

function matrixResponse(path: string): unknown {
  const projectPath = `/api/v1/orgs/${ref.org}/projects/${ref.project}`;
  if (path === `${projectPath}/environments`) {
    return { items: [development, production], count: 2 };
  }
  if (path === `${projectPath}/keys`) {
    return { items: [], count: 0, schema_revision: 1 };
  }
  if (path === `${projectPath}/key-groups`) {
    return { items: [], count: 0 };
  }
  for (const [environmentId, value, revision, protectedEnvironment] of [
    [devId, 'debug', 2, false],
    [prodId, 'warn', 7, true],
  ] satisfies readonly (readonly [string, string, number, boolean])[]) {
    const environmentPath = `${projectPath}/environments/${environmentId}`;
    if (path === `${environmentPath}/values`) {
      return {
        items: [
          {
            key_id: keyId,
            name: 'LOG_LEVEL',
            classification: 'config',
            set: true,
            revealed: true,
            value,
          },
        ],
        count: 1,
      };
    }
    if (path === `${environmentPath}/signals`) {
      return { environment_id: environmentId, revision, cells: [] };
    }
    if (path === `${environmentPath}/settings`) {
      return { protected: protectedEnvironment, reauth_window_seconds: null };
    }
    if (path === `${environmentPath}/pending`) {
      return { items: [], count: 0 };
    }
  }
  throw new Error(`unexpected matrix request ${path}`);
}
