// @vitest-environment happy-dom
import { act } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { created, renderForm, settle, typeInto } from '../testkit/renderForm.tsx';
import { NewEnvironmentForm } from './ProjectSettings.tsx';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('NewEnvironmentForm', () => {
  it('posts the entered name and announces the created environment', async () => {
    const fetchMock = vi.fn((..._args: Parameters<typeof fetch>) =>
      Promise.resolve(
        created({
          id: 'env_123e4567-e89b-12d3-a456-426614174000',
          org_id: 'org_123e4567-e89b-12d3-a456-426614174001',
          project_id: 'prj_123e4567-e89b-12d3-a456-426614174002',
          name: 'staging',
          display_order: 0,
          created_at: '2026-01-01T00:00:00Z',
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    const { container } = await renderForm(
      <NewEnvironmentForm org="org_1" project="project_1" />,
    );
    const input = container.querySelector('input');
    if (!(input instanceof HTMLInputElement)) {
      throw new Error('the form has no name input');
    }
    const form = container.querySelector('form');
    if (!(form instanceof HTMLFormElement)) {
      throw new Error('the form element is missing');
    }

    await act(async () => {
      typeInto(input, 'staging');
    });
    await act(async () => {
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });
    await settle();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const request = fetchMock.mock.calls[0]?.[0];
    if (!(request instanceof Request)) {
      throw new Error('fetch was not called with a Request');
    }
    expect(request.method).toBe('POST');
    expect(new URL(request.url).pathname).toBe(
      '/api/v1/orgs/org_1/projects/project_1/environments',
    );
    expect(await request.json()).toEqual({ name: 'staging' });

    const status = container.querySelector('[role="status"]');
    expect(status?.textContent).toContain('Environment staging created.');
  });
});
