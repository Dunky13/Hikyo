import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';

/**
 * The minimum harness for exercising a form component against a mocked fetch,
 * under a per-file `// @vitest-environment happy-dom` pragma. It deliberately
 * avoids testing-library: the repo has no such dependency and these forms need
 * only a mount, a controlled-input write, a submit, and a settle.
 */

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });

/** Mount a node under a fresh, retry-free QueryClient in the happy-dom document. */
export async function renderForm(node: ReactNode): Promise<{
  container: HTMLElement;
  client: QueryClient;
  unmount: () => Promise<void>;
}> {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const root = createRoot(container);
  await act(async () => {
    root.render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
  });
  return {
    container,
    client,
    unmount: async () => {
      await act(async () => root.unmount());
      container.remove();
    },
  };
}

/** Write a controlled input's value the way React's synthetic onChange observes. */
export function typeInto(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (setter === undefined) {
    throw new Error('HTMLInputElement exposes no value setter');
  }
  setter.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

/** Flush the mutation's microtask chain and its React re-renders inside act. */
export async function settle(rounds = 10): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

/** A 201 JSON response, the shape the create routes answer with. */
export function created(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 201,
    headers: { 'Content-Type': 'application/json' },
  });
}
