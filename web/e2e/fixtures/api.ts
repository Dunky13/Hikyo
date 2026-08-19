import { z } from 'zod';
import type { Page } from '@playwright/test';

import { ADMIN, BASE_URL } from './instance.ts';

export const zFixtureIgnored = z.object({});
export const zFixtureStaged = z.object({ version_id: z.string() });
export const zFixtureRevisionList = z.object({
  items: z.array(
    z.object({
      revision: z.number(),
      changed_keys: z.array(
        z.object({
          key_id: z.string(),
          name: z.string(),
          change: z.enum(['added', 'edited', 'removed']),
        }),
      ),
    }),
  ),
});

/** Mint a password bearer used only by API-driven fixture setup and repair. */
export async function fixtureBearer(label: string): Promise<string> {
  const response = await fetch(`${BASE_URL}/api/v1/auth/local/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: ADMIN.username, password: ADMIN.password }),
  });
  if (!response.ok) {
    throw new Error(`${label} could not sign in: ${response.status}`);
  }
  return z.object({ session_token: z.string() }).parse(await response.json()).session_token;
}

/** Call the real API as a bearer and parse every successful response at the boundary. */
export async function fixtureApiCall<T>(
  token: string,
  method: string,
  path: string,
  schema: z.ZodType<T>,
  body?: Record<string, unknown>,
): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    throw new Error(`${method} ${path} answered ${response.status}: ${await response.text()}`);
  }
  const raw: unknown = response.status === 204 ? {} : await response.json();
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(
      `${method} ${path} answered a shape the fixture does not expect: ${parsed.error.message}`,
    );
  }
  return parsed.data;
}

/** Drive the same typed fixture call through an authenticated browser cookie. */
export async function fixtureBrowserCall<T>(
  page: Page,
  method: string,
  path: string,
  schema: z.ZodType<T>,
  body?: Record<string, unknown>,
): Promise<T> {
  const result = await page.evaluate(
    async (input: { method: string; path: string; body: Record<string, unknown> | null }) => {
      const csrf = document.cookie
        .split(';')
        .map((part) => part.trim().split('='))
        .find(([name]) => name === '__Host-hikyo-csrf')
        ?.slice(1)
        .join('=') ?? '';
      const response = await fetch(input.path, {
        method: input.method,
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-Hikyo-CSRF': csrf },
        ...(input.body === null ? {} : { body: JSON.stringify(input.body) }),
      });
      return {
        status: response.status,
        body: response.status === 204 ? {} : await response.json(),
      };
    },
    { method, path, body: body ?? null },
  );
  if (result.status < 200 || result.status >= 300) {
    throw new Error(`${method} ${path} answered ${String(result.status)}`);
  }
  return schema.parse(result.body);
}
