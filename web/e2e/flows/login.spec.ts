import { expect, test, type Page } from '@playwright/test';

import {
  expectContrast,
  expectPinnedAssertionSet,
  expectStatusIsTextAndAria,
  measureSurfaceLuminance,
} from '../fixtures/assertions.ts';
import { ADMIN } from '../fixtures/instance.ts';

async function expectLoginSurface(page: Page, theme: 'dark' | 'light') {
  await page.emulateMedia({ colorScheme: theme });
  await page.goto('/login');

  const card = page.locator('.login__card');
  const submit = page.getByRole('button', { name: 'Sign in' });
  const heading = page.getByRole('heading', { name: 'Sign in to Hikyo' });
  const lede = page.getByText('Use the credential you established');

  await expectPinnedAssertionSet(page, {
    flow: 'login',
    surface: 'login',
    theme,
    text: [heading, lede],
    radii: [
      [card, 'container'],
      [submit, 'control'],
      [page.getByLabel('Username'), 'control'],
      [page.getByLabel('Password'), 'control'],
    ],
    fonts: [
      [heading, 'ui'],
      [lede, 'ui'],
    ],
    colours: [
      [heading, 'color', '--tx'],
      [lede, 'color', '--tx-dim'],
      [card, 'backgroundColor', '--bg-raise'],
      [card, 'borderTopColor', '--line'],
      [submit, 'backgroundColor', '--accent'],
      [submit, 'color', '--on-accent'],
    ],
    hairlines: [card, page.getByLabel('Username')],
    density: [[submit, '--touch']],
  });
}

/**
 * Flow: login (registry surface `login`).
 *
 * Covers the surface's whole job — refusal and success — and runs the pinned
 * assertion set over everything it touches.
 */

test.describe('login', () => {
  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
  });

  test('refuses a wrong credential in text and ARIA, not colour', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: 'Sign in to Hikyo' })).toBeVisible();

    await page.getByLabel('Username').fill(ADMIN.username);
    await page.getByLabel('Password').fill('not the password at all');
    await page.getByRole('button', { name: 'Sign in' }).click();

    const alert = page.getByRole('alert');
    await expectStatusIsTextAndAria(page, alert);
    // The refusal must not name which half was wrong: the server closes that
    // oracle deliberately and the UI must not reopen it.
    await expect(alert).toContainText('username and password');
    await expect(alert).not.toContainText(/unknown|no such|does not exist/i);

    // Still on the login page, cookie-free.
    await expect(page).toHaveURL(/\/login$/);
    expect(await page.context().cookies()).toEqual([]);
  });

  test('signs in and establishes a browser session on cookies alone', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('Username').fill(ADMIN.username);
    await page.getByLabel('Password').fill(ADMIN.password);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page.getByRole('navigation', { name: 'Organisations' })).toBeVisible();

    const cookies = await page.context().cookies();
    const session = cookies.find((c) => c.name === '__Host-hikyo');
    const csrf = cookies.find((c) => c.name === '__Host-hikyo-csrf');
    expect(session, 'no browser session cookie').toBeDefined();
    expect(session?.httpOnly, 'the session token is readable by script').toBe(true);
    expect(csrf, 'no synchronizer-token cookie').toBeDefined();
    expect(csrf?.httpOnly, 'the synchronizer token is unreachable to the SPA').toBe(false);

    // Nothing about the session is in storage: the whole point of the cookie
    // pair is that JavaScript holds no replayable credential.
    const stored = await page.evaluate(() => ({
      local: Object.entries(globalThis.localStorage),
      session: Object.entries(globalThis.sessionStorage),
    }));
    expect(JSON.stringify(stored)).not.toContain('hik_1_');
  });

  // The palette is a dual-theme palette, so conformance is a dual-theme claim:
  // the pinned set runs on the surface in both schemes.
  for (const scheme of ['dark', 'light'] as const) {
    test(`meets the pinned assertion set (${scheme})`, async ({ page }) => {
      await expectLoginSurface(page, scheme);
    });
  }

  test('is dark by default and follows the platform preference', async ({ page }) => {
    await page.goto('/login');
    // No explicit choice has been made — no attribute, no stored value — and
    // no script decides the theme, which is what lets the CSP forbid inline
    // script without a first-paint flash.
    await expect(page.locator('html')).not.toHaveAttribute('data-theme', /.+/);

    await page.emulateMedia({ colorScheme: 'dark' });
    const dark = await measureSurfaceLuminance(page);
    expect(dark.luminance, `the dark surface is not dark (${dark.colour})`).toBeLessThan(0.1);

    // Chromium never reports `no-preference`, so "dark default" is asserted
    // where it is observable — the declared default in the stylesheet, before
    // the light override — via the document's own colour-scheme order.
    const declared = await page.evaluate(
      () => document.querySelector('meta[name="color-scheme"]')?.getAttribute('content') ?? '',
    );
    expect(declared.trim().split(/\s+/)[0], 'the document does not declare dark first').toBe(
      'dark',
    );

    await page.emulateMedia({ colorScheme: 'light' });
    const light = await measureSurfaceLuminance(page);
    expect(
      light.luminance,
      `a light platform preference was not respected (${light.colour})`,
    ).toBeGreaterThan(0.7);
  });

  test('meets the pinned contrast floor in both themes', async ({ page }) => {
    await page.goto('/login');
    for (const scheme of ['dark', 'light'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await expectContrast(page.getByRole('heading', { name: 'Sign in to Hikyo' }));
      await expectContrast(page.getByText('Use the credential you established'));
      await expectContrast(page.getByText('Username'));
    }
  });
});
