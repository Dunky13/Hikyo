import { expect, test, type Page } from '@playwright/test';

import {
  expectPinnedAssertionSet,
  expectStatusIsTextAndAria,
} from '../fixtures/assertions.ts';
import { ADMIN, STORAGE_STATE } from '../fixtures/instance.ts';
import { surfacesForFlow } from '../registry.ts';

/**
 * Flow: the application chrome (registry surfaces `overview`, `projects`,
 * `settings`).
 *
 * The skeleton's contract is navigation, not content: every section is
 * reachable, the account entry works, the theme is switchable, and the whole
 * thing survives a phone viewport. The pinned assertion set runs over every
 * control the flow touches.
 *
 * These tests start from a session minted once in global setup rather than
 * driving the login form each time. Signing in is the login flow's subject,
 * and the instance's per-source throttle (ten attempts a minute) means a suite
 * that re-authenticates per test would eventually be measuring the throttle.
 */

/** openNav reveals the sidebar, which is a disclosure on a phone. */
async function openNav(page: Page): Promise<void> {
  const toggle = page.getByRole('button', { name: 'Menu' });
  if (await toggle.isVisible()) {
    if ((await toggle.getAttribute('aria-expanded')) !== 'true') {
      await toggle.click();
    }
  }
  await expect(page.getByRole('navigation', { name: 'Sections' })).toBeVisible();
}

test.describe('app chrome', () => {
  test.use({ storageState: STORAGE_STATE });

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('navigation', { name: 'Organisations' })).toBeVisible();
  });

  test('reaches every section of the skeleton', async ({ page }) => {
    for (const surface of surfacesForFlow('shell')) {
      await openNav(page);
      await page.getByRole('link', { name: surface.label, exact: true }).click();
      await expect(page.getByRole('heading', { name: surface.label, level: 1 })).toBeVisible();
      // The breadcrumb is the "where am I" answer and must follow.
      await expect(page.getByLabel('Breadcrumb')).toContainText(surface.label);
    }
  });

  test('a deep link is served by the instance, not just by the router', async ({ page }) => {
    // The SPA-fallback rule seen from the outside: a full page load of an
    // application route must return the document, uncached, not a 404.
    const response = await page.goto('/settings');
    expect(response?.status(), 'a deep link did not fall back to the document').toBe(200);
    expect(response?.headers()['cache-control'], 'the document was served cacheable').toBe(
      'no-cache',
    );
    await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  });

  test('switches theme and keeps the choice explicit', async ({ page }) => {
    const toggle = page.getByRole('button', { name: /theme/i });
    await expect(toggle).toHaveText('System theme');
    await toggle.click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await toggle.click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    // The choice survives a reload: it is a decision, not a session mood.
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  });

  // The rail's zero state. The bootstrap administrator's grants are all
  // instance-scoped, and `listMyOrgs` projects only the orgs a caller's own
  // grants NAME — so this session has none, correctly.
  //
  // What used to be here was a "you need a second factor" notice, because the
  // rail asked `listOrgs`, the operator's enumeration of every org on the
  // instance, which is MFA-mandatory. That notice was the UI apologising for
  // asking the wrong question; the zero state is the honest answer to the
  // right one, and it must still be text + ARIA rather than an empty column.
  test('shows the zero-organisation state rather than an empty rail', async ({ page }) => {
    await openNav(page);
    const notice = page.getByRole('status');
    await expectStatusIsTextAndAria(page, notice);
    await expect(notice).toContainText('No organisations yet');
    // And no step-up wall: nothing on the navigation surface asks for one.
    await expect(page.getByText(/second factor/i)).toHaveCount(0);
  });

  // The matrix is DERIVED from the registry, not re-listed beside it: this
  // flow asserts exactly the surfaces it claims, so claiming a fourth is the
  // same act as asserting it. Both themes, because the palette is a dual-theme
  // palette and half of it going unchecked is half a claim.
  for (const surface of surfacesForFlow('shell')) {
    for (const scheme of ['dark', 'light'] as const) {
      test(`meets the pinned assertion set on ${surface.label} (${scheme})`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.goto(surface.path);
        await openNav(page);

        const account = page.getByRole('button', { name: /^Account:/ });
        const theme = page.getByRole('button', { name: /theme/i });
        const heading = page.getByRole('heading', { name: surface.label, level: 1 });
        const well = page.locator('.card');
        const crumbs = page.getByLabel('Breadcrumb');
        const active = page.getByRole('link', { name: surface.label, exact: true });

        await expectPinnedAssertionSet(page, {
          flow: 'shell',
          surface: surface.id,
          theme: scheme,
          text: [heading, crumbs, active],
          radii: [
            // The identity circle is one of the three things allowed to be a pill.
            [account, 'pill'],
            [theme, 'control'],
            [well, 'container'],
          ],
          fonts: [
            [heading, 'ui'],
            [crumbs, 'ui'],
          ],
          colours: [
            [heading, 'color', '--tx'],
            [well, 'backgroundColor', '--bg-raise'],
            [well, 'borderTopColor', '--line'],
            // Treatment e's hairline rule: the sub-items hang off it.
            [page.locator('.sidebar__items').first(), 'borderLeftColor', '--line'],
          ],
          hairlines: [well],
          density: [[theme, '--touch']],
        });
      });
    }
  }

  test('the skip link is the first tab stop and becomes visible', async ({ page }) => {
    await page.keyboard.press('Tab');
    const skip = page.getByRole('link', { name: 'Skip to content' });
    await expect(skip).toBeFocused();
    await expect(skip).toBeInViewport();
  });
});

// Sign-out revokes the session it uses, so it gets its own — sharing the
// suite's would leave every later test holding a dead cookie.
test.describe('sign out', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('signs out through the account entry and clears both cookies', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('Username').fill(ADMIN.username);
    await page.getByLabel('Password').fill(ADMIN.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('navigation', { name: 'Organisations' })).toBeVisible();

    await page.getByRole('button', { name: /^Account:/ }).click();
    await page.getByRole('menuitem', { name: 'Sign out' }).click();

    // Sign-out is a cookie-authenticated POST, so it only succeeds if the SPA
    // echoed the synchronizer token — reaching the login page proves the whole
    // CSRF contract end to end, through the real server.
    await expect(page.getByRole('heading', { name: 'Sign in to Hikyo' })).toBeVisible();
    const names = (await page.context().cookies()).map((c) => c.name);
    expect(names).not.toContain('__Host-hikyo');
    expect(names).not.toContain('__Host-hikyo-csrf');
  });
});
