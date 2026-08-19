import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { zGrantResult, zServiceAccountList, zWhoAmI } from '@hikyo/zod';
import { z } from 'zod';

import { expectPinnedAssertionSet, expectStatusIsTextAndAria } from '../fixtures/assertions.ts';
import {
  browserApi,
  readSeed,
  refreshSharedSession,
  STORAGE_STATE,
} from '../fixtures/instance.ts';

/**
 * Flow: members & grants (registry surface `members`) — mvp-boundary S3's
 * "members (grant modal incl. blast warning + staging default)", against the
 * locked prototype #29 iteration 15.
 *
 * What it proves, in the permission ADR's own terms:
 *
 *  - the membership listing is one line PER CAPABILITY, each carrying its
 *    origin chips, grouped by principal and scope;
 *  - "who can…?" answers by inspection and counts a grant ABOVE the scope
 *    asked about, because grants inherit downward;
 *  - the grant modal's scope select runs narrow to wide, preselects an
 *    environment confirmed unprotected, and puts the protected one last and
 *    never selected;
 *  - an organisation-scoped grant shows its blast radius ENUMERATED — every
 *    project and environment, plus the future ones — and "back, change scope"
 *    keeps the composition, so the warning can be answered rather than only
 *    dismissed;
 *  - each checked capability lands as its own line, and revoking one is
 *    one click with feedback that stays on the page;
 *  - the org rail drives the breadcrumb and the org-scoped surfaces.
 *
 * The session is the shared administrator's: `manage-members` is MFA-mandatory
 * and the shared session is stepped up, and its `manage-members` is held at
 * INSTANCE scope, which reaches this organisation by ordinary downward
 * inheritance.
 */

const seed = readSeed();
/** The seed's safest scope: its one confirmed-unprotected environment named staging. */
const DEFAULT_SCOPE = `env:${seed.history.project}:${seed.history.staging}`;
const PATH = `/orgs/${seed.org}/members`;

/**
 * automationPrincipal is the grant target: the seeded `automation` service
 * account.
 *
 * Not the administrator: granting to yourself advances your OWN session
 * generation and kills the session the flow is running in. Not the workload
 * either: its normative allowlist admits `read` alone, so a two-capability
 * composition would be refused for a reason this flow is not about. The
 * automation class may hold read, edit, publish and definitions-edit at
 * project scope or below, which is exactly the composition the modal is for.
 */
async function automationPrincipal(page: Page): Promise<string> {
  const accounts = await browserApi(
    page,
    'GET',
    `/api/v1/orgs/${seed.org}/projects/${seed.project}/service-accounts`,
    zServiceAccountList,
  );
  const account = accounts.items.find((item) => item.name === seed.machine.automation);
  if (account === undefined) {
    throw new Error(`the fixture's ${seed.machine.automation} service account is missing`);
  }
  return account.principal_id;
}

/** revokeAll takes back everything this flow granted, whatever happened. */
async function revokeAll(page: Page, principal: string, capabilities: readonly string[]) {
  for (const capability of capabilities) {
    const query = `principal=${encodeURIComponent(principal)}&capability=${capability}`;
    try {
      await browserApi(
        page,
        'DELETE',
        `/api/v1/orgs/${seed.org}/projects/${seed.project}/environments/${seed.dev}/grants?${query}`,
        z.null(),
      );
    } catch (error) {
      if (error instanceof Error && error.message.includes('answered 404:')) {
        continue;
      }
      throw error;
    }
  }
}

async function freshPage(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ storageState: STORAGE_STATE });
  return { context, page: await context.newPage() };
}

test.describe('members and grants', () => {
  test.use({ storageState: STORAGE_STATE });

  test.beforeEach(async ({ page }) => {
    await page.goto(PATH);
    await expect(page.getByRole('heading', { name: 'Members', level: 1 })).toBeVisible();
  });

  test('lists one line per capability with its origin chips', async ({ page }) => {
    const table = page.getByRole('table');
    // The fixture's workload holds `read` on development, granted through the
    // API — so its origin is `manual`, not the break-glass kind the seeding
    // CLI writes at instance scope.
    await expect(table).toContainText('read');
    await expect(table).toContainText('payments · development');
    await expect(table.getByText('manual').first()).toBeVisible();
    // Instance-scope grants reach this org by inheritance and are absent by
    // design; the surface says so rather than leaving a hole.
    await expect(page.getByText('Instance-scope grants reach this organisation')).toBeVisible();
  });

  test('answers "who can…?" by inspection, counting the grants above the scope', async ({
    page,
  }) => {
    await page.getByLabel('Capability').selectOption('read');
    // By VALUE: the seed holds two projects with a `development` environment
    // (#59's history project), so a label is ambiguous.
    await page.getByLabel('On', { exact: true }).selectOption(`env:${seed.project}:${seed.dev}`);
    const answer = page.locator('.inspect__answer');
    await expect(answer).toContainText('grant line');

    // Production holds no `read` line of its own, and nothing inside the org
    // covers it — the honest answer is nobody, with the caveat that an
    // instance-scope holder would not appear.
    await page.getByLabel('On', { exact: true }).selectOption(`env:${seed.project}:${seed.prod}`);
    await expect(answer).toContainText('Nobody');
    await expect(answer).toContainText('instance-scope holder would not appear');
  });

  test('does not answer Nobody before the grant listing succeeds', async ({ page }) => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route(
      (url) => url.pathname === `/api/v1/orgs/${seed.org}/grants`,
      async (route) => {
        await gate;
        await route.continue();
      },
    );
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('status').filter({ hasText: 'Loading grants before answering' })).toBeVisible();
    await expect(page.locator('#members-inspect')).not.toContainText('Nobody');
    if (release === undefined) {
      throw new Error('the grant-list gate was not installed');
    }
    release();
    await expect(page.getByRole('status').filter({ hasText: 'Loading grants before answering' })).toHaveCount(0);
  });

  test('opens the grant modal with the safest scope preselected', async ({ page }) => {
    await page.getByRole('button', { name: 'New grant' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'New grant' })).toBeVisible();

    const scope = dialog.getByLabel('Scope');
    // The safest default: the seed's one confirmed-unprotected environment
    // NAMED staging (the history project's), preferred over `payments`'
    // development even though that project sorts first.
    await expect(scope).toHaveValue(DEFAULT_SCOPE);

    const values = await scope.locator('option').evaluateAll((options) =>
      options.map((option) => (option instanceof HTMLOptionElement ? option.value : '')),
    );
    const dev = values.indexOf(`env:${seed.project}:${seed.dev}`);
    const prod = values.indexOf(`env:${seed.project}:${seed.prod}`);
    const project = values.indexOf(`project:${seed.project}`);
    const org = values.indexOf(`org:${seed.org}`);
    expect(dev, 'development is offered').toBeGreaterThan(0);
    // Narrow to wide, with the protected environment last inside its project.
    expect(prod).toBeGreaterThan(dev);
    expect(project).toBeGreaterThan(prod);
    expect(org).toBeGreaterThan(project);

    // The capability explanations are the permission ADR's own wording, one
    // (?) toggle each, closed until asked for.
    const explain = dialog.locator('summary[aria-label="Explain reveal"]');
    await expect(explain.locator('..')).not.toHaveAttribute('open', '');
    await explain.click();
    await expect(explain.locator('..')).toHaveAttribute('open', '');
    await expect(dialog.getByText('current secret plaintext, by any route')).toBeVisible();
  });

  test('prefers a confirmed-unprotected staging environment by name', async ({ page }) => {
    // `payments` (development · production) sorts before the history project
    // (development · staging); position order alone would pick
    // payments/development. The rule prefers the confirmed-unprotected
    // environment named staging, wherever it sits.
    await page.getByRole('button', { name: 'New grant' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel('Scope')).toHaveValue(DEFAULT_SCOPE);
    await expect(dialog.getByLabel('Scope').locator('option:checked')).toHaveText('staging');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
  });

  test('resets a cancelled composition when a fresh grant dialog opens', async ({ page }) => {
    const principal = await automationPrincipal(page);
    const newGrant = page.getByRole('button', { name: 'New grant' });
    await newGrant.click();
    let dialog = page.getByRole('dialog');
    await dialog.getByLabel('Principal').fill(principal);
    await dialog.getByRole('checkbox', { name: 'read', exact: true }).check();
    await dialog.getByLabel('Scope').selectOption(`env:${seed.project}:${seed.prod}`);
    await dialog.getByRole('button', { name: 'Cancel' }).click();

    await newGrant.click();
    dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel('Principal')).toHaveValue('');
    await expect(dialog.getByRole('checkbox', { name: 'read', exact: true })).not.toBeChecked();
    await expect(dialog.getByLabel('Scope')).toHaveValue(DEFAULT_SCOPE);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
  });

  test('waits for the complete topology before enabling a new grant', async ({ page }) => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route(
      (url) => url.pathname === `/api/v1/orgs/${seed.org}/projects`,
      async (route) => {
        await gate;
        await route.continue();
      },
    );
    await page.reload({ waitUntil: 'domcontentloaded' });
    const newGrant = page.getByRole('button', { name: 'New grant' });
    await expect(newGrant).toBeDisabled();
    await expect(page.getByText(/Loading the complete organisation topology/)).toBeVisible();
    if (release === undefined) {
      throw new Error('the project-list gate was not installed');
    }
    release();
    await expect(newGrant).toBeEnabled();
    await newGrant.click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
  });

  test('warns on an org-scoped grant and keeps the composition on the way back', async ({
    page,
  }) => {
    const principal = await automationPrincipal(page);
    await page.getByRole('button', { name: 'New grant' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Principal').fill(principal);
    await dialog.getByRole('checkbox', { name: 'read', exact: true }).check();
    await dialog.getByRole('checkbox', { name: 'edit', exact: true }).check();
    await dialog.getByLabel('Scope').selectOption({ label: `${seed.orgName} (every project and environment)` });
    await dialog.getByRole('button', { name: 'Grant', exact: true }).click();

    const blast = page.getByRole('dialog');
    await expect(
      blast.getByRole('heading', { name: /blast radius/i }),
    ).toBeVisible();
    // The capabilities being handed over, named.
    await expect(blast).toContainText('read, edit');
    // Every project and every environment, enumerated rather than summarised
    // — including the protected one, and including the ones that do not exist.
    const list = blast.getByRole('list', { name: /organisation-scoped grant reaches/i });
    await expect(list).toContainText('payments');
    await expect(list).toContainText('development');
    await expect(list).toContainText('production (protected)');
    await expect(list).toContainText('any project created later');

    await blast.getByRole('button', { name: 'Back, change scope' }).click();
    // Composition preserved: a warning that threw the work away would train
    // people to click through it.
    const again = page.getByRole('dialog');
    await expect(again.getByLabel('Principal')).toHaveValue(principal);
    await expect(again.getByRole('checkbox', { name: 'read', exact: true })).toBeChecked();
    await expect(again.getByRole('checkbox', { name: 'edit', exact: true })).toBeChecked();
    await again.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('dialog')).toBeHidden();
  });

  test('marks unreadable environment protection and never preselects it', async ({ page }) => {
    // Every environment's protection becomes unreadable, so nothing is
    // CONFIRMED unprotected and nothing may be preselected — the history
    // project's staging included.
    const settingsPath = /\/api\/v1\/orgs\/[^/]+\/projects\/[^/]+\/environments\/[^/]+\/settings$/;
    await page.route(
      (url) => settingsPath.test(url.pathname) && url.search === '',
      (route) => route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({ error: { code: 'not_found', message: 'not found' } }),
      }),
    );
    await page.reload();
    await page.getByRole('button', { name: 'New grant' }).click();
    const scope = page.getByRole('dialog').getByLabel('Scope');
    await expect(
      scope.locator(`option[value="env:${seed.project}:${seed.dev}"]`),
    ).toHaveText('development (protection unreadable)');
    await expect(scope).toHaveValue('');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
  });

  test('reports a real later-capability refusal while keeping the earlier grant live', async ({ page }) => {
    const principal = await automationPrincipal(page);
    const attempted: string[] = [];
    const grantPath = `/api/v1/orgs/${seed.org}/projects/${seed.project}/environments/${seed.dev}/grants`;
    page.on('request', (request) => {
      if (request.method() === 'POST' && new URL(request.url()).pathname === grantPath) {
        attempted.push(z.object({ capability: z.string() }).parse(request.postDataJSON()).capability);
      }
    });
    try {
      await page.getByRole('button', { name: 'New grant' }).click();
      const dialog = page.getByRole('dialog');
      await dialog.getByLabel('Principal').fill(principal);
      await dialog.getByRole('checkbox', { name: 'read', exact: true }).check();
      // `pin` is an environment atom, but the automation principal's normative
      // allowlist refuses it. `read` before it is a real successful first write.
      await dialog.getByRole('checkbox', { name: 'edit', exact: true }).check();
      await dialog.getByRole('checkbox', { name: 'pin', exact: true }).check();
      await dialog.getByLabel('Scope').selectOption(`env:${seed.project}:${seed.dev}`);
      await dialog.getByRole('button', { name: 'Grant', exact: true }).click();

      const partial = page.getByRole('alert').filter({ hasText: 'Granted: read, edit' });
      await expect(partial).toContainText('2 of 3');
      await expect(partial).toContainText('pin was refused');
      await expect(partial).toContainText('live and listed below');
      const row = page.getByRole('row').filter({ hasText: principal });
      await expect(row).toContainText('read');
      await expect(row).toContainText('edit');
      expect(attempted).toEqual(['read', 'edit', 'pin']);
    } finally {
      await revokeAll(page, principal, ['read', 'edit', 'pin']);
    }
  });

  test('grants each capability as its own line and revokes one back', async ({ page }) => {
    const principal = await automationPrincipal(page);
    try {
      await page.getByRole('button', { name: 'New grant' }).click();
      const dialog = page.getByRole('dialog');
      await dialog.getByLabel('Principal').fill(principal);
      await dialog.getByRole('checkbox', { name: 'read', exact: true }).check();
      await dialog.getByRole('checkbox', { name: 'edit', exact: true }).check();
      await dialog.getByLabel('Scope').selectOption(`env:${seed.project}:${seed.dev}`);
      await dialog.getByRole('button', { name: 'Grant', exact: true }).click();

      const feedback = page.locator('.notice').filter({ hasText: 'Granted' });
      await expectStatusIsTextAndAria(page, feedback);
      await expect(feedback).toContainText('separate lines');

      // Two independent rows, not a bundle.
      const row = page.getByRole('row').filter({ hasText: principal });
      await expect(row).toContainText('read');
      await expect(row).toContainText('edit');

      await page
        .getByRole('button', { name: `Revoke edit on payments · development for ${principal}` })
        .click();
      const revoked = page.locator('.notice').filter({ hasText: 'Revoked edit' });
      await expectStatusIsTextAndAria(page, revoked);
      await expect(page.getByRole('row').filter({ hasText: principal })).not.toContainText('edit');
      await expect(page.getByRole('row').filter({ hasText: principal })).toContainText('read');
    } finally {
      await revokeAll(page, principal, ['read', 'edit']);
    }
  });

  test('renders membership and organisation server failures honestly', async ({ page }) => {
    await page.route(
      (url) => url.pathname === `/api/v1/orgs/${seed.org}/grants`,
      (route) => route.fulfill({ status: 500, contentType: 'application/json', body: '{}' }),
    );
    await page.route(
      (url) => url.pathname === `/api/v1/orgs/${seed.org}`,
      (route) => route.fulfill({ status: 500, contentType: 'application/json', body: '{}' }),
    );
    await page.reload();
    await expect(page.getByRole('alert').filter({ hasText: 'server failed while reading memberships' })).toBeVisible();
    await expect(page.locator('#members-inspect')).not.toContainText('Nobody');
    await expect(page.getByRole('alert').filter({ hasText: 'organisation could not be read' })).toBeVisible();
    await expect(page.getByRole('alert').filter({ hasText: 'second factor' })).toHaveCount(0);
  });

  test('switches real organisation membership from a project route without leaking the old org', async ({
    browser,
    page,
  }) => {
    const principal = (await browserApi(page, 'GET', '/api/v1/auth/whoami', zWhoAmI)).principal.id;
    let grantedA = false;
    let grantedB = false;

    const change = async (method: 'POST' | 'DELETE', org: string) => {
      const fresh = await freshPage(browser);
      try {
        const query = `principal=${encodeURIComponent(principal)}&capability=read`;
        await browserApi(
          fresh.page,
          method,
          `/api/v1/orgs/${org}/grants${method === 'DELETE' ? `?${query}` : ''}`,
          method === 'POST' ? zGrantResult : z.null(),
          method === 'POST' ? { principal, capability: 'read' } : undefined,
        );
      } catch (error) {
        if (method === 'DELETE' && error instanceof Error && error.message.includes('answered 404:')) {
          return;
        }
        throw error;
      } finally {
        await fresh.context.close();
      }
    };

    try {
      await change('POST', seed.org);
      grantedA = true;
      await refreshSharedSession();
      await change('POST', seed.orgB);
      grantedB = true;
      await refreshSharedSession();

      const view = await freshPage(browser);
      try {
        await view.page.goto(`/orgs/${seed.org}/projects/${seed.project}/matrix`);
        const rail = view.page.getByRole('navigation', { name: 'Organisations' });
        await expect(rail.getByRole('button', { name: `Organisation ${seed.orgName}` })).toHaveAttribute(
          'aria-current',
          'true',
        );
        await rail.getByRole('button', { name: `Organisation ${seed.orgBName}` }).click();
        await expect(view.page).toHaveURL(/\/projects$/);
        await expect(view.page.getByLabel('Breadcrumb')).toContainText(seed.orgBName);
        const menu = view.page.getByRole('button', { name: 'Menu' });
        if (await menu.isVisible()) {
          await menu.click();
        }
        await expect(view.page.getByRole('link', { name: 'Members' })).toHaveAttribute(
          'href',
          `/orgs/${seed.orgB}/members`,
        );
        await expect(view.page.getByText('payments', { exact: true })).toHaveCount(0);

        // A deep link into the second organisation must stay selected when the
        // human moves to an unscoped surface: the route named the org, and
        // `/projects` must not silently fall back to the first circle.
        await view.page.goto(`/orgs/${seed.orgB}/members`);
        await expect(view.page.getByLabel('Breadcrumb')).toContainText(seed.orgBName);
        const menuAgain = view.page.getByRole('button', { name: 'Menu' });
        if (await menuAgain.isVisible()) {
          await menuAgain.click();
        }
        await view.page.getByRole('link', { name: 'Projects', exact: true }).click();
        await expect(view.page).toHaveURL(/\/projects$/);
        await expect(view.page.getByLabel('Breadcrumb')).toContainText(seed.orgBName);
        await expect(
          rail.getByRole('button', { name: `Organisation ${seed.orgBName}` }),
        ).toHaveAttribute('aria-current', 'true');
      } finally {
        await view.context.close();
      }
    } finally {
      if (grantedA) {
        await change('DELETE', seed.org);
        await refreshSharedSession();
      }
      if (grantedB) {
        await change('DELETE', seed.orgB);
        await refreshSharedSession();
      }
    }
  });

  for (const scheme of ['dark', 'light'] as const) {
    test(`meets the pinned assertion set on members (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      try {
        const heading = page.getByRole('heading', { name: 'Members', level: 1 });
        const well = page.locator('.panel').first();
        const jump = page.getByRole('link', { name: 'Who can…?' });
        const chip = page.locator('.chip').first();
        const newGrant = page.getByRole('button', { name: 'New grant' });

        await expectPinnedAssertionSet(page, {
          flow: 'members',
          surface: 'members',
          theme: scheme,
          text: [heading, page.locator('.inspect__answer'), page.locator('.capability__name').first()],
          radii: [
            [well, 'container'],
            [newGrant, 'control'],
            [chip, 'badge'],
          ],
          fonts: [
            [heading, 'ui'],
            [page.locator('.capability__name').first(), 'mono'],
          ],
          colours: [
            [heading, 'color', '--tx'],
            [well, 'backgroundColor', '--bg-raise'],
            [well, 'borderTopColor', '--line'],
          ],
          hairlines: [well],
          density: [
            [newGrant, '--touch'],
            [jump, '--touch'],
          ],
        });
      } finally {
        await page.emulateMedia({ colorScheme: null });
      }
    });
  }

  for (const scheme of ['dark', 'light'] as const) {
    test(`meets the pinned assertion set on both grant dialogs (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      try {
        const principal = await automationPrincipal(page);
        const opener = page.getByRole('button', { name: 'New grant' });
        await opener.click();
        const composition = page.getByRole('dialog');
        await expect(composition).toBeVisible();

        await expectPinnedAssertionSet(page, {
          flow: 'members',
          surface: 'members',
          theme: scheme,
          text: [
            composition.getByRole('heading', { level: 2 }),
            composition.locator('.field__hint').first(),
          ],
          radii: [
            [composition, 'container'],
            [composition.getByRole('button', { name: 'Cancel' }), 'control'],
          ],
          fonts: [[composition.locator('.mono').first(), 'mono']],
          colours: [[composition, 'backgroundColor', '--bg-raise']],
          hairlines: [composition],
          density: [[composition.getByRole('button', { name: 'Cancel' }), '--touch']],
        });

        await composition.getByLabel('Principal').fill(principal);
        await composition.getByRole('checkbox', { name: 'read', exact: true }).check();
        await composition
          .getByLabel('Scope')
          .selectOption({ label: `${seed.orgName} (every project and environment)` });
        await composition.getByRole('button', { name: 'Grant', exact: true }).click();

        const blast = page.getByRole('dialog');
        const blastRow = blast.locator('.blast__list li').first();
        await expectPinnedAssertionSet(page, {
          flow: 'members',
          surface: 'members',
          theme: scheme,
          text: [blast.getByRole('heading', { level: 2 }), blast.locator('.blast__envs').first()],
          radii: [
            [blast, 'container'],
            [blastRow, 'container'],
            [blast.getByRole('button', { name: 'Back, change scope' }), 'control'],
          ],
          fonts: [[blast.locator('.mono').first(), 'mono']],
          colours: [[blast, 'backgroundColor', '--bg-raise']],
          hairlines: [blast, blastRow],
          density: [[blast.getByRole('button', { name: 'Back, change scope' }), '--touch']],
        });

        await page.keyboard.press('Escape');
        await expect(page.getByRole('dialog')).toBeHidden();
        await expect(opener).toBeFocused();
      } finally {
        await page.emulateMedia({ colorScheme: null });
      }
    });
  }
});
