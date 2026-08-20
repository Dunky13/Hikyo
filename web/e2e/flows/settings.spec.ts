import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import {
  zDefinitionsSettings,
  zEnvironment,
  zEnvironmentSettings,
  zOrg,
  zProject,
  zProjectRetentionPolicy,
  zRetentionPolicy,
} from '@hikyo/zod';
import { generatePath } from 'react-router';
import { z } from 'zod';

import { expectPinnedAssertionSet, expectStatusIsTextAndAria } from '../fixtures/assertions.ts';
import { browserApi, readSeed, STORAGE_STATE } from '../fixtures/instance.ts';
import { surfacesForFlow } from '../registry.ts';

/**
 * Flow: organisation and project settings (registry surfaces `org-settings`
 * and `project-settings`) — mvp-boundary S3's "project/org settings incl.
 * retention + danger zones", against the locked prototype #29 iterations 14
 * (org) and 15/16 (project, retention).
 *
 * Everything destructive here happens to objects this flow CREATES. The
 * seeded tenant is the reveal, matrix and machine-access flows' subject: its
 * environment policy is what their ceremonies depend on, and a settings drill
 * that flipped production's protected flag would break three other flows from
 * a cause several files away. So the drills run on a throwaway organisation
 * and a throwaway project, named per Playwright project so a run that dies
 * halfway cannot collide with the next viewport's run.
 *
 * The pinned assertion set runs on the SEEDED organisation and project, where
 * the retention panels and the environment policy have real state to render.
 */

const seed = readSeed();
const SETTINGS_SURFACES = surfacesForFlow('chrome-settings');

function isBrowserApiStatus(error: unknown, status: number): boolean {
  return error instanceof Error && error.message.includes(` answered ${status}:`);
}

test.describe('organisation settings', () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ storageState: STORAGE_STATE });

  let context: BrowserContext;
  let page: Page;
  let drillOrg = '';
  let drillName = '';

  test.beforeAll(async ({ browser }, testInfo) => {
    context = await browser.newContext({ storageState: STORAGE_STATE });
    page = await context.newPage();
    await page.goto('/');
    drillName = `Settings drill ${testInfo.project.name}`;
    const created = await browserApi(page, 'POST', '/api/v1/orgs', zOrg, { name: drillName });
    drillOrg = created.id;
  });

  test.afterAll(async () => {
    if (drillOrg !== '') {
      // The delete drill below may already have taken it; either way the
      // instance is left as it was found.
      try {
        await browserApi(page, 'DELETE', `/api/v1/orgs/${drillOrg}`, z.null());
      } catch (error) {
        if (!isBrowserApiStatus(error, 404)) {
          throw error;
        }
      }
    }
    await context.close();
  });

  test('states the organisation cap and saves a new one', async () => {
    await page.goto(`/orgs/${seed.org}/settings`);
    await expect(
      page.getByRole('heading', { name: 'Organisation settings', level: 1 }),
    ).toBeVisible();

    const retention = page.locator('#org-retention');
    // keep-if-either is TWO bounds, and the sentence says the OR out loud: a
    // payload survives while it is young enough or recent enough.
    await expect(retention).toContainText('OR among the last');
    const projectPolicy = retention
      .locator(`a[href="/orgs/${seed.org}/projects/${seed.project}/settings"]`)
      .locator('..');
    await expect(projectPolicy).toContainText(/inherits →|custom —/);
    await expect(projectPolicy).toContainText('OR among the last');

    const before = await retention.getByLabel('Maximum age, in days').inputValue();
    const beforeCount = await retention
      .getByLabel('Revisions kept per environment')
      .inputValue();
    try {
      await retention.getByLabel('Maximum age, in days').fill('');
      await retention.getByRole('button', { name: 'Save retention' }).click();
      await expect(retention.getByRole('alert')).toContainText(
        'Maximum age in days must be a whole number of at least 1.',
      );

      await retention.getByLabel('Maximum age, in days').fill('60');
      await retention.getByLabel('Revisions kept per environment').fill('8');
      await retention.getByRole('button', { name: 'Save retention' }).click();
      const saved = page.locator('.notice').filter({ hasText: 'Retention saved' });
      await expectStatusIsTextAndAria(page, saved);
      await expect(saved).toContainText('younger than 60 days OR among the last 8');
    } finally {
      // Restored: the retention cap is instance state the GC scheduler reads,
      // and a run must leave it as it found it.
      await browserApi(page, 'PUT', `/api/v1/orgs/${seed.org}/retention`, zRetentionPolicy, {
        mode: 'keep-if-either',
        max_age_seconds: Number(before) * 86400,
        last_revisions: Number(beforeCount),
      });
    }
  });

  test('renames the organisation and says who may do it', async () => {
    await page.goto(`/orgs/${drillOrg}/settings`);
    await expect(page.getByLabel('Name', { exact: true })).toHaveValue(drillName);
    // The standing consequence, stated on the surface rather than discovered
    // as a mysterious refusal: the locked capability set has no org-lifecycle
    // atom, so this is instance-operator work.
    await expect(page.locator('#org-identity')).toContainText('instance-operator work');

    await page.getByLabel('Name', { exact: true }).fill(`${drillName} renamed`);
    await page.getByRole('button', { name: 'Rename' }).click();
    const done = page.locator('.notice').filter({ hasText: 'Renamed to' });
    await expectStatusIsTextAndAria(page, done);
    drillName = `${drillName} renamed`;
  });

  test('does not claim an organisation is active when identity is unreadable', async () => {
    const orgRead = new RegExp(`/api/v1/orgs/${drillOrg}$`);
    await page.route(orgRead, (route) =>
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: { code: 'internal', message: 'internal error' } }),
      }),
    );
    try {
      await page.goto(`/orgs/${drillOrg}/settings`);
      const state = page.locator('#org-identity .kv__pair').filter({ hasText: 'State' });
      await expect(state.locator('dd')).toHaveText('—');
      await expect(state.locator('dd')).not.toHaveText('active');
    } finally {
      await page.unroute(orgRead);
    }
  });

  test('disarms organisation deletion while the route identity is pending', async () => {
    const targetName = `Pending org ${Date.now()}`;
    const target = await browserApi(page, 'POST', '/api/v1/orgs', zOrg, { name: targetName });
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const targetRead = new RegExp(`/api/v1/orgs/${target.id}$`);
    await page.route(targetRead, async (route) => {
      await gate;
      await route.continue();
    });
    try {
      await page.goto(`/orgs/${drillOrg}/settings`);
      const danger = page.locator('#org-danger');
      await danger.getByLabel('Delete this organisation').fill(drillName);
      await expect(danger.getByRole('button', { name: 'Delete organisation' })).toBeEnabled();

      await page.evaluate((path) => {
        history.pushState(null, '', path);
        dispatchEvent(new PopStateEvent('popstate'));
      }, `/orgs/${target.id}/settings`);
      await expect(page).toHaveURL(new RegExp(`${target.id}/settings$`));
      await expect(page.getByLabel('Name', { exact: true })).toHaveValue('');
      const pendingDanger = page.locator('#org-danger');
      await expect(pendingDanger.getByLabel('Delete this organisation')).toHaveValue('');
      await expect(pendingDanger.getByRole('button', { name: 'Delete organisation' })).toBeDisabled();
      if (release === undefined) {
        throw new Error('the organisation-read gate was not installed');
      }
      release();
      await expect(page.getByLabel('Name', { exact: true })).toHaveValue(targetName);
    } finally {
      if (release !== undefined) {
        release();
      }
      await page.unroute(targetRead);
      await browserApi(page, 'DELETE', `/api/v1/orgs/${target.id}`, z.null());
    }
  });

  test('deletes the organisation only behind the typed name', async () => {
    await page.goto(`/orgs/${drillOrg}/settings`);
    const danger = page.locator('#org-danger');
    const remove = danger.getByRole('button', { name: 'Delete organisation' });
    await expect(remove).toBeDisabled();
    // The armed state is text, not only a disabled attribute: "why is this
    // button dead" is answerable without seeing it.
    await expect(danger.getByRole('status')).toContainText('Type');

    await danger.getByLabel('Delete this organisation').fill('not the name');
    await expect(remove).toBeDisabled();

    await danger.getByLabel('Delete this organisation').fill(drillName);
    await expect(danger.getByRole('status')).toContainText('The name matches');
    await expect(remove).toBeEnabled();
    await remove.click();
    await expect(page.locator('.notice').filter({ hasText: 'Organisation deleted' })).toBeVisible();
    drillOrg = '';
  });

});

test.describe('project settings', () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ storageState: STORAGE_STATE });

  let context: BrowserContext;
  let page: Page;
  let drillProject = '';
  let drillEnv = '';
  let drillName = '';

  const base = () => `/api/v1/orgs/${seed.org}/projects/${drillProject}`;

  test.beforeAll(async ({ browser }, testInfo) => {
    context = await browser.newContext({ storageState: STORAGE_STATE });
    page = await context.newPage();
    await page.goto('/');
    drillName = `drill-${testInfo.project.name}`;
    const project = await browserApi(
      page,
      'POST',
      `/api/v1/orgs/${seed.org}/projects`,
      zProject,
      { name: drillName },
    );
    drillProject = project.id;
    const environment = await browserApi(
      page,
      'POST',
      `${base()}/environments`,
      zEnvironment,
      { name: 'staging' },
    );
    drillEnv = environment.id;
  });

  test.afterAll(async () => {
    if (drillProject !== '') {
      try {
        if (drillEnv !== '') {
          await browserApi(page, 'DELETE', `${base()}/environments/${drillEnv}`, z.null());
        }
        await browserApi(page, 'DELETE', base(), z.null());
      } catch (error) {
        if (!isBrowserApiStatus(error, 404)) {
          throw error;
        }
      }
    }
    await context.close();
  });

  test('renames the project and leaves the identifier alone', async () => {
    await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
    await expect(page.getByRole('heading', { name: 'Project settings', level: 1 })).toBeVisible();
    await expect(page.locator('#project-identity')).toContainText(drillProject);

    await page.getByLabel('Name', { exact: true }).fill(`${drillName}-renamed`);
    await page.getByRole('button', { name: 'Rename' }).click();
    await expect(page.locator('.notice').filter({ hasText: 'Renamed to' })).toBeVisible();
    drillName = `${drillName}-renamed`;
    // The identifier is what every URL, pin and audit row already names.
    await expect(page.locator('#project-identity')).toContainText(drillProject);
  });

  test('protects an environment and caps its reveal window at zero', async () => {
    await browserApi(
      page,
      'PUT',
      `${base()}/environments/${drillEnv}/settings`,
      zEnvironmentSettings,
      {
      protected: false,
      reauth_window_seconds: 60,
      },
    );
    await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
    const policy = page.locator('#project-policy');
    const row = policy.locator('.envpolicy__row').filter({ hasText: 'staging' });

    await expect(row.getByLabel('Protected environment')).not.toBeChecked();
    await expect(row.getByLabel('Reveal reauthentication window')).toHaveValue('60');
    await expect(row.getByLabel('Reveal reauthentication window')).toContainText(
      '60 seconds (current)',
    );

    await row.getByLabel('Protected environment').check();
    // Fixed at zero and stated, not hidden: protection and an explicit zero
    // window are different facts.
    await expect(row.getByLabel('Reveal reauthentication window')).toBeDisabled();
    await expect(row).toContainText('Protected caps this window at 0');
    await row.getByRole('button', { name: 'Save policy for staging' }).click();
    const done = page.locator('.notice').filter({ hasText: 'is protected' });
    await expectStatusIsTextAndAria(page, done);
    await expect(done).toContainText('every disclosure takes its own passkey ceremony');

    // And back, with a real sliding window.
    await page.reload();
    const again = page.locator('.envpolicy__row').filter({ hasText: 'staging' });
    await again.getByLabel('Protected environment').uncheck();
    await again.getByLabel('Reveal reauthentication window').selectOption('300');
    await again.getByRole('button', { name: 'Save policy for staging' }).click();
    await expect(page.locator('.notice').filter({ hasText: 'is not protected' })).toContainText(
      '300 seconds',
    );

    await page.reload();
    const readBack = page.locator('.envpolicy__row').filter({ hasText: 'staging' });
    await expect(readBack.getByLabel('Protected environment')).not.toBeChecked();
    await expect(readBack.getByLabel('Reveal reauthentication window')).toHaveValue('300');

    await expect(policy.getByLabel('Definitions source')).toHaveValue('db');
  });

  test('persists Git-governed definitions and explains the read-only boundary', async () => {
    await page.emulateMedia({ colorScheme: 'dark' });
    try {
      await browserApi(page, 'PUT', `${base()}/definitions/settings`, zDefinitionsSettings, {
        definitions_source: 'db',
      });
      await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
      const policy = page.locator('#project-policy');
      const source = policy.getByLabel('Definitions source');
      await expect(source).toHaveValue('db');

      // Select by contract value: labels are presentation and may be localised.
      await source.selectOption('git');
      const gitNotice = policy.getByRole('alert').filter({
        hasText:
          'Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`.',
      });
      await expect(gitNotice.locator('span').last()).toHaveText(
        'Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`.',
      );
      await expect(source).toHaveValue('git');

      await page.reload();
      const persistedPolicy = page.locator('#project-policy');
      const persistedSource = persistedPolicy.getByLabel('Definitions source');
      await expect(persistedSource).toHaveValue('git');
      const persistedNotice = persistedPolicy.getByRole('alert').filter({
        hasText:
          'Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`.',
      });
      await expect(persistedNotice).toBeVisible();
      await expect(persistedPolicy).toContainText('Values remain editable in either mode.');

      const heading = page.getByRole('heading', { name: 'Project settings', level: 1 });
      await expectPinnedAssertionSet(page, {
        flow: 'chrome-settings',
        surface: 'project-settings',
        theme: 'dark',
        text: [heading, persistedNotice, persistedPolicy.getByText(/Values remain editable/)],
        radii: [
          [persistedPolicy, 'container'],
          [persistedSource, 'control'],
        ],
        fonts: [
          [heading, 'ui'],
          [page.locator('#project-identity .kv dd').first(), 'mono'],
        ],
        colours: [
          [heading, 'color', '--tx'],
          [persistedPolicy, 'backgroundColor', '--bg-raise'],
          [persistedPolicy, 'borderTopColor', '--line'],
        ],
        hairlines: [persistedPolicy],
        density: [[persistedSource, '--touch']],
      });

      // project-settings remains capable of changing its own governance mode.
      await persistedSource.selectOption('db');
      await expect(persistedSource).toHaveValue('db');
      await expect(persistedNotice).toHaveCount(0);
      await page.reload();
      await expect(page.locator('#project-policy').getByLabel('Definitions source')).toHaveValue(
        'db',
      );
    } finally {
      await page.emulateMedia({ colorScheme: null });
    }
  });

  test('keeps save disabled while an environment policy is unreadable', async () => {
    const settingsPath = `${base()}/environments/${drillEnv}/settings`;
    await page.route(`**${settingsPath}`, async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ error: { code: 'not_found', message: 'not found' } }),
        });
        return;
      }
      await route.continue();
    });
    try {
      await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
      const row = page.locator('.envpolicy__row').filter({ hasText: 'staging' });
      await expect(row).toContainText('policy could not be read');
      await expect(row.getByRole('button', { name: 'Save policy for staging' })).toBeDisabled();
    } finally {
      await page.unroute(`**${settingsPath}`);
    }
  });

  for (const refusal of [
    { status: 403, code: 'forbidden', text: 'not permitted to read' },
    { status: 500, code: 'internal', text: 'failed to load' },
  ]) {
    test(`surfaces a ${refusal.status} environment-policy read as an alert`, async () => {
      const settingsPath = `${base()}/environments/${drillEnv}/settings`;
      await page.route(`**${settingsPath}`, async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: refusal.status,
            contentType: 'application/json',
            body: JSON.stringify({ error: { code: refusal.code, message: refusal.code } }),
          });
          return;
        }
        await route.continue();
      });
      try {
        await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
        const row = page.locator('.envpolicy__row').filter({ hasText: 'staging' });
        await expect(row.getByRole('alert')).toContainText(refusal.text);
        await expect(row.getByRole('button', { name: 'Save policy for staging' })).toBeDisabled();
      } finally {
        await page.unroute(`**${settingsPath}`);
      }
    });
  }

  test('does not turn failed dependencies into empty or generic retention state', async () => {
    const environmentsRead = new RegExp(`${base()}/environments$`);
    const orgRetentionRead = new RegExp(`/api/v1/orgs/${seed.org}/retention$`);
    const fault = {
      status: 500,
      contentType: 'application/json',
      body: JSON.stringify({ error: { code: 'internal', message: 'internal error' } }),
    };
    await page.route(environmentsRead, (route) => route.fulfill(fault));
    await page.route(orgRetentionRead, (route) => route.fulfill(fault));
    try {
      await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
      await expect(page.locator('#project-policy').getByRole('alert')).toContainText(
        'environments could not be read',
      );
      await expect(page.getByText('This project holds no environments yet.')).toHaveCount(0);
      await expect(page.locator('#project-retention').getByRole('alert')).toContainText(
        'organisation retention cap could not be read',
      );
      await expect(
        page.getByText('The organisation cap decides what this project may keep.'),
      ).toHaveCount(0);
    } finally {
      await page.unroute(environmentsRead);
      await page.unroute(orgRetentionRead);
    }
  });

  test('shows the server detail for each retention-cap dimension', async () => {
    await browserApi(page, 'PUT', `${base()}/retention`, zProjectRetentionPolicy, {
      inherited: false,
      max_age_seconds: 60,
      last_revisions: 2,
    });
    await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
    const retention = page.locator('#project-retention');
    await expect(retention).toContainText('Organisation cap');
    await expect(retention.locator('.retention__current')).toContainText('1 minute');
    await expect(retention.getByRole('alert')).toContainText('exact (60 seconds), not whole days');
    await expect(retention.getByLabel('Maximum age, in days')).toHaveValue('');
    await expect(retention.getByLabel('Maximum age, in days')).toBeDisabled();
    await retention.getByRole('button', { name: 'Save retention' }).click();
    await expect(
      retention
        .getByRole('alert')
        .filter({ hasText: 'Maximum age in days must be a whole number of at least 1.' }),
    ).toBeVisible();

    await retention.getByRole('button', { name: 'Replace with whole days' }).click();
    await expect(retention.getByLabel('Maximum age, in days')).toBeEnabled();

    await retention.getByLabel('Policy').selectOption('override');
    await retention.getByLabel('Maximum age, in days').fill('');
    await retention.getByLabel('Revisions kept per environment').fill('5');
    await retention.getByRole('button', { name: 'Save retention' }).click();
    await expect(
      retention
        .getByRole('alert')
        .filter({ hasText: 'Maximum age in days must be a whole number of at least 1.' }),
    ).toBeVisible();

    await retention.getByLabel('Maximum age, in days').fill('30');
    await retention.getByLabel('Revisions kept per environment').fill('40');
    await retention.getByRole('button', { name: 'Save retention' }).click();
    // Server-side SafeDetail names the cap's revision-count dimension.
    await expect(
      page.getByRole('alert').filter({ hasText: 'last_revisions=10' }),
    ).toBeVisible();

    await retention.getByLabel('Revisions kept per environment').fill('5');
    await retention.getByRole('button', { name: 'Save retention' }).click();
    await expect(page.locator('.notice').filter({ hasText: 'Override saved' })).toContainText(
      'younger than 30 days OR among the last 5',
    );

    await retention.getByLabel('Policy').selectOption('inherit');
    await retention.getByRole('button', { name: 'Save retention' }).click();
    await expect(page.locator('.notice').filter({ hasText: 'Override cleared' })).toBeVisible();
  });

  test('disarms typed-name deletion when route identity changes', async () => {
    await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
    await expect(page.getByLabel('Name', { exact: true })).toHaveValue(drillName);
    const danger = page.locator('#project-danger');
    await danger.getByLabel('Delete this project').fill(drillName);
    await expect(danger.getByRole('button', { name: 'Delete project' })).toBeEnabled();

    const target = `/orgs/${seed.org}/projects/${seed.project}/settings`;
    const projectRead = new RegExp(
      `/api/v1/orgs/${seed.org}/projects/${seed.project}$`,
    );
    await page.route(projectRead, (route) =>
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: { code: 'internal', message: 'internal error' } }),
      }),
    );
    try {
      await page.evaluate((path) => {
        history.pushState(null, '', path);
        dispatchEvent(new PopStateEvent('popstate'));
      }, target);
      await expect(page).toHaveURL(new RegExp(`${seed.project}/settings$`));
      await expect(page.getByLabel('Name', { exact: true })).toHaveValue('');
      await expect(page.getByRole('button', { name: 'Rename' })).toBeDisabled();
      const nextDanger = page.locator('#project-danger');
      await expect(nextDanger.getByLabel('Delete this project')).toHaveValue('');
      await expect(nextDanger.getByRole('button', { name: 'Delete project' })).toBeDisabled();
    } finally {
      await page.unroute(projectRead);
    }
  });

  test('disarms typed-name deletion between successfully loaded projects with the same name', async () => {
    const otherOrg = await browserApi(page, 'POST', '/api/v1/orgs', zOrg, {
      name: `Same-name holder ${Date.now()}`,
    });
    const otherProject = await browserApi(
      page,
      'POST',
      `/api/v1/orgs/${otherOrg.id}/projects`,
      zProject,
      { name: drillName },
    );
    try {
      await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
      const danger = page.locator('#project-danger');
      await danger.getByLabel('Delete this project').fill(drillName);
      await expect(danger.getByRole('button', { name: 'Delete project' })).toBeEnabled();

      await page.goto(`/orgs/${otherOrg.id}/projects/${otherProject.id}/settings`);
      await expect(page.getByLabel('Name', { exact: true })).toHaveValue(drillName);
      const switched = page.locator('#project-danger');
      await expect(switched.getByLabel('Delete this project')).toHaveValue('');
      await expect(switched.getByRole('button', { name: 'Delete project' })).toBeDisabled();
    } finally {
      await browserApi(
        page,
        'DELETE',
        `/api/v1/orgs/${otherOrg.id}/projects/${otherProject.id}`,
        z.null(),
      );
      await browserApi(page, 'DELETE', `/api/v1/orgs/${otherOrg.id}`, z.null());
    }
  });

  test('refuses to delete a project that still holds an environment, then deletes it', async () => {
    await page.goto(`/orgs/${seed.org}/projects/${drillProject}/settings`);
    const danger = page.locator('#project-danger');
    await danger.getByLabel('Delete this project').fill(drillName);
    await danger.getByRole('button', { name: 'Delete project' }).click();
    // Deletion never cascades: emptying a container is explicit work.
    const refusal = page.getByRole('alert').filter({ hasText: 'never cascades' });
    await expect(refusal).toBeVisible();

    await browserApi(page, 'DELETE', `${base()}/environments/${drillEnv}`, z.null());
    drillEnv = '';
    await page.reload();
    await expect(page.getByLabel('Name', { exact: true })).toHaveValue(drillName);
    const again = page.locator('#project-danger');
    await again.getByLabel('Delete this project').fill(drillName);
    await again.getByRole('button', { name: 'Delete project' }).click();
    await expect(page.locator('.notice').filter({ hasText: 'Project deleted' })).toBeVisible();
    drillProject = '';
  });

});

test.describe('settings flow visual contract', () => {
  test.use({ storageState: STORAGE_STATE });

  // Registry-derived: adding a claimed surface adds its pinned checks here.
  for (const surface of SETTINGS_SURFACES) {
    for (const scheme of ['dark', 'light'] as const) {
      test(`meets the pinned assertion set on ${surface.label} (${scheme})`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        try {
          const path = generatePath(surface.path, { org: seed.org, project: seed.project });
          await page.goto(path);
          const heading = page.getByRole('heading', { name: surface.label, level: 1 });
          const well = page.locator('.panel').first();
          const save = page.getByRole('button', { name: 'Save retention' }).first();

          await expectPinnedAssertionSet(page, {
            flow: 'chrome-settings',
            surface: surface.id,
            theme: scheme,
            text: [
              heading,
              page.locator('.retention__current').first(),
              page.locator('.kv dd').first(),
            ],
            radii: [
              [well, 'container'],
              [save, 'control'],
            ],
            fonts: [
              [heading, 'ui'],
              [page.locator('.kv dd').first(), 'mono'],
            ],
            colours: [
              [heading, 'color', '--tx'],
              [well, 'backgroundColor', '--bg-raise'],
              [well, 'borderTopColor', '--line'],
            ],
            hairlines: [well],
            density: [[save, '--touch']],
          });
        } finally {
          await page.emulateMedia({ colorScheme: null });
        }
      });
    }
  }
});
