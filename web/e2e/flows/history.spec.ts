import { expect, test, type Locator, type Page } from '@playwright/test';
import {
  zExportValuesRequest,
  zPendingDraftList,
  zPublishRequest,
  zRevisionPinList,
  zValueCell,
} from '@hikyo/zod';

import {
  INTERACTIVE_ELEMENT_SELECTOR,
  expectPinnedAssertionSet,
  expectStatusIsTextAndAria,
  expectTouchTargets,
} from '../fixtures/assertions.ts';
import {
  fixtureBrowserCall as api,
  zFixtureIgnored as zAny,
  zFixtureRevisionList as zRevisions,
  zFixtureStaged as zStaged,
} from '../fixtures/api.ts';
import {
  countDisclosureEvents,
  establishSession,
  installPasskeyAuthenticator,
  readSeed,
  refreshSharedSession,
  STORAGE_STATE,
} from '../fixtures/instance.ts';
import { surfacesForFlow } from '../registry.ts';
import { zHistoryRollbackResult } from '../../src/api/history.ts';

/**
 * Flow: the revision-history drawer (registry surface `history`).
 *
 * Covers mvp-boundary **C5 [UI]** — the restore flow from the history drawer —
 * and the history half of **S3**: drawer, per-key filter, restore and the pin
 * lifecycle, on both viewport projects under the pinned assertion set.
 *
 * It runs against its OWN project (`seed.history`), not the matrix flow's: one
 * instance serves the whole suite, and the matrix flow asserts exact key counts
 * and exact cell text in `payments`.
 *
 * The fixture's shape is what makes the hard cases reachable:
 *
 *   added    LOG_LEVEL=debug · DB_PASSWORD=hunter2-r1 · WORKERS='not-an-integer'
 *   edited   DB_PASSWORD=hunter2-r2  (the SECRET edit) · WORKERS='12'
 *   edited   LOG_LEVEL=info          (the CONFIG edit)
 *   then WORKERS' declaration is TIGHTENED to `integer`
 *
 * so restoring the secret-edit revision stages exactly one clean row while still
 * opening a historical secret (the ceremony), and restoring or pinning the
 * key-adding revision is refused naming WORKERS.
 *
 * The revision NUMBERS are read out of the fixture, never assumed: every schema
 * act mints its own revision in every environment of the project, so the three
 * publishes above are not r1..r3 and hard-coding them would make this flow a
 * test of when a revision happens to be minted.
 */

const seed = readSeed();
const HISTORY_PATH = `/orgs/${seed.org}/projects/${seed.history.project}/matrix/history`;
const MATRIX_PATH = `/orgs/${seed.org}/projects/${seed.history.project}/matrix`;
const DEV_HISTORY = `${HISTORY_PATH}?env=${seed.history.dev}`;
const SCHEMES: readonly ('dark' | 'light')[] = ['dark', 'light'];
const PROJECT = `/api/v1/orgs/${seed.org}/projects/${seed.history.project}`;
const DEV = `${PROJECT}/environments/${seed.history.dev}`;

// --- the flow's own fixture repair -----------------------------------------
//
// This flow MUTATES its project: it stages restores, publishes them, and moves
// pins around. One instance serves the whole suite and runs it once per viewport
// project, so pass two starts from whatever pass one left. Every number this
// flow asserts is therefore DERIVED at `beforeAll`, and the two pieces of state
// pass one moves — the leftover invalid draft and the pins — are put back.
//
// The alternative, seeding two projects, buys the same property at the cost of a
// second fixture to keep in step; repairing is what the matrix flow does too,
// with per-project values.

type Facts = {
  /** The newest revision when this pass started. */
  current: number;
  /** How many rows the drawer's list renders, per environment. */
  devRevisions: number;
  stagingRevisions: number;
  /** The newest revision that EDITED each key. */
  secretEdit: number;
  configEdit: number;
  /** The revision that ADDED the tightened key, and still holds its bad value. */
  tightened: number;
  /** How many revisions the per-key filter keeps for the config key. */
  configKeyRevisions: number;
  secretKeyRevisions: number;
  /** True only while the instance still exactly matches global setup. */
  firstPass: boolean;
  seededPin: { workload: string; revision: number; expiresAt: string } | null;
  configBeforeRestore: string;
};

let facts: Facts;
test.beforeAll(async ({ browser }) => {
  const context = await browser.newContext({ storageState: STORAGE_STATE });
  const apiPage = await context.newPage();
  await apiPage.goto(DEV_HISTORY);

  // Repair only drift pass one can leave. A fresh pass must exercise the exact
  // state global setup built, not a state recreated by this hook.
  const pending = await api(apiPage, 'GET', `${DEV}/pending`, zPendingDraftList);
  const invalidTightenedDraft = pending.items.find(
    (draft) =>
      draft.name === seed.history.tightenedKey &&
      draft.operation === 'set' &&
      draft.value !== undefined &&
      !/^-?\d+$/.test(draft.value),
  );
  if (invalidTightenedDraft !== undefined) {
    const repaired = await api(apiPage, 'PUT', `${DEV}/values/${seed.history.tightenedKey}`, zStaged, {
      value: '12',
    });
    await api(apiPage, 'POST', `${DEV}/publish`, zAny, { version_ids: [repaired.version_id] });
  }

  const dev = await api(apiPage, 'GET', `${DEV}/revisions`, zRevisions);
  const staging = await api(
    apiPage,
    'GET',
    `${PROJECT}/environments/${seed.history.staging}/revisions`,
    zRevisions,
  );
  const newest = (key: string, change: 'added' | 'edited', atMost = Number.MAX_SAFE_INTEGER): number => {
    const found = dev.items.find((item) =>
      item.revision <= atMost &&
      item.changed_keys.some((changed) => changed.name === key && changed.change === change),
    );
    if (found === undefined) {
      throw new Error(`no revision in this environment ${change} ${key}`);
    }
    return found.revision;
  };
  const current = dev.items[0]?.revision;
  if (current === undefined) {
    throw new Error('the history fixture published no revisions');
  }

  const pins = await api(apiPage, 'GET', `${DEV}/pins`, zRevisionPinList);
  const config = await api(
    apiPage,
    'GET',
    `${DEV}/values/${seed.history.configKey}`,
    zValueCell,
  );
  if (!config.revealed || config.value === undefined) {
    throw new Error('history config fixture was not readable');
  }
  const firstPass = current === seed.history.pinnedRevision;
  const seededPin = pins.items.length === 1 && pins.items[0] !== undefined
    ? {
        workload: pins.items[0].workload_principal_id,
        revision: Number(pins.items[0].revision),
        expiresAt: pins.items[0].expires_at,
      }
    : null;
  const canonical = pins.items.length === 1 && pins.items[0] !== undefined &&
    pins.items[0].workload_principal_id === seed.history.pinnedWorkloadPrincipal &&
    pins.items[0].revision === BigInt(current) &&
    !pins.items[0].expired &&
    new Date(pins.items[0].expires_at).getTime() - Date.now() < 31 * 24 * 60 * 60 * 1000;
  if (!canonical) {
    for (const pin of pins.items) {
      await api(apiPage, 'DELETE', `${DEV}/pins/${pin.workload_principal_id}`, zAny);
    }
    const expiry = new Date(Date.now() + (seed.history.pinExpiryDays * 24 + 12) * 60 * 60 * 1000);
    await api(apiPage, 'POST', `${DEV}/pins`, zAny, {
      workload_principal_id: seed.history.pinnedWorkloadPrincipal,
      revision: current,
      expires_at: expiry.toISOString(),
    });
  }

  facts = {
    current,
    devRevisions: dev.items.length,
    stagingRevisions: staging.items.length,
    secretEdit: newest(seed.history.secretKey, 'edited', seed.history.pinnedRevision),
    configEdit: newest(seed.history.configKey, 'edited', seed.history.pinnedRevision),
    tightened: newest(seed.history.tightenedKey, 'added'),
    configKeyRevisions: dev.items.filter((item) =>
      item.changed_keys.some((changed) => changed.name === seed.history.configKey),
    ).length,
    secretKeyRevisions: dev.items.filter((item) =>
      item.changed_keys.some((changed) => changed.name === seed.history.secretKey),
    ).length,
    firstPass,
    seededPin,
    configBeforeRestore: config.value,
  };
  await context.close();
});

async function expectNoFixtureSecret(surface: Locator): Promise<void> {
  const text = await surface.textContent();
  for (const value of seed.history.secretValues) {
    expect(text).not.toContain(value);
  }
}

/**
 * Selects one revision, on either viewport.
 *
 * Below 800px the drawer shows ONE pane at a time, so the revision list is not
 * on screen while a detail is open — and an element that is not rendered is not
 * in the accessibility tree, which is a click that waits forever rather than a
 * click that fails. The back affordance is `display: none` on a desktop, so this
 * is a no-op there.
 */
async function openRevision(page: Page, revision: number): Promise<void> {
  const back = page.locator('#history-detail-back');
  if (await back.isVisible()) {
    await back.click();
  }
  await page.locator(`[data-history-revision="${String(revision)}"]`).click();
  await expect(page.locator('#history-detail-title')).toContainText(`r${String(revision)}`);
  await expectNoFixtureSecret(page.getByRole('complementary', { name: 'Revision history' }));
}

test.describe('revision history', () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ storageState: STORAGE_STATE });

  // The pinned assertion set runs FIRST, deliberately.
  //
  // The two ceremony-bearing tests below reissue the browser session — a
  // disclosure reauthentication mints a new cookie — so the suite's shared
  // storage state is stale afterwards. Asserting the surface before anything
  // mutates it keeps the S3 evidence off that dependency entirely, and it reads
  // the seeded state rather than whatever the last restore left behind.
  for (const surface of surfacesForFlow('history')) {
    for (const scheme of SCHEMES) {
      test(`meets the pinned assertion set on ${surface.label} (${scheme})`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.goto(DEV_HISTORY);

        const drawer = page.locator('.history');
        const heading = page.getByRole('heading', { name: '↺ Revision history' });
        const row = page.locator('.history__row').first();
        const retention = page.locator('.history__retention');
        const tab = page.locator('.history__tab').first();

        await expect(heading).toBeVisible();
        await expectNoFixtureSecret(drawer);
        if (facts.firstPass) {
          expect(facts.devRevisions, 'fresh pass must use the seeded revision list').toBe(
            seed.history.revisionCount,
          );
          expect(facts.seededPin?.workload, 'fresh pass must use the seeded workload').toBe(
            seed.history.pinnedWorkloadPrincipal,
          );
          expect(facts.seededPin?.revision, 'fresh pass must use the seeded pin revision').toBe(
            seed.history.pinnedRevision,
          );
          expect(
            new Date(facts.seededPin?.expiresAt ?? '').getTime(),
            'fresh pass must use the seeded pin expiry',
          ).toBe(new Date(seed.history.pinExpiresAt).getTime());
        }
        await expectPinnedAssertionSet(page, {
          flow: 'history',
          surface: surface.id,
          theme: scheme,
          text: [heading, row, retention],
          radii: [
            [retention, 'container'],
            [tab, 'control'],
          ],
          fonts: [
            [heading, 'ui'],
            [row.locator('.mono').first(), 'mono'],
          ],
          colours: [
            [heading, 'color', '--tx'],
            [drawer, 'backgroundColor', '--bg-raise'],
            [retention, 'borderTopColor', '--line'],
          ],
          hairlines: [retention],
          density: [[tab, '--touch']],
        });
      });
    }
  }


  test('opens from the matrix environment header and reads one environment at a time', async ({
    page,
  }) => {
    await page.goto(MATRIX_PATH);
    await expect(page.getByRole('heading', { name: 'Environment matrix', level: 1 })).toBeVisible();

    // Entry point one: the `rev N · history` link in the environment column head.
    await page
      .getByRole('link', { name: `rev ${String(facts.current)} · history` })
      .first()
      .click();
    await expect(page).toHaveURL(new RegExp(`/matrix/history\\?env=${seed.history.dev}$`));

    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expectNoFixtureSecret(drawer);
    await expect(drawer.getByRole('heading', { name: '↺ Revision history' })).toBeVisible();
    await expect(drawer).toContainText(`current r${String(facts.current)}`);

    // Three revisions of lineage, newest first.
    const list = drawer.getByRole('list', { name: 'Revisions, newest first' });
    await expect(list.getByRole('button')).toHaveCount(facts.devRevisions);
    await expect(list.getByRole('button').first()).toContainText(
      `r${String(facts.current)}`,
    );
    await expect(list.getByRole('button').first()).toContainText('current');

    // The read-only retention line: effective window, inheritance, and a
    // pointer at the surface that owns the knob. No editing here.
    const retention = drawer.locator('.history__retention');
    await expect(retention).toContainText('values kept:');
    await expect(retention).toContainText('plus pinned');
    await expect(retention).toContainText('inherits org');
    await expect(retention).toContainText('→ change it in project settings › Policy');
    await expect(
      retention.locator(INTERACTIVE_ELEMENT_SELECTOR),
    ).toHaveCount(0);

    // Environment tabs: a second environment with its own, shorter history.
    await drawer.getByRole('button', { name: 'staging' }).click();
    await expect(page).toHaveURL(new RegExp(`env=${seed.history.staging}`));
    await expect(list.getByRole('button')).toHaveCount(facts.stagingRevisions);
    await expectNoFixtureSecret(drawer);
    await drawer.getByRole('button', { name: 'development' }).click();
    await expect(list.getByRole('button')).toHaveCount(facts.devRevisions);
    await expectNoFixtureSecret(drawer);
  });

  test('shows one revision’s lineage without ever showing a secret value', async ({ page }) => {
    await page.goto(DEV_HISTORY);
    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expectNoFixtureSecret(drawer);
    await openRevision(page, facts.secretEdit);

    // The actor is a principal id, shortened, with the whole one in `title`:
    // nothing in this API resolves a human principal to a name.
    await expect(drawer).toContainText('Published by');
    await expect(drawer).toContainText('Schema revision pinned');

    // r2 is the secret edit. Write-presence only — the marker and the
    // transition, never a value, a length or a comparison.
    const changes = drawer.locator('.history__changes');
    await expect(changes).toContainText(`🔒 ${seed.history.secretKey}`);
    await expect(changes).toContainText('write-presence only');
    await expectNoFixtureSecret(drawer);
  });

  test('filters the timeline to one key, by click and by URL', async ({ page }) => {
    // Entry 1: the matrix KEY NAME opens the drawer filtered to that key
    // (revision-history it-1/6 — the name is history; any cell is the editor).
    await page.goto(MATRIX_PATH);
    await page.getByRole('link', { name: `History of ${seed.history.configKey}` }).click();
    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expect(drawer.locator('.history__filter')).toContainText(
      `filter active: history of ${seed.history.configKey}`,
    );
    await expect(page).toHaveURL(
      new RegExp(`key=${encodeURIComponent(seed.history.configKeyId)}`),
    );
    await expectNoFixtureSecret(drawer);

    // Entry 2: a changed-key row inside a revision's detail pane.
    await page.goto(DEV_HISTORY);
    await expectNoFixtureSecret(drawer);
    const list = drawer.getByRole('list', { name: 'Revisions, newest first' });

    // The config edit's own revision; clicking its changed key filters to it.
    await openRevision(page, facts.configEdit);
    await drawer.getByRole('button', { name: seed.history.configKey, exact: false }).first().click();

    const filter = drawer.locator('.history__filter');
    await expectStatusIsTextAndAria(page, filter);
    await expect(filter).toContainText(`filter active: history of ${seed.history.configKey}`);
    // LOG_LEVEL moved exactly twice: added, then edited.
    await expect(list.getByRole('button')).toHaveCount(facts.configKeyRevisions);
    await expectNoFixtureSecret(drawer);
    await expect(page).toHaveURL(
      new RegExp(`key=${encodeURIComponent(seed.history.configKeyId)}`),
    );

    // The same filter is a deep link, which is the whole point of it being a
    // query parameter rather than a second surface.
    await page.goto(`${DEV_HISTORY}&key=${encodeURIComponent(seed.history.secretKeyId)}`);
    await expect(drawer.locator('.history__filter')).toContainText(
      `history of ${seed.history.secretKey}`,
    );
    await expect(list.getByRole('button')).toHaveCount(facts.secretKeyRevisions);
    await expectNoFixtureSecret(drawer);

    await drawer.getByRole('button', { name: '✕ show every revision' }).click();
    await expect(list.getByRole('button')).toHaveCount(facts.devRevisions);
    await expectNoFixtureSecret(drawer);
  });

  test('restores an environment to an earlier revision and publishes the staged drafts', async ({
    page,
  }) => {
    const persistPasskey = await installPasskeyAuthenticator(page);
    try {
      await page.goto(DEV_HISTORY);
      const drawer = page.getByRole('complementary', { name: 'Revision history' });
      await expectNoFixtureSecret(drawer);
      await openRevision(page, facts.secretEdit);
      await expectNoFixtureSecret(drawer);

      await drawer
        .getByRole('button', { name: `Restore r${String(facts.secretEdit)}…` })
        .click();
      const sheet = page.getByRole('dialog');
      await expectNoFixtureSecret(sheet);
      await expect(sheet).toContainText('re-validates against the CURRENT schema');
      const rollbackResponse = page.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          new URL(response.url()).pathname === `${DEV}/revisions/${String(facts.secretEdit)}/rollback` &&
          response.ok(),
      );
      await sheet
        .getByRole('button', { name: `Stage the restore from r${String(facts.secretEdit)}` })
        .click();

      // Restore reads a superseded secret, so it takes a purpose-bound
      // ceremony over exactly that key before anything is staged.
      await expect(page.getByRole('heading', { name: /restore an earlier revision of/ })).toBeVisible();
      // The ceremony modal enumerates KEYS, never values: assert it on the
      // ceremony state too, or a secret leaking only there would go unnoticed.
      await expectNoFixtureSecret(page.getByRole('dialog', { name: /restore an earlier revision of|pin a historical revision of/ }));
      await expect(page.getByRole('list', { name: 'Keys this decision covers' })).toContainText(
        seed.history.secretKey,
      );
      await page.getByRole('button', { name: 'Use a passkey' }).click();
      const rollback = zHistoryRollbackResult.parse(await (await rollbackResponse).json());
      const restoredVersions = rollback.changes.map((change) => change.version_id);

      // The impact preview: a summary chip line, then the rows. Config
      // plaintext before→after; a secret would be status-only.
      const preview = page.getByRole('dialog');
      await expect(preview.locator('.history__chips')).toContainText('1 set');
      await expect(preview.locator('.history__impact')).toContainText(seed.history.configKey);
      await expect(preview.locator('.history__impact')).toContainText(
        `${facts.configBeforeRestore} → debug`,
      );
      await expect(preview.locator('.notice')).toContainText('Staged as ordinary drafts');
      await expectNoFixtureSecret(preview);

      // The in-drawer path spends the exact token and exact version set returned
      // by rollback. Deleting either assertion leaves this test red.
      const publishRequest = page.waitForRequest(
        (request) =>
          request.method() === 'POST' && new URL(request.url()).pathname === `${DEV}/publish`,
      );
      await page.locator('#history-restore-publish').click();
      const publishBody = zPublishRequest.parse((await publishRequest).postDataJSON());
      expect(publishBody.preview_token).toBe(rollback.preview.token);
      expect([...publishBody.version_ids].sort()).toEqual([...restoredVersions].sort());
      await expect(drawer.locator('.notice')).toContainText('Published the restore');
    } finally {
      // A disclosure ceremony REISSUES the browser session, so the suite's
      // shared storage state now holds a dead cookie — the next test would land
      // on the sign-in page for a reason several tests in its past. Persist the
      // counter, then re-mint, exactly as the matrix flow does.
      await persistPasskey();
      await refreshSharedSession();
    }
  });

  test('restores one key from the changed-key row', async ({ page }) => {
    await page.goto(DEV_HISTORY);
    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expectNoFixtureSecret(drawer);
    await openRevision(page, facts.configEdit);

    await drawer.getByRole('button', { name: `Restore ${seed.history.configKey}…` }).click();
    const sheet = page.getByRole('dialog');
    await expectNoFixtureSecret(sheet);
    await expect(sheet).toContainText(`Restore ${seed.history.configKey} from r`);
    const rollbackResponse = page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname === `${DEV}/revisions/${String(facts.configEdit)}/rollback` &&
        response.ok(),
    );
    await sheet.getByRole('button', { name: /^Stage the restore from r/ }).click();
    const rollback = zHistoryRollbackResult.parse(await (await rollbackResponse).json());

    // A config-only restore opens no secret plaintext, so it takes no ceremony.
    await expect(sheet.locator('.history__chips')).toContainText('1 set');
    await expect(sheet.locator('.history__impact')).toContainText('debug → info');
    await expectNoFixtureSecret(sheet);
    await sheet.locator('#history-restore-back').click();
    await expect(
      page.getByRole('button', { name: new RegExp(`${seed.history.configKey} in development:.*draft set`) }),
    ).toBeVisible();

    await page.getByRole('button', { name: /Review & publish/ }).click();
    const publishSheet = page.getByRole('region', { name: 'Publish drafts' });
    await expectNoFixtureSecret(publishSheet);
    const publishRequest = page.waitForRequest(
      (request) => request.method() === 'POST' && new URL(request.url()).pathname === `${DEV}/publish`,
    );
    await publishSheet.getByRole('button', { name: /Publish selected/ }).click();
    const publishBody = zPublishRequest.parse((await publishRequest).postDataJSON());
    expect(publishBody.preview_token).toBe(rollback.preview.token);
    expect([...publishBody.version_ids].sort()).toEqual(
      rollback.changes.map((change) => change.version_id).sort(),
    );
    await expect(page.locator('.notice')).toContainText('Published atomically: development');
  });

  test('refuses partial restore overlap, then publishes the restore set alone', async ({ page }) => {
    await page.goto(DEV_HISTORY);
    const advanced = await api(page, 'PUT', `${DEV}/values/${seed.history.configKey}`, zStaged, {
      value: 'trace',
    });
    await api(page, 'POST', `${DEV}/publish`, zAny, { version_ids: [advanced.version_id] });
    await page.reload();
    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expectNoFixtureSecret(drawer);
    await openRevision(page, facts.configEdit);
    await drawer.getByRole('button', { name: `Restore ${seed.history.configKey}…` }).click();
    const restoreSheet = page.getByRole('dialog');
    await expectNoFixtureSecret(restoreSheet);
    await restoreSheet.getByRole('button', { name: /^Stage the restore from r/ }).click();
    await expect(restoreSheet.locator('.history__impact')).toContainText(seed.history.configKey);
    await expectNoFixtureSecret(restoreSheet);
    await restoreSheet.locator('#history-restore-back').click();

    // Another key in the SAME environment makes the matrix sheet's version set
    // a partial overlap with the remembered restore preview.
    await page.getByRole('button', {
      name: new RegExp(`${seed.history.tightenedKey} in development:`),
    }).click();
    await page.getByLabel('development value').fill('13');
    await page.getByRole('button', { name: 'Save 1 draft' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);

    await page.getByRole('button', { name: /Review & publish/ }).click();
    const publishSheet = page.getByRole('region', { name: 'Publish drafts' });
    await expectNoFixtureSecret(publishSheet);
    await expect(publishSheet).toContainText(seed.history.configKey);
    await expect(publishSheet).toContainText(seed.history.tightenedKey);
    let publishRequests = 0;
    page.on('request', (request) => {
      if (request.method() === 'POST' && new URL(request.url()).pathname === `${DEV}/publish`) {
        publishRequests += 1;
      }
    });
    await publishSheet.getByRole('button', { name: /Publish selected/ }).click();
    await expect(publishSheet.getByRole('alert')).toContainText(
      'Restore drafts must be published exactly as previewed',
    );
    await expectNoFixtureSecret(publishSheet);
    expect(publishRequests, 'client-side overlap refusal must not call publish').toBe(0);

    // Re-stage through SPA navigation, preserving the module-level preview
    // store, then the drawer can select only the newly previewed restore set.
    await page.getByRole('link', { name: /rev \d+ · history/ }).first().click();
    await expectNoFixtureSecret(drawer);
    await openRevision(page, facts.configEdit);
    await drawer.getByRole('button', { name: `Restore ${seed.history.configKey}…` }).click();
    const restagedSheet = page.getByRole('dialog');
    await expectNoFixtureSecret(restagedSheet);
    const rollbackResponse = page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname === `${DEV}/revisions/${String(facts.configEdit)}/rollback` &&
        response.ok(),
    );
    await restagedSheet.getByRole('button', { name: /^Stage the restore from r/ }).click();
    const rollback = zHistoryRollbackResult.parse(await (await rollbackResponse).json());
    await expectNoFixtureSecret(restagedSheet);
    const publishRequest = page.waitForRequest(
      (request) => request.method() === 'POST' && new URL(request.url()).pathname === `${DEV}/publish`,
    );
    await restagedSheet.locator('#history-restore-publish').click();
    const body = zPublishRequest.parse((await publishRequest).postDataJSON());
    expect(body.preview_token).toBe(rollback.preview.token);
    expect([...body.version_ids].sort()).toEqual(
      rollback.changes.map((change) => change.version_id).sort(),
    );
    expect(publishRequests, 'publish-alone action must call publish exactly once').toBe(1);
    await expect(drawer.locator('.notice')).toContainText('Published the restore');
  });

  test('renders secret restore impact status-only and never exposes its value', async ({ page }) => {
    const persistPasskey = await installPasskeyAuthenticator(page);
    try {
      await page.goto(DEV_HISTORY);
      const drawer = page.getByRole('complementary', { name: 'Revision history' });
      await expectNoFixtureSecret(drawer);
      await openRevision(page, facts.tightened);
      await drawer.getByRole('button', { name: `Restore ${seed.history.secretKey}…` }).click();
      const sheet = page.getByRole('dialog');
      await expectNoFixtureSecret(sheet);
      const rollbackResponse = page.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          new URL(response.url()).pathname === `${DEV}/revisions/${String(facts.tightened)}/rollback` &&
          response.ok(),
      );
      await sheet.getByRole('button', { name: /^Stage the restore from r/ }).click();
      await expect(page.getByRole('heading', { name: /restore an earlier revision of/ })).toBeVisible();
      // The ceremony modal enumerates KEYS, never values: assert it on the
      // ceremony state too, or a secret leaking only there would go unnoticed.
      await expectNoFixtureSecret(page.getByRole('dialog', { name: /restore an earlier revision of|pin a historical revision of/ }));
      await page.getByRole('button', { name: 'Use a passkey' }).click();
      const rollback = zHistoryRollbackResult.parse(await (await rollbackResponse).json());

      const impact = sheet.locator('.history__impact');
      const secretImpact = impact.getByRole('listitem').filter({ hasText: seed.history.secretKey });
      await expect(secretImpact.locator('.history__impact-values')).toHaveText(
        'secret — edited, write-presence only',
      );
      await expect(secretImpact.locator('.history__impact-values')).not.toContainText('→');
      await expectNoFixtureSecret(sheet);
      const publishRequest = page.waitForRequest(
        (request) => request.method() === 'POST' && new URL(request.url()).pathname === `${DEV}/publish`,
      );
      await sheet.locator('#history-restore-publish').click();
      const publish = zPublishRequest.parse((await publishRequest).postDataJSON());
      expect(publish.preview_token).toBe(rollback.preview.token);
      await expect(drawer.locator('.notice')).toContainText('Published the restore');

      // Put the live secret back on the seeded r2 material so viewport two can
      // exercise the same r1 impact instead of seeing a no-op restore.
      const liveSecret = seed.history.secretValues.at(-1);
      if (liveSecret === undefined) throw new Error('history fixture has no live secret value');
      const reset = await api(page, 'PUT', `${DEV}/values/${seed.history.secretKey}`, zStaged, {
        value: liveSecret,
      });
      await api(page, 'POST', `${DEV}/publish`, zAny, { version_ids: [reset.version_id] });
    } finally {
      await persistPasskey();
      await refreshSharedSession();
    }
  });

  test('refuses a schema-failing restore loud, naming the key', async ({ page }) => {
    await page.goto(DEV_HISTORY);
    const before = await api(page, 'GET', `${DEV}/revisions`, zRevisions);
    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expectNoFixtureSecret(drawer);
    await openRevision(page, facts.tightened);

    // Only WORKERS is staged, so the failed publish leaves exactly the invalid
    // draft the next viewport's drift repair is specified to supersede.
    await drawer.getByRole('button', { name: `Restore ${seed.history.tightenedKey}…` }).click();
    const sheet = page.getByRole('dialog');
    await expectNoFixtureSecret(sheet);
    const rollbackResponse = page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname === `${DEV}/revisions/${String(facts.tightened)}/rollback` &&
        response.ok(),
    );
    await sheet.getByRole('button', { name: /^Stage the restore from r/ }).click();
    const rollback = zHistoryRollbackResult.parse(await (await rollbackResponse).json());
    const restoredDraft = rollback.changes.find(
      (change) => change.key_id === seed.history.tightenedKeyId,
    );
    const invalidImpact = rollback.preview.environments
      .flatMap((environment) => environment.changes)
      .find((change) => change.key_id === seed.history.tightenedKeyId);
    const restoreEnvironment = rollback.preview.environments.find(
      (environment) => environment.environment_id === seed.history.dev,
    );
    expect(restoredDraft, 'restore must stage the tightened key').toBeDefined();
    expect(restoreEnvironment, 'restore preview must carry the development environment').toBeDefined();
    expect(invalidImpact, 'restore preview must carry the tightened key').toMatchObject({
      classification: 'config',
      operation: 'set',
    });
    expect(invalidImpact?.after, 'older revision must carry the invalid config value').toBeDefined();
    await expect(sheet.locator('.history__impact')).toContainText(seed.history.tightenedKey);
    await expectNoFixtureSecret(sheet);
    await sheet.locator('#history-restore-back').click();

    await expect(
      page.getByRole('button', {
        name: new RegExp(`${seed.history.tightenedKey} in development:.*draft set`),
      }),
    ).toBeVisible();
    await page.getByRole('button', { name: /Review & publish/ }).click();
    const publishSheet = page.getByRole('region', { name: 'Publish drafts' });
    await expectNoFixtureSecret(publishSheet);
    await publishSheet.getByRole('button', { name: /Publish selected/ }).click();
    const refusal = publishSheet.getByRole('alert');
    await expect(refusal).toHaveAttribute('role', 'alert');
    await expect(refusal).toContainText(`value for "${seed.history.tightenedKey}" is invalid (`);
    await expect(page.getByText(/Published atomically/)).toHaveCount(0);
    await expectNoFixtureSecret(publishSheet);

    const pending = await api(page, 'GET', `${DEV}/pending`, zPendingDraftList);
    const pendingRestoredDraft = pending.items.find(
      (draft) => draft.version_id === restoredDraft?.version_id,
    );
    expect(pendingRestoredDraft, 'the refused draft must be the one returned by restore').toMatchObject({
      key_id: seed.history.tightenedKeyId,
      name: seed.history.tightenedKey,
      classification: 'config',
      operation: 'set',
      staged_from_revision: restoreEnvironment?.base_revision,
      revealed: true,
      value: invalidImpact?.after,
    });
    const after = await api(page, 'GET', `${DEV}/revisions`, zRevisions);
    expect(after.items.map((revision) => revision.revision)).toEqual(
      before.items.map((revision) => revision.revision),
    );
  });

  test('shows the behind-latest gap sentence and warning-tier expiry as text', async ({ page }) => {
    await page.goto(DEV_HISTORY);
    const revisions = await api(page, 'GET', `${DEV}/revisions`, zRevisions);
    const pins = await api(page, 'GET', `${DEV}/pins`, zRevisionPinList);
    const latest = revisions.items[0]?.revision;
    const pin = pins.items.find(
      (candidate) => candidate.workload_principal_id === seed.history.pinnedWorkloadPrincipal,
    );
    if (latest === undefined || pin === undefined) throw new Error('pin-gap fixture state is missing');
    const pinnedRevision = Number(pin.revision);
    const behind = revisions.items.filter((revision) => revision.revision > pinnedRevision).length;
    const expiryDays = Math.ceil(
      (new Date(pin.expires_at).getTime() - Date.now()) / (24 * 60 * 60 * 1000),
    );
    expect(behind).toBeGreaterThan(0);
    expect(expiryDays).toBeGreaterThan(7);
    expect(expiryDays).toBeLessThanOrEqual(30);

    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expectNoFixtureSecret(drawer);
    await openRevision(page, pinnedRevision);
    const pinRow = drawer.locator('.history__pin').filter({ hasText: seed.history.pinnedWorkload });
    await expect(pinRow.locator('.history__pin-gap')).toHaveText(
      `${seed.history.pinnedWorkload} still runs on r${String(pinnedRevision)}'s values — ${String(behind)} publishes behind latest (r${String(latest)}). New publishes don't reach it.`,
    );
    await expect(pinRow.locator('.history__expiry--month')).toHaveText(
      `! expires in ${String(expiryDays)} d`,
    );
  });

  test('requires a fresh-session ceremony for a historical move and audits comparison', async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    const persistPasskey = await installPasskeyAuthenticator(page);
    try {
      await context.clearCookies();
      await page.goto(DEV_HISTORY);
      await establishSession(page);
      await page.goto(DEV_HISTORY);
      const advanced = await api(page, 'PUT', `${DEV}/values/${seed.history.configKey}`, zStaged, {
        value: 'current-after-pin-target',
      });
      await api(page, 'POST', `${DEV}/publish`, zAny, { version_ids: [advanced.version_id] });
      await page.reload();
      const revisions = await api(page, 'GET', `${DEV}/revisions`, zRevisions);
      const latest = revisions.items[0]?.revision;
      const pinsBefore = await api(page, 'GET', `${DEV}/pins`, zRevisionPinList);
      const existing = pinsBefore.items.find(
        (pin) => pin.workload_principal_id === seed.history.pinnedWorkloadPrincipal,
      );
      if (latest === undefined || existing === undefined) throw new Error('historical-pin fixture state is missing');
      const drawer = page.getByRole('complementary', { name: 'Revision history' });
      await expectNoFixtureSecret(drawer);
      await openRevision(page, facts.configEdit);
      await drawer.getByRole('button', { name: `Pin r${String(facts.configEdit)}…` }).click();
      const moveSheet = page.getByRole('dialog');
      await expectNoFixtureSecret(moveSheet);
      await moveSheet.getByLabel('Workload').selectOption({
        label: `${seed.history.pinnedWorkload} — pinned to r${String(existing.revision)}`,
      });
      await moveSheet.locator('#history-pin-submit').click();

      // Fresh cookie jar means no sliding reauth window can satisfy this.
      await expect(page.getByRole('heading', { name: /pin a historical revision of/ })).toBeVisible();
      // The ceremony modal enumerates KEYS, never values: assert it on the
      // ceremony state too, or a secret leaking only there would go unnoticed.
      await expectNoFixtureSecret(page.getByRole('dialog', { name: /restore an earlier revision of|pin a historical revision of/ }));
      await page.getByRole('button', { name: 'Use a passkey' }).click();
      await expect(drawer.locator('.notice')).toContainText('Pin reassigned');
      await expectNoFixtureSecret(drawer);
      const pinsAfter = await api(page, 'GET', `${DEV}/pins`, zRevisionPinList);
      const moved = pinsAfter.items.find(
        (pin) => pin.workload_principal_id === seed.history.pinnedWorkloadPrincipal,
      );
      expect(moved?.revision).toBe(BigInt(facts.configEdit));
      expect(moved?.history_authorized).toBe(true);

      // Same purpose-bound session now owns a live window. Comparison may read
      // config plaintext, while secret output remains lineage-only.
      await openRevision(page, facts.configEdit);
      await drawer.getByRole('button', { name: `Pin r${String(facts.configEdit)}…` }).click();
      const compareSheet = page.getByRole('dialog');
      await compareSheet.getByLabel('Workload').selectOption({
        label: `${seed.history.spareWorkload} — follows latest`,
      });
      await expectNoFixtureSecret(compareSheet);
      const trailBeforeComparison = countDisclosureEvents();
      // The comparison is a read-only export: `reveal:false` on the wire, so no
      // secret is ever opened and no disclosure event may be written. Asserting
      // the body AND the trail delta means a regression that started revealing
      // (or a server that started logging config reads as disclosures) fails.
      const exportRequest = page.waitForRequest(
        (request) =>
          request.method() === 'POST' &&
          new URL(request.url()).pathname === `${DEV}/values/export`,
      );
      await compareSheet.locator('#history-pin-compare').click();
      const exportBody = zExportValuesRequest.parse((await exportRequest).postDataJSON());
      expect(exportBody.reveal, 'the comparison must never ask for secret plaintext').not.toBe(true);
      expect(exportBody.revision).toBe(BigInt(facts.configEdit));
      const comparison = compareSheet.locator('#history-pin-compare-results');
      const comparedConfigKeys = [seed.history.configKey, seed.history.tightenedKey];
      await expect(comparison).toContainText(seed.history.configKey);
      await expect(comparison).toContainText(
        `${String(comparedConfigKeys.length - 1)} config key unchanged`,
      );
      await expect(compareSheet).toContainText(
        'Secret lines are write-presence from the lineage, never a value comparison',
      );
      await expect(comparison).toContainText(
        new RegExp(
          `${seed.history.secretKey} (not written|written again) since r${String(facts.configEdit)}`,
        ),
      );
      await expectNoFixtureSecret(compareSheet);
      expect(
        countDisclosureEvents() - trailBeforeComparison,
        'a read-only config comparison opens no secret and therefore writes no disclosure event',
      ).toBe(0);

      // Restore canonical state for the remaining lifecycle test without
      // opening historical material.
      await api(page, 'POST', `${DEV}/pins`, zAny, {
        workload_principal_id: seed.history.pinnedWorkloadPrincipal,
        revision: latest,
        expires_at: new Date(Date.now() + (seed.history.pinExpiryDays * 24 + 12) * 60 * 60 * 1000).toISOString(),
      });
    } finally {
      await persistPasskey();
      await context.close();
    }
  });

  test('keeps the mobile matrix inert and restores drawer focus', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'mobile', 'mobile-only focus contract');
    await page.goto(DEV_HISTORY);
    const drawer = page.getByRole('complementary', { name: 'Revision history' });
    await expectNoFixtureSecret(drawer);
    await expect(page.locator('.matrix[inert]')).toBeVisible();
    await expect(page.locator('#history-title')).toBeFocused();

    const selectedRow = page.locator(`[data-history-revision="${String(facts.current)}"]`);
    await selectedRow.click();
    await expect(page.locator('#history-detail-title')).toBeFocused();
    await expectNoFixtureSecret(drawer);
    await page.locator('#history-detail-back').click();
    await expect(selectedRow).toBeFocused();
    await expectNoFixtureSecret(drawer);
  });

  test('runs renew, schema override, and retention-gated one-click release', async ({ page }) => {
    const persistPasskey = await installPasskeyAuthenticator(page);
    try {
      await page.goto(DEV_HISTORY);
      const revisions = await api(page, 'GET', `${DEV}/revisions`, zRevisions);
      const latest = revisions.items[0]?.revision;
      if (latest === undefined) throw new Error('pin lifecycle has no current revision');
      const drawer = page.getByRole('complementary', { name: 'Revision history' });
      await expectNoFixtureSecret(drawer);
      await openRevision(page, latest);

      await drawer.getByRole('button', { name: `Pin r${String(latest)}…` }).click();
      const pinSheet = page.getByRole('dialog');
      await expectNoFixtureSecret(pinSheet);
      await pinSheet.getByLabel('Workload').selectOption({
        label: `${seed.history.pinnedWorkload} — pinned to r${String(latest)}`,
      });
      const tooFar = new Date(Date.now() + 400 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
      await pinSheet.getByLabel(/Expires on/).fill(tooFar);
      await pinSheet.locator('#history-pin-submit').click();
      await expect(drawer.getByRole('alert')).toContainText('pin expiry exceeds the maximum 365 days');
      await expectNoFixtureSecret(pinSheet);
      const ok = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
      await pinSheet.getByLabel(/Expires on/).fill(ok);
      await pinSheet.locator('#history-pin-submit').click();
      await expect(drawer.locator('.notice')).toContainText('Pin renewed');
      await expectNoFixtureSecret(drawer);

      // Retention read succeeded, so this non-sole current pin releases in one
      // click without a consequence confirmation sheet.
      await expect(drawer.locator('.history__retention')).toContainText('values kept:');
      const renewed = drawer.locator('.history__pin').filter({ hasText: seed.history.pinnedWorkload });
      await renewed.getByRole('button', { name: 'Release' }).click();
      const releaseConfirm = page.locator('#history-release-confirm');
      await expect(releaseConfirm).toHaveCount(0);
      if (await releaseConfirm.isVisible()) {
        await expectNoFixtureSecret(releaseConfirm);
      }
      await expect(drawer.locator('.notice')).toContainText('resumes latest');

      await openRevision(page, facts.tightened);
      await drawer.getByRole('button', { name: `Pin r${String(facts.tightened)}…` }).click();
      const overrideSheet = page.getByRole('dialog');
      await expectNoFixtureSecret(overrideSheet);
      await overrideSheet.getByLabel('Workload').selectOption({
        label: `${seed.history.spareWorkload} — follows latest`,
      });
      await expect(overrideSheet.getByRole('checkbox')).toHaveCount(0);
      await overrideSheet.locator('#history-pin-submit').click();
      await expect(page.getByRole('heading', { name: /pin a historical revision of/ })).toBeVisible();
      // The ceremony modal enumerates KEYS, never values: assert it on the
      // ceremony state too, or a secret leaking only there would go unnoticed.
      await expectNoFixtureSecret(page.getByRole('dialog', { name: /restore an earlier revision of|pin a historical revision of/ }));
      await page.getByRole('button', { name: 'Use a passkey' }).click();
      await expect(drawer.getByRole('alert')).toContainText(seed.history.tightenedKey);
      await expectNoFixtureSecret(overrideSheet);
      const override = overrideSheet.getByRole('checkbox');
      await expect(override).toBeVisible();
      // The override renders only after a refusal, so the pinned sweep over the
      // idle surface never reaches it; the touch floor is asserted here, where
      // it exists (mobile runs the check, desktop is skipped by design).
      await expectTouchTargets(page, [override]);
      await override.check();
      await overrideSheet.locator('#history-pin-submit').click();
      await expect(drawer.locator('.notice')).toContainText('Pin created');
      await expectNoFixtureSecret(drawer);
      const drifted = drawer.locator('.history__pin').filter({ hasText: seed.history.spareWorkload });
      await expect(drifted).toContainText('Δ schema drift');

      // Clean up the override pin when the product classifier exposes it.
      await drifted.getByRole('button', { name: 'Release' }).click();
      await expect(drawer.locator('.notice')).toContainText('resumes latest');
    } finally {
      await persistPasskey();
      await refreshSharedSession();
    }
  });

});
