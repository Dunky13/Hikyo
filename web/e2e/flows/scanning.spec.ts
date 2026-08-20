import { expect, test } from '@playwright/test';
import { z } from 'zod';

import { expectPinnedAssertionSet } from '../fixtures/assertions.ts';
import { browserApi, readSeed, STORAGE_STATE } from '../fixtures/instance.ts';
import { surfacesForFlow } from '../registry.ts';

/**
 * Flow: secret-scanning Surface-1 warn dialog on the matrix editing surface
 * (#74, SS2/SS4 [UI]; secret-scanning ADR §§2,4).
 *
 * A config-classified value carrying a credential-shaped string SAVES — the
 * warn never blocks — and the redacted finding rides back into a dialog naming
 * the rule and the key, never the matched text. The two named resolutions are
 * exercised: keep-as-config (a sticky dismissal the identical value no longer
 * trips, while a distinct offending value still does) and reclassify-as-secret
 * (routing the key through secret handling). SS4's non-disclosure invariant is
 * asserted where it is easiest to violate: the planted canary reaches neither
 * the dialog DOM nor the browser console.
 *
 * The canaries are AWS's own documented EXAMPLE access-key ids — syntactically
 * valid, matched by the `aws-access-token` rule, and non-live by construction.
 */

const seed = readSeed();
const MATRIX_PATH = `/orgs/${seed.org}/projects/${seed.project}/matrix`;
const SCHEMES: readonly ('dark' | 'light')[] = ['dark', 'light'];

// Two distinct, syntactically valid, non-live AWS access-key ids.
const CANARY = 'AKIAIOSFODNN7EXAMPLE';
const DISTINCT = 'AKIAI44QH8DHBEXAMPLE';

const zCreatedKey = z.object({ id: z.string() });

test.describe('secret scanning warn dialog', () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ storageState: STORAGE_STATE });

  test('warns, dismisses stickily, re-fires, and reclassifies (SS2/SS4 [UI])', async ({
    page,
  }, testInfo) => {
    // A fresh config key per viewport project: the two projects share one
    // instance, and reclassifying a seeded key to secret would break the
    // sibling matrix flow. The name matches the KeyName grammar (^[A-Z_]…).
    const keyName = `SCAN_${testInfo.project.name.toUpperCase()}`;

    // Capture the console BEFORE anything navigates, so the SS4 sweep sees every
    // message the save could have logged.
    const consoleLines: string[] = [];
    page.on('console', (message) => consoleLines.push(message.text()));
    page.on('pageerror', (error) => consoleLines.push(String(error)));

    await page.goto(MATRIX_PATH);
    await expect(page.getByRole('heading', { name: 'Environment matrix', level: 1 })).toBeVisible();

    // The matrix has no create-key control; a surface's fixture work goes
    // through the page's own session (browserApi), exactly as other flows do.
    await browserApi(
      page,
      'POST',
      `/api/v1/orgs/${seed.org}/projects/${seed.project}/keys`,
      zCreatedKey,
      { name: keyName, classification: 'config', declaration: { rule: { type: 'string' } } },
    );
    await page.reload();
    const cell = page.getByRole('button', { name: new RegExp(`${keyName} in development:`) });
    await expect(cell).toBeVisible();

    const warn = page.locator('dialog.scan-warn');

    // --- SS2: plant the credential; the save succeeds and the warn fires -----
    await plantValue(page, cell, CANARY);

    await expect(
      warn.getByRole('heading', { name: 'Possible secret in a config value' }),
    ).toBeVisible();
    // The finding names its rule and offers both first-class resolutions.
    await expect(warn.getByText('aws-access-token')).toBeVisible();
    await expect(
      warn.getByRole('button', { name: `Reclassify ${keyName} as secret` }),
    ).toBeVisible();
    await expect(warn.getByRole('button', { name: 'Keep as config' })).toBeVisible();
    // No blanket ignore-all input exists on the dialog (ADR §4).
    await expect(warn.getByRole('button', { name: /ignore all/i })).toHaveCount(0);

    // --- SS4 [UI]: the canary is nowhere in the dialog, nowhere in the console
    await expect(warn).not.toContainText(CANARY);
    expect(consoleLines.filter((line) => line.includes(CANARY))).toEqual([]);

    // --- SS2: keep-as-config is the sticky dismissal. It re-submits the
    // identical value with the finding's token; the server re-scans that exact
    // value under the fresh dismissal and returns no finding, so the dialog
    // closes. The dialog closing IS "the identical value no longer warns",
    // proven through the real dismissal path rather than a second editor round.
    await warn.getByRole('button', { name: 'Keep as config' }).click();
    await expect(warn).toHaveCount(0);
    // Let the dismissal's re-save cascade (values/signals/pending) settle before
    // reopening the editor: the dev cell now carries a staged draft.
    await expect(cell).toHaveAccessibleName(/draft set/);

    // --- SS2: a distinct offending value re-fires -----------------------------
    await plantValue(page, cell, DISTINCT);
    await expect(
      warn.getByRole('heading', { name: 'Possible secret in a config value' }),
    ).toBeVisible();

    // --- SS2: reclassify-as-secret completes ----------------------------------
    await warn.getByRole('button', { name: `Reclassify ${keyName} as secret` }).click();
    await expect(warn).toHaveCount(0);
    // The key is now secret: the matrix re-fetches and the key row shows the
    // lock. That is reclassification completing, observed end to end.
    await expect(page.locator('.matrix__key').filter({ hasText: keyName })).toContainText('🔒');
  });

  for (const surface of surfacesForFlow('scanning')) {
    for (const scheme of SCHEMES) {
      test(`meets the pinned assertion set on ${surface.label} (${scheme})`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        await page.goto(MATRIX_PATH);

        const heading = page.getByRole('heading', { name: 'Environment matrix', level: 1 });
        const layout = page.locator('.matrix__layout');
        const groups = page.locator('.matrix__groups');
        const chooser = page.locator('.matrix__environment-picker summary');
        const key = page.locator('.matrix__key').first();
        const cell = page.locator('.matrix-cell').first();

        await expectPinnedAssertionSet(page, {
          flow: 'scanning',
          surface: surface.id,
          theme: scheme,
          text: [heading, key, cell],
          radii: [
            [layout, 'container'],
            [chooser, 'control'],
            [cell, 'pill'],
          ],
          fonts: [
            [heading, 'ui'],
            [key, 'mono'],
            [cell, 'mono'],
          ],
          colours: [
            [heading, 'color', '--tx'],
            [groups, 'backgroundColor', '--bg-raise'],
            [layout, 'borderTopColor', '--line'],
          ],
          hairlines: [layout],
          density: [[chooser, '--touch']],
        });
      });
    }
  }
});

/** plantValue opens the row editor, stages one development value, and saves. */
async function plantValue(
  page: import('@playwright/test').Page,
  cell: import('@playwright/test').Locator,
  value: string,
): Promise<void> {
  await cell.click();
  const editor = page.locator('dialog.matrix-row-editor');
  await expect(editor).toBeVisible();
  await editor.getByLabel('development value').fill(value);
  const save = editor.getByRole('button', { name: /^Save \d+ draft/ });
  await expect(save).toBeEnabled();
  await save.click();
  // A successful save closes the editor (its findings, if any, open the warn).
  await expect(editor).toHaveCount(0);
}
