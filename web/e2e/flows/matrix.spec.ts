import { expect, test } from '@playwright/test';

import {
  expectPinnedAssertionSet,
  expectStatusIsTextAndAria,
} from '../fixtures/assertions.ts';
import {
  installPasskeyAuthenticator,
  readSeed,
  refreshSharedSession,
  STORAGE_STATE,
} from '../fixtures/instance.ts';
import { surfacesForFlow } from '../registry.ts';

/**
 * Flow: whole-project environment matrix (registry surface `matrix`).
 *
 * Each project first stages clean development and unsafe production drafts,
 * proves selective publish, then repairs production through its protected
 * ceremony. The copy leg proves the same protected guard and secret routing.
 * Mobile narrows to the acceptance viewport, 375px, before its final edit.
 */

const seed = readSeed();
const MATRIX_PATH = `/orgs/${seed.org}/projects/${seed.project}/matrix`;
const SCHEMES: readonly ('dark' | 'light')[] = ['dark', 'light'];

test.describe('environment matrix', () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ storageState: STORAGE_STATE });

  test.beforeEach(async ({ page }) => {
    await page.goto(MATRIX_PATH);
    await expect(page.getByRole('heading', { name: 'Environment matrix', level: 1 })).toBeVisible();
    await expect(page.getByRole('button', { name: /LOG_LEVEL in development:/ })).toBeVisible();
  });

  test('keeps problems visible and publishes only selected clean environments', async ({ page }, testInfo) => {
    const persistPasskey = await installPasskeyAuthenticator(page);
    try {
      await page.getByRole('button', { name: /LOG_LEVEL in development:/ }).click();
      await page.getByRole('dialog').getByLabel('development value').fill(`selective-${testInfo.project.name}`);
      await page.getByRole('dialog').getByRole('button', { name: 'Save 1 draft' }).click();

      await page.getByRole('button', { name: new RegExp(`${seed.matrixRequired} in production:`) }).click();
      await page.getByRole('dialog').getByRole('button', { name: 'Clear production to absent' }).click();
      await page.getByRole('dialog').getByRole('button', { name: 'Save 1 draft' }).click();
      await expect(page.locator('.notice')).toContainText(`1 draft updated for ${seed.matrixRequired}`);

      await page.getByRole('button', { name: /Review & publish/ }).click();
      const publishSheet = page.getByRole('region', { name: 'Publish drafts' });
      const development = publishSheet.getByRole('checkbox', { name: /development/ });
      const production = publishSheet.getByRole('checkbox', { name: /production/ });
      const publish = publishSheet.getByRole('button', { name: /Publish selected/ });
      await expect(development).toBeChecked();
      await expect(publishSheet).toContainText(`selective-${testInfo.project.name}`);
      await expect(production).not.toBeChecked();
      await expect(production).toBeDisabled();
      await expect(publish).toBeEnabled();
      await expect(publishSheet.getByRole('alert')).toContainText(
        `Publish blocked: ${seed.matrixRequired} in production`,
      );

      await page.getByRole('button', { name: /Problems/ }).click();
      const bar = page.locator('.matrix__filter');
      await expectStatusIsTextAndAria(page, bar);
      await expect(bar).toContainText('filter active: problems');
      await expect(bar).toContainText('showing 1 of 5 keys');

      await expect(page.getByRole('rowheader', { name: new RegExp(seed.matrixRequired) })).toBeVisible();
      await expect(page.getByRole('rowheader', { name: /LOG_LEVEL/ })).toHaveCount(0);

      const hiddenApp = page.locator('.matrix__group-link[title="hidden by the problems filter"]', {
        hasText: 'app/',
      });
      await expect(hiddenApp).toBeDisabled();
      await expect(hiddenApp).toHaveAttribute('title', 'hidden by the problems filter');

      await page.locator('.matrix__group-link', { hasText: 'ops/' }).click();
      await expect(bar).toBeVisible();
      await expect(bar).toContainText('filter active: problems');

      await page.getByRole('button', { name: '✕ show all keys' }).click();
      await expect(page.getByRole('rowheader', { name: /LOG_LEVEL/ })).toBeVisible();

      await publish.click();
      await expect(page.locator('.notice')).toContainText('Published atomically: development');

      await page.getByRole('button', { name: new RegExp(`${seed.matrixRequired} in production:`) }).click();
      const editor = page.getByRole('dialog');
      await editor.getByLabel('production value').fill(`required-${testInfo.project.name}`);
      await editor.getByRole('button', { name: 'Save 1 draft' }).click();

      await page.getByRole('button', { name: /Review & publish/ }).click();
      const repairedSheet = page.getByRole('region', { name: 'Publish drafts' });
      await expect(repairedSheet.getByText('PROTECTED — confirms before publish')).toBeVisible();
      const protectedConfirmation = repairedSheet.getByRole('checkbox', {
        name: 'I confirm publishing to protected production.',
      });
      const protectedPublish = repairedSheet.getByRole('button', { name: /Publish selected/ });
      await expect(protectedPublish).toBeDisabled();
      await protectedConfirmation.check();
      await protectedPublish.click();
      await expect(page.getByRole('heading', { name: 'publish into · production' })).toBeVisible();
      await expect(page.getByRole('list', { name: 'Keys this decision covers' })).toContainText(
        seed.matrixRequired,
      );
      await page.getByRole('button', { name: 'Use a passkey' }).click();
      await expect(page.locator('.notice')).toContainText('Published atomically: production');
    } finally {
      await persistPasskey();
      await refreshSharedSession();
    }
  });

  test('uses environment visibility and collapsible-group density valves', async ({ page }) => {
    const chooser = page.locator('.matrix__environment-picker');
    await chooser.locator('summary').click();
    await chooser.getByText('production', { exact: true }).click();
    await expect(chooser.locator('summary')).toContainText('Environments 1/2');
    await expect(page.getByRole('columnheader', { name: 'production' })).toHaveCount(0);
    await expect(chooser.getByRole('checkbox', { name: 'development' })).toBeDisabled();

    await chooser.getByText('production', { exact: true }).click();
    await expect(chooser.locator('summary')).toContainText('Environments 2/2');
    await chooser.locator('summary').click();

    const group = page.locator('.matrix__group-row button', { hasText: 'app' });
    await group.click();
    await expect(group).toHaveAttribute('aria-expanded', 'false');
    await expect(group).toContainText('LOG_LEVEL');
    await group.click();
    await expect(group).toHaveAttribute('aria-expanded', 'true');
  });

  test('confirms protected config copy and routes secret work to Values', async ({ page }) => {
    const persistPasskey = await installPasskeyAuthenticator(page);
    try {
      await page
        .getByRole('button', { name: new RegExp(`${seed.config} in development:`) })
        .click();
      const editor = page.getByRole('dialog');
      await editor.getByRole('button', { name: 'Copy published development value to…' }).click();
      await editor.getByRole('checkbox', { name: 'production · protected' }).check();

      const copy = editor.getByRole('button', { name: 'Copy to 1 environment' });
      await expect(copy).toBeDisabled();
      await editor
        .getByRole('checkbox', { name: 'I confirm copying into protected production.' })
        .check();
      await expect(copy).toBeEnabled();
      await copy.click();
      await expect(
        page.getByRole('heading', { name: 'publish into · production' }),
      ).toBeVisible();
      await expect(page.getByRole('list', { name: 'Keys this decision covers' })).toContainText(
        seed.config,
      );
      await page.getByRole('button', { name: 'Use a passkey' }).click();
      await expect(page.locator('.notice')).toContainText(
        `${seed.config} copied to 1 environment`,
      );

      const secret = seed.secrets[0] ?? '';
      await page
        .getByRole('button', { name: new RegExp(`${secret} in development:`) })
        .click();
      await expect(
        page.getByRole('dialog').getByRole('link', { name: 'Open Values' }),
      ).toHaveAttribute(
        'href',
        `/orgs/${seed.org}/projects/${seed.project}/environments/${seed.dev}/values`,
      );
    } finally {
      await persistPasskey();
      await refreshSharedSession();
    }
  });

  test('edits and publishes from the matrix at desktop and 375px mobile', async ({ page }, testInfo) => {
    const persistPasskey = await installPasskeyAuthenticator(page);
    try {
      if (testInfo.project.name === 'mobile') {
        await page.setViewportSize({ width: 375, height: 812 });
      }

      await page.getByRole('button', { name: /^LOG_LEVEL in development:/ }).click();
      const editor = page.getByRole('dialog');
      await expect(editor).toBeVisible();
      await expect(editor).toContainText('Updated by');
      await expect(editor).toContainText('Revision');
      await expect(editor.getByText('PROTECTED', { exact: true })).toBeVisible();
      const firstEditorRow = editor.locator('.matrix-row-editor__row').first();
      await expectPinnedAssertionSet(page, {
        flow: 'matrix',
        surface: 'matrix',
        theme: `${testInfo.project.name}-row-editor`,
        text: [editor.getByRole('heading', { name: 'LOG_LEVEL' }), firstEditorRow],
        radii: [
          [editor, 'container'],
          [firstEditorRow, 'control'],
          [editor.getByLabel('development value'), 'control'],
        ],
        fonts: [
          [editor.getByRole('heading', { name: 'LOG_LEVEL' }), 'mono'],
          [editor.getByLabel('development value'), 'mono'],
        ],
        colours: [
          [editor.getByRole('heading', { name: 'LOG_LEVEL' }), 'color', '--tx'],
          [firstEditorRow, 'borderTopColor', '--line'],
        ],
        hairlines: [firstEditorRow],
        density: [[editor.getByRole('button', { name: 'Close row editor' }), '--touch']],
      });

      const value = `matrix-${testInfo.project.name}`;
      await editor.getByLabel('Fill all environments').fill(`  ${value}  `);
      await editor.getByRole('button', { name: 'Fill all', exact: true }).click();
      await expect(editor.getByLabel('development value')).toHaveValue(`  ${value}  `);
      await editor.getByLabel('production value').fill(`\t${value}-production `);
      if (testInfo.project.name === 'mobile') {
        const box = await editor.boundingBox();
        expect(box).not.toBeNull();
        expect(Math.abs((box?.y ?? 0) + (box?.height ?? 0) / 2 - 812 / 2)).toBeLessThan(8);
        expect(
          await editor.evaluate((element) =>
            Number.parseFloat(getComputedStyle(element).borderBottomLeftRadius),
          ),
        ).toBeGreaterThan(0);
      }
      await editor.getByRole('button', { name: 'Save 2 drafts' }).click();
      await expect(page.locator('.notice')).toContainText('2 drafts updated for LOG_LEVEL');
      await expect(page.locator('.notice')).toContainText('whitespace was removed from 2 values');
      await expect(page.getByRole('button', { name: /LOG_LEVEL in development:.*draft set/ })).toBeVisible();

      await page.getByRole('button', { name: /^LOG_LEVEL in development:/ }).click();
      const reopened = page.getByRole('dialog');
      await expect(reopened.getByLabel('development value')).toHaveValue(value);
      await expect(reopened.getByLabel('production value')).toHaveValue(`${value}-production`);
      await reopened.getByRole('button', { name: 'Close row editor' }).click();

      await page.reload();

      const review = page.getByRole('button', { name: /Review & publish/ });
      await review.click();
      const publishSheet = page.getByRole('region', { name: 'Publish drafts' });
      await expect(publishSheet).toContainText(value);
      await expect(publishSheet).toContainText(`${value}-production`);
      const atomicPublish = publishSheet.getByRole('button', { name: /Publish selected/ });
      await expect(atomicPublish).toBeDisabled();
      await publishSheet.getByRole('checkbox', {
        name: 'I confirm publishing to protected production.',
      }).check();
      await atomicPublish.click();
      await expect(page.getByRole('heading', { name: 'publish into · production' })).toBeVisible();
      await page.getByRole('button', { name: 'Use a passkey' }).click();
      await expect(page.locator('.notice')).toContainText(/Published atomically: .*Signals updated/);
      await expect(page.getByRole('button', { name: /LOG_LEVEL in development:/ })).not.toHaveAccessibleName(/draft set/);
      await expect(page.getByRole('button', { name: /LOG_LEVEL in development:/ })).toContainText('changed in r');
    } finally {
      await persistPasskey();
      await refreshSharedSession();
    }
  });

  for (const surface of surfacesForFlow('matrix')) {
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
          flow: 'matrix',
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
