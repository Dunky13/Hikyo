import { defineConfig, devices } from '@playwright/test';

import { BASE_URL } from './e2e/fixtures/instance.ts';

/**
 * The flow suite (mvp-boundary S3).
 *
 * Two projects, one browser. Desktop and mobile are the two shapes the locked
 * design has to work in — DESIGN.md is mobile-first and the matrix "earns
 * phone screens" — so a flow that only passes at 1280px has not passed.
 *
 * Chromium only, and that is a decision rather than an omission: the pinned
 * assertion set needs `forced-colors` emulation and axe-core's colour
 * sampling, and Chromium is where both are reliable. Cross-browser rendering
 * is a different question from "is this surface accessible and on-token".
 */
export default defineConfig({
  testDir: './e2e/flows',
  outputDir: './test-results',
  fullyParallel: false,
  forbidOnly: process.env['CI'] !== undefined,
  retries: 0,
  workers: 1,
  reporter: process.env['CI'] !== undefined ? [['github'], ['list']] : [['list']],
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    // Colour scheme is emulated per assertion, not fixed here. Chromium never
    // reports `no-preference` — the CSS keyword exists, the platform signal
    // does not — so "dark unless the platform asks for light" is proven by
    // emulating each preference in turn rather than by picking one globally.
  },
  projects: [
    {
      name: 'desktop',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } },
    },
    {
      name: 'mobile',
      // A real phone shape with touch and a device pixel ratio, because the
      // 44px target assertion is meaningless at a desktop viewport.
      use: { ...devices['Pixel 5'] },
    },
  ],
});
