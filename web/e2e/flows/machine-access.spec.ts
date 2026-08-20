import { expect, test, type BrowserContext, type Page } from '@playwright/test';

import { expectPinnedAssertionSet, expectStatusIsTextAndAria } from '../fixtures/assertions.ts';
import {
  establishSession,
  parseCredential,
  readPasskey,
  readSeed,
  writePasskey,
} from '../fixtures/instance.ts';

/**
 * Flow: machine access (registry surface `machine-access`) — mvp-boundary S3's
 * "all three tabs + row expansion + display-once mint", against the locked
 * prototype #31 iteration 3.
 *
 * What this flow proves, in the ADRs' own terms:
 *
 *  - the inventory is a TABBED one — service accounts, federation, Kubernetes
 *    targets — and each tab renders the state this build actually holds;
 *  - a credential row is METADATA ONLY: prefix hint, kind, expiry in words,
 *    last used, and never a value;
 *  - expanding a service account shows credentials and federated bindings on
 *    the left, delivery targets and actions on the right, and the five-step
 *    setup journey full-width below;
 *  - the mint is DISPLAY-ONCE: the step-up names the post-state formula, the
 *    value appears exactly once, a stored-confirmation checkbox gates dismiss,
 *    and after dismissal the value is nowhere on the page while the new row is;
 *  - a federated binding renders byte-exactly, and the form REFUSES a
 *    pull-request event until it is deliberately bound.
 *
 * The passkey machinery is here for the session, not for the mint: a
 * `manage-members` read of the grant rows is MFA-mandatory, so the surface's
 * scope column needs a stepped-up session to exist at all.
 */

const seed = readSeed();
const PATH = `/orgs/${seed.org}/projects/${seed.project}/machine-access`;

/**
 * installAuthenticator attaches Chromium's virtual authenticator preloaded with
 * the passkey global setup enrolled — never a fresh one. Enrolment is an
 * account-security mutation that deletes every other session the principal
 * holds, so a flow that enrolled would invalidate the suite's shared session.
 */
async function installAuthenticator(page: Page): Promise<() => Promise<void>> {
  const session = await page.context().newCDPSession(page);
  await session.send('WebAuthn.enable');
  const { authenticatorId } = await session.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  await session.send('WebAuthn.addCredential', { authenticatorId, credential: readPasskey() });
  // Hand the ADVANCED signature counter back: the next Playwright project's
  // authenticator must carry on from here or the server sees a clone.
  return async () => {
    const { credentials } = await session.send('WebAuthn.getCredentials', { authenticatorId });
    const advanced: unknown = credentials[0];
    if (advanced !== undefined) {
      writePasskey(parseCredential(advanced));
    }
  };
}

/** accountRow is the disclosure button that expands one service account. */
function accountRow(page: Page, name: string) {
  return page.getByRole('button', { name, exact: false }).first();
}

/**
 * revokeMinted retires everything this flow minted, and it is not tidiness.
 *
 * The instance caps concurrent live credentials per service account at five,
 * and this file mints three times per Playwright project across two viewport
 * projects — so without revoking, the sixth mint is refused by the cap and the
 * failure reads as a broken mint rather than as a test that littered. Revoking
 * is also the second half of the rotation the ADR describes: mint, distribute,
 * then revoke.
 */
async function revokeMinted(page: Page) {
  const expansion = page.locator('.machine__sub');
  const buttons = expansion.getByRole('button', { name: /^Revoke hik_1_wl_/ });
  for (let remaining = await buttons.count(); remaining > 0; remaining--) {
    await buttons.first().click();
    await expect(expansion.locator('.cred')).toHaveCount(remaining - 1);
  }
  await expect(expansion.locator('.cred')).toHaveCount(0);
}

test.describe('machine access', () => {
  test.describe.configure({ mode: 'serial' });

  let context: BrowserContext;
  let page: Page;
  let persistPasskey: () => Promise<void>;

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    page = await context.newPage();
    persistPasskey = await installAuthenticator(page);
  });

  test.afterAll(async () => {
    await persistPasskey();
    await context.close();
  });

  test.beforeEach(async () => {
    await context.clearCookies();
    await page.goto(PATH);
    await establishSession(page);
    await page.goto(PATH);
    await expect(page.getByRole('heading', { name: 'Machine access', level: 1 })).toBeVisible();
  });

  test('the inventory has three tabs, and every one of them says what it holds', async () => {
    const tabs = page.getByRole('tab');
    await expect(tabs).toHaveCount(3);
    await expect(tabs.nth(0)).toHaveText(/Service accounts \(3\)/);
    await expect(tabs.nth(1)).toHaveText(/Federation \(1\)/);
    await expect(tabs.nth(2)).toHaveText(/Kubernetes targets \(0\)/);

    // The policy strip: the per-project opt-in is stated, not offered as a
    // control whose only outcome would be a refusal.
    const policy = page.locator('.machine__policy');
    await expect(policy).toContainText('per-project opt-in): off.');
    await expectStatusIsTextAndAria(page, policy);

    // The inventory itself: every seeded account, with its immutable kind.
    for (const name of [seed.machine.workload, seed.machine.automation, seed.machine.mintable]) {
      await expect(page.getByRole('button', { name, exact: false })).toBeVisible();
    }
    await expect(page.getByRole('row').filter({ hasText: seed.machine.workload })).toContainText(
      'development',
    );
    await expect(page.getByRole('row').filter({ hasText: seed.machine.automation })).toContainText(
      'automation',
    );

    // The federation tab renders the binding BYTE-EXACTLY. Nothing folds case,
    // resolves the URL or strips a slash, so what was seeded is what is here.
    await page.getByRole('tab', { name: 'Federation' }).click();
    await expect(page.getByText(seed.machine.issuer, { exact: true })).toBeVisible();
    await expect(page.getByText(seed.machine.subject, { exact: true })).toBeVisible();
    await expect(page.getByText(seed.machine.audience, { exact: true })).toBeVisible();

    // The Kubernetes tab is EMPTY and says why. An empty list here must not
    // read as "everything is healthy".
    await page.getByRole('tab', { name: 'Kubernetes targets' }).click();
    const empty = page.getByRole('status').filter({ hasText: 'No delivery targets are reported' });
    await expect(empty).toContainText('never that everything is healthy');
    await expectStatusIsTextAndAria(page, empty);
  });

  test('expanding a row shows credentials, bindings, targets and the journey below', async () => {
    const toggle = accountRow(page, seed.machine.workload);
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');

    const expansion = page.locator('.machine__sub');
    await expect(expansion.getByRole('heading', { name: 'Credentials' })).toBeVisible();
    await expect(expansion.getByRole('heading', { name: 'Federated bindings' })).toBeVisible();
    await expect(expansion.getByRole('heading', { name: 'Delivery targets' })).toBeVisible();
    await expect(expansion.getByRole('heading', { name: 'Setup journey' })).toBeVisible();

    // The journey is five steps. With the project's machine-reveal opt-in off
    // (the seeded default) step 4 is the next act and step 5 says the grant
    // API refuses until it is on, in words rather than a dead control.
    const steps = expansion.locator('.journey__step');
    await expect(steps).toHaveCount(5);
    await expect(steps.nth(1)).toContainText(`read granted — development`);
    await expect(steps.nth(3)).toContainText('Enable the project machine-reveal opt-in');
    await expect(steps.nth(3)).toContainText('next');
    await expect(steps.nth(4)).toContainText('refused by the grant API until the opt-in above is on');

    // An automation principal has no journey at all: it never delivers to a
    // workload.
    await toggle.click();
    await accountRow(page, seed.machine.automation).click();
    await expect(page.locator('.machine__sub')).toContainText('has no setup journey');
    await expect(page.locator('.journey__step')).toHaveCount(0);
  });

  test('the mint shows the value exactly once, and the confirmation gates dismiss', async () => {
    await accountRow(page, seed.machine.mintable).click();
    await page
      .getByRole('button', { name: `Mint credential for ${seed.machine.mintable}` })
      .click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('heading', { level: 2 })).toHaveText(
      `mint credential · ${seed.machine.mintable}`,
    );
    // The step-up names the POST-STATE formula, not what the mint adds — and
    // says honestly that this account reaches no plaintext, so nothing is
    // reauthenticated for a disclosure that cannot happen.
    await expect(dialog).toContainText('resulting post-state');
    await expect(dialog).toContainText('reaches no plaintext');

    await dialog.getByRole('button', { name: 'Mint credential' }).click();

    // The value, exactly once, in the credential grammar.
    const token = dialog.locator('.machine__token');
    await expect(token).toHaveText(/^hik_1_wl_/);
    const value = (await token.textContent()) ?? '';
    expect(value.length, 'the minted value').toBeGreaterThan(20);
    await expect(dialog).toContainText('never retrievable again');

    // Dismissal is GATED. Pressing Done without the confirmation refuses, in
    // words, and the value stays on screen rather than being lost.
    await dialog.getByRole('button', { name: 'Done' }).click();
    await expect(dialog.getByRole('alert')).toContainText('there is no second look');
    await expect(token).toBeVisible();

    await dialog.getByRole('checkbox').check();
    await dialog.getByRole('button', { name: 'Done' }).click();
    await expect(dialog).toBeHidden();

    // And it is gone: nothing on this page can return it, which is the whole
    // point of display-once. The row shows the PREFIX HINT instead.
    await expect(page.getByText(value)).toHaveCount(0);
    const expansion = page.locator('.machine__sub');
    await expect(expansion.locator('.cred')).toHaveCount(1);
    await expect(expansion.locator('.cred code')).toHaveText(/^hik_1_wl_.*…$/);
    await expect(expansion.locator('.cred')).toContainText('expires in');
    await expect(expansion.locator('.cred')).toContainText('never used');
    // The row shows a PREFIX, not the value: what is on screen is a strict,
    // short prefix of what was minted and nothing more.
    const hint = ((await expansion.locator('.cred code').textContent()) ?? '').replace('…', '');
    expect(value.startsWith(hint), 'the row shows a prefix of the minted value').toBe(true);
    expect(hint.length, 'the hint is far shorter than the value').toBeLessThan(value.length / 2);

    // Revoking is the other half of rotation, and it bites at the next request
    // rather than at expiry.
    await revokeMinted(page);
    await expect(
      page.getByRole('status').filter({ hasText: 'stops authenticating at the next request' }),
    ).toBeVisible();
  });

  test('escape does not throw away a value nothing can return', async () => {
    await accountRow(page, seed.machine.mintable).click();
    await page
      .getByRole('button', { name: `Mint credential for ${seed.machine.mintable}` })
      .click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Mint credential' }).click();
    await expect(dialog.locator('.machine__token')).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('alert')).toContainText('there is no second look');

    await dialog.getByRole('checkbox').check();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await revokeMinted(page);
  });

  test('escape while the mint is in flight does not unmount the value', async () => {
    // The window this closes: Escape reaches a native <dialog> even when Cancel
    // is disabled, so a dismissal mid-flight would unmount the component the
    // server is about to hand a credential to — losing a value nothing can
    // return while leaving a live credential behind.
    //
    // The mint is delayed rather than stubbed: the request, the commit and the
    // response are all real, only slower, so what is asserted is the real
    // ordering rather than a fixture's.
    await page.route('**/service-accounts/*/credentials', async (route) => {
      if (route.request().method() !== 'POST') {
        await route.fallback();
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      await route.continue();
    });
    try {
      await accountRow(page, seed.machine.mintable).click();
      await page
        .getByRole('button', { name: `Mint credential for ${seed.machine.mintable}` })
        .click();
      const dialog = page.getByRole('dialog');
      await dialog.getByRole('button', { name: 'Mint credential' }).click();
      await expect(dialog.getByRole('button', { name: 'Minting…' })).toBeVisible();

      await page.keyboard.press('Escape');
      await expect(dialog).toBeVisible();

      // And the value still arrives, at the component that is still there.
      await expect(dialog.locator('.machine__token')).toHaveText(/^hik_1_wl_/, { timeout: 10_000 });
    } finally {
      await page.unroute('**/service-accounts/*/credentials');
    }

    const dialog = page.getByRole('dialog');
    await dialog.getByRole('checkbox').check();
    await dialog.getByRole('button', { name: 'Done' }).click();
    await expect(dialog).toBeHidden();
    await revokeMinted(page);
  });

  test('browser Back is a dismissal attempt, not a way to lose the value', async () => {
    // Escape goes through the dialog's own cancel event; Back pops the ROUTE,
    // which would unmount the component and everything it holds. The guard
    // turns the pop into the same gated dismissal attempt: mid-flight it is
    // ignored, with an unstored value it holds back, and the URL never moves.
    await page.route('**/service-accounts/*/credentials', async (route) => {
      if (route.request().method() !== 'POST') {
        await route.fallback();
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      await route.continue();
    });
    try {
      await accountRow(page, seed.machine.mintable).click();
      await page
        .getByRole('button', { name: `Mint credential for ${seed.machine.mintable}` })
        .click();
      const dialog = page.getByRole('dialog');
      await dialog.getByRole('button', { name: 'Mint credential' }).click();
      await expect(dialog.getByRole('button', { name: 'Minting…' })).toBeVisible();

      // Back mid-flight: ignored, the mint completes where it started.
      await page.goBack();
      await expect(dialog).toBeVisible();
      await expect(dialog.locator('.machine__token')).toHaveText(/^hik_1_wl_/, { timeout: 10_000 });
      expect(new URL(page.url()).pathname).toBe(PATH);

      // Back with the unstored value on screen: held back, in words.
      await page.goBack();
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole('alert')).toContainText('there is no second look');
      expect(new URL(page.url()).pathname).toBe(PATH);

      await dialog.getByRole('checkbox').check();
      await dialog.getByRole('button', { name: 'Done' }).click();
      await expect(dialog).toBeHidden();
    } finally {
      await page.unroute('**/service-accounts/*/credentials');
    }
    await revokeMinted(page);
  });

  test('the binding form refuses a pull-request event until it is deliberately bound', async () => {
    await page.getByRole('tab', { name: 'Federation' }).click();
    await page.getByRole('button', { name: 'New binding' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    // The Kubernetes preset fills the byte-exact issuer and the UID pin the
    // server refuses a binding without.
    await expect(dialog.getByLabel('Issuer')).toHaveValue(seed.machine.issuer);
    await expect(dialog.getByLabel(/ServiceAccount UID/)).toBeVisible();

    // A binding expires on the same terms as a bearer credential, and the
    // indefinite option is present-and-disabled with its reason rather than
    // absent — the instance opt-in that admits it is off by default.
    const lifetime = dialog.getByLabel('Binding lifetime');
    await expect(lifetime).toHaveValue('default');
    await expect(lifetime.getByRole('option', { name: /Indefinite/ })).toBeDisabled();
    await lifetime.selectOption('90d');

    await dialog.getByRole('button', { name: 'GitHub Actions' }).click();
    await expect(dialog.getByLabel(/Repository id/)).toBeVisible();
    // `push` is not a refusal.
    await expect(dialog.getByRole('alert')).toHaveCount(0);

    // A numeric pin is refused BEFORE the request when it is not a whole number
    // the issuer could have minted: an empty field would bind repository 0, and
    // anything past 2^53 rounds to a neighbouring repository id.
    await dialog.getByLabel(/Repository id \(repository_id\)/).fill('4242.7');
    await dialog.getByLabel(/Repository owner id/).fill('99');
    await dialog.getByLabel('Audience').fill(seed.machine.audience);
    await dialog.getByRole('button', { name: 'Bind this identity' }).click();
    await expect(dialog.getByRole('alert')).toContainText('must be a whole number');
    await dialog.getByLabel(/Repository id \(repository_id\)/).fill('4242');

    // The audience is mandatory, and refused here rather than as a 400.
    await dialog.getByLabel('Audience').fill('');
    await dialog.getByRole('button', { name: 'Bind this identity' }).click();
    await expect(dialog.getByRole('alert')).toContainText('An audience is mandatory');
    await dialog.getByLabel('Audience').fill(seed.machine.audience);

    await dialog.getByLabel('Event name').selectOption('pull_request_target');
    const refusal = dialog.getByRole('alert');
    await expect(refusal).toContainText('pull_request_target');
    await expect(refusal).toContainText("this service account's fetch authority");
    await expectStatusIsTextAndAria(page, refusal.first());

    // The refusal HOLDS: pressing bind without the acknowledgement is refused
    // by the surface, before the server is asked anything.
    await dialog.getByRole('button', { name: 'Bind this identity' }).click();
    await expect(dialog).toContainText('Acknowledge deliberately below');

    // And the acknowledgement is a deliberate act, not a default.
    const deliberate = dialog.getByRole('checkbox');
    await expect(deliberate).not.toBeChecked();
    await deliberate.check();
    await expect(deliberate).toBeChecked();

    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
  });

  test('the grant warning names the live credentials and the newly reachable keys', async () => {
    await accountRow(page, seed.machine.workload).click();
    await page
      .getByRole('button', { name: `Add environment grant to ${seed.machine.workload}` })
      .click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('Grants attach to the service account, never to a credential');
    // The two numbers nothing else on the surface says: how many credentials
    // this re-scopes, and exactly what becomes reachable. The count is the
    // SERVER's `live_credentials`, so an expired credential is not counted as
    // one this grant re-scopes.
    await expect(dialog).toContainText('re-scopes every credential already in circulation');
    await expect(dialog).toContainText('1 live credential');

    // The formula, and the honest statement that its disclosure conjunct is
    // vacuous here — the same sentence the mint makes, for the same reason.
    await expect(dialog).toContainText('the delta, not the whole post-state');
    await expect(dialog).toContainText('newly decrypts nothing');

    // What a `read` grant actually delivers: the whole key catalogue by name,
    // classification and presence — config keys included, unset keys included
    // — and no value of any classification.
    const keys = dialog.getByRole('list', { name: 'Keys this grant makes reachable' });
    for (const key of [...seed.secrets, seed.config]) {
      await expect(keys).toContainText(key);
    }
    await expect(keys).toContainText('config');
    await expect(keys).toContainText('secret');
    await expect(dialog).toContainText('No value of any classification is delivered');

    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
  });

  for (const scheme of ['dark', 'light'] as const) {
    test(`meets the pinned assertion set on the inventory (${scheme})`, async () => {
      await page.emulateMedia({ colorScheme: scheme });
      try {
        await page.reload();
        await expect(page.getByRole('heading', { name: 'Machine access', level: 1 })).toBeVisible();
        // Expanded, because the expansion is most of this surface: the
        // credential rows, the binding card and the journey rail are all only
        // reachable through it.
        await accountRow(page, seed.machine.workload).click();

        const heading = page.getByRole('heading', { name: 'Machine access', level: 1 });
        const well = page.locator('.card');
        const badge = page.locator('.badge').first();
        const mint = page.getByRole('button', {
          name: `Mint credential for ${seed.machine.workload}`,
        });

        await expectPinnedAssertionSet(page, {
          flow: 'machine-access',
          surface: 'machine-access',
          theme: scheme,
          text: [heading, page.locator('.machine__policy'), page.locator('.journey__step').first()],
          radii: [
            [well, 'container'],
            [mint, 'control'],
            [badge, 'badge'],
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
          density: [[mint, '--touch']],
        });
      } finally {
        await page.emulateMedia({ colorScheme: null });
      }
    });
  }

  test('meets the pinned assertion set with the display-once value on screen', async () => {
    // The mint dialog is the component this ticket exists for, and it is the
    // only place in the SPA a credential value is ever rendered. Asserting only
    // the resting surface would leave it, its confirmation checkbox and its
    // refusal unchecked.
    await accountRow(page, seed.machine.mintable).click();
    await page
      .getByRole('button', { name: `Mint credential for ${seed.machine.mintable}` })
      .click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Mint credential' }).click();
    await expect(dialog.locator('.machine__token')).toBeVisible();

    await expectPinnedAssertionSet(page, {
      flow: 'machine-access',
      surface: 'machine-access',
      theme: 'dark',
      text: [dialog.getByRole('heading', { level: 2 }), dialog.locator('.machine__token')],
      radii: [
        [dialog, 'container'],
        [dialog.locator('.machine__token'), 'control'],
      ],
      fonts: [[dialog.locator('.machine__token'), 'mono']],
      colours: [[dialog, 'backgroundColor', '--bg-raise']],
      hairlines: [dialog],
      density: [[dialog.getByRole('button', { name: 'Done' }), '--touch']],
    });

    await dialog.getByRole('checkbox').check();
    await dialog.getByRole('button', { name: 'Done' }).click();
    await expect(dialog).toBeHidden();
    await revokeMinted(page);
  });
});
