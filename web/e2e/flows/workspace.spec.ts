import { expect, test, type Page } from '@playwright/test';

import { expectPinnedAssertionSet, expectStatusIsTextAndAria } from '../fixtures/assertions.ts';
import { ADMIN, BASE_URL, BASE_URL_B, HOST_B, REMOTE_NAME, STORAGE_STATE } from '../fixtures/instance.ts';
import { surfacesForFlow } from '../registry.ts';

/**
 * Flow: the multi-instance surfaces (registry surfaces `remotes`,
 * `workspace-approve`, `workspace-callback`).
 *
 * This is M6's [UI] deliverable — "workspace popup ceremony + kill switch" —
 * and it runs against TWO REAL INSTANCES on two loopback origins, not against a
 * mock. What it proves, in the order it proves it:
 *
 *   1. The directory card renders a real entry, its state, and the last-known
 *      listing it holds.
 *   2. The serving instance's administrator allowlists the viewing origin
 *      THROUGH THE UI — the consent surface, exercised rather than seeded.
 *   3. "Open workspace" opens a popup ON THE REMOTE'S ORIGIN, the human
 *      authorizes there, the code returns through this origin's own callback
 *      page over a BroadcastChannel, and the shell redeems it cross-origin.
 *      There is no server in the middle at any point.
 *   4. Removing the allowlist entry kills the workspace, and the shell says so.
 *   5. Revoking the session in the remote's own active-session list kills it
 *      the same way — criterion 5, seen from the browser.
 *
 * The two instances differ by HOSTNAME (A is `localhost`, B is `127.0.0.1`)
 * and not only by port, because cookies are not partitioned by port: one
 * hostname would mean one cookie jar and B's session would destroy A's. A
 * takes the NAME because a WebAuthn relying-party id must be a registrable
 * domain and an IP literal is not one, so the passkey ceremonies have to run
 * there.
 */

const VIEWING_ORIGIN = BASE_URL;

/** onB opens a page against the serving instance in the same context. */
async function onB(page: Page, path: string): Promise<void> {
  await page.goto(BASE_URL_B + path);
}

/** card is the directory card for the seeded remote entry. */
function card(page: Page) {
  return page.locator('.remote').filter({ hasText: REMOTE_NAME });
}

test.describe('multi-instance', () => {
  test.use({ storageState: STORAGE_STATE });

  test('the directory card carries state, identity and the last-known listing', async ({ page }) => {
    await page.goto('/remotes');
    const entry = card(page);
    await expect(entry).toBeVisible();
    await expect(entry).toContainText(BASE_URL_B);

    // The state is a SENTENCE, announced, never a colour. The entry is
    // deliberately unreachable over plaintext — the server refuses to fetch a
    // remote URL that is not https — so the card is in exactly the state the
    // ADR names: last known, with its age.
    await expectStatusIsTextAndAria(page, entry.getByRole('status').first());
    await expect(entry).toContainText('Showing the last known directory');

    // The last-known listing came from a real authenticated directory fetch of
    // the other instance, so its identity is present and is not this
    // instance's own.
    await expect(entry.getByText('Identity')).toBeVisible();
    await expect(entry).not.toContainText('not yet observed');
  });

  test('the popup ceremony opens a workspace, and both kill switches close it', async ({
    page,
    context,
  }) => {
    // --- consent, through the serving instance's own UI ---------------------
    const b = await context.newPage();
    await onB(b, '/remotes');
    await b.getByRole('textbox', { name: 'Origin' }).fill(VIEWING_ORIGIN);
    await b.getByRole('button', { name: 'Allow origin' }).click();
    await expect(b.getByText(VIEWING_ORIGIN, { exact: true })).toBeVisible();

    // --- the ceremony -------------------------------------------------------
    await page.goto('/remotes');
    const entry = card(page);
    await entry.getByRole('button', { name: 'Open workspace' }).click();
    // Two clicks, and the second is the one that opens the window: a popup
    // opened after an await has lost its user gesture and the browser blocks
    // it. The interstitial names the origin the human is about to sign in at.
    const proceed = entry.getByRole('button', { name: /^Continue to / });
    await expect(proceed).toBeVisible({ timeout: 30_000 });
    const popupOpened = context.waitForEvent('page');
    // The redemption response is where the bearer exists on the wire exactly
    // once. Capturing it here is what turns the persistence assertion below
    // from "no string that looks like a bearer is stored" into "THIS bearer is
    // stored nowhere".
    const redemption = page.waitForResponse(
      (r) => r.url().includes('/api/v1/auth/workspace/redeem') && r.ok(),
    );
    const liveness = page.waitForRequest((r) => r.url().includes('/api/v1/me/sessions'));
    await proceed.click();

    const popup = await popupOpened;
    await popup.waitForLoadState();
    // `noopener` ASSERTED, not claimed. Without it the remote's page keeps a
    // handle on the viewing shell and can navigate it to phishing content;
    // removing the flag would otherwise have changed no assertion in this file.
    expect(
      await popup.evaluate(() => globalThis.opener === null),
      'the popup can reach back into the viewing shell — window.opener is not null',
    ).toBe(true);
    // The ceremony is on the REMOTE'S origin. This assertion is the whole
    // architecture in one line: nothing about authenticating to B happens on
    // A, and no code path exists by which A's server could.
    expect(new URL(popup.url()).origin, 'the popup is not on the remote origin').toBe(
      new URL(BASE_URL_B).origin,
    );
    await expect(popup.getByRole('heading', { name: 'Authorize this workspace' })).toBeVisible();
    // The popup's OWN tab-scoped stores, inspected at the last moment the tab
    // is on B's origin. This is the only browsing context that ever holds
    // B-origin sessionStorage during the ceremony, and the only ceremony
    // artifact it has seen by now is the handoff state — assert B's ceremony
    // pages stash no workspace-grammar artifact (ws bearer, hc code, hs state;
    // B's own script-readable CSRF token is legitimately present and is not a
    // ceremony artifact). The bearer itself CANNOT appear in this tab's
    // B-origin storage at any later moment either: it is minted by the shell's
    // redemption call after the popup has left B for the callback origin
    // (openPrepared in web/src/api/workspace.ts — "the artifact never crosses
    // a redirect"), so this pre-authorization snapshot plus the origin-scoped
    // localStorage check below on page `b` close every store B can write.
    const popupStores = await popup.evaluate(() => ({
      local: Object.entries(globalThis.localStorage),
      session: Object.entries(globalThis.sessionStorage),
      cookie: document.cookie,
    }));
    for (const artifact of ['hik_1_ws_', 'hik_1_hc_', 'hik_1_hs_']) {
      expect(
        JSON.stringify(popupStores),
        `B's ceremony pages persisted a ${artifact} artifact in the popup tab`,
      ).not.toContain(artifact);
    }
    await popup.getByRole('button', { name: 'Authorize' }).click();

    // The popup lands on THIS origin's callback page and closes itself — it was
    // opened with `noopener`, so there is no `window.opener` to talk back
    // through and the return path is a BroadcastChannel only this origin can
    // open.
    await expect(entry.getByText('Workspace open')).toBeVisible({ timeout: 30_000 });

    // --- the bearer is in JS MEMORY ONLY, proven against the real value -----
    const redeemed: unknown = await (await redemption).json();
    const value =
      typeof redeemed === 'object' && redeemed !== null && 'value' in redeemed
        ? String(redeemed.value)
        : '';
    expect(value, 'the redemption returned no bearer to check').not.toBe('');

    const stored = await page.evaluate(() => ({
      local: Object.entries(globalThis.localStorage),
      session: Object.entries(globalThis.sessionStorage),
      cookie: document.cookie,
    }));
    expect(JSON.stringify(stored), 'the workspace bearer was persisted on the viewing origin').not.toContain(
      value,
    );
    // document.cookie sees only script-readable cookies on THIS origin. The
    // cookie jar is where an HttpOnly cookie would be, and B's jar is where the
    // remote would have set one — both are checked, because "memory only" is a
    // claim about every store either origin can write.
    const jar = await context.cookies([VIEWING_ORIGIN, BASE_URL_B]);
    expect(JSON.stringify(jar), 'the workspace bearer reached a cookie jar').not.toContain(value);
    // The SERVING origin's script-visible stores get the same inspection.
    // localStorage and document.cookie are ORIGIN-scoped, so this tab sees any
    // write the popup's B pages made. sessionStorage is tab-scoped and this
    // tab's says nothing about the popup's — that gap is closed structurally
    // by the pre-authorization popup snapshot above: the bearer is minted only
    // after the popup has left B's origin, so no B-tab sessionStorage moment
    // exists in which it could have been stored.
    const storedB = await b.evaluate(() => ({
      local: Object.entries(globalThis.localStorage),
      cookie: document.cookie,
    }));
    expect(
      JSON.stringify(storedB),
      'the workspace bearer was persisted on the serving origin',
    ).not.toContain(value);

    // And the transport is what the ADR requires: the bearer rides an
    // Authorization header, and nothing ambient travels with it.
    const probe = await liveness;
    const headers = await probe.allHeaders();
    expect(headers['authorization'], 'the liveness probe carries no bearer').toBe(`Bearer ${value}`);
    expect(headers['cookie'], 'the cross-origin probe carried cookies').toBeUndefined();

    // --- kill switch 1: the remote withdraws consent ------------------------
    await onB(b, '/remotes');
    await b
      .getByRole('button', { name: `Remove ${VIEWING_ORIGIN} and kill its workspace sessions` })
      .click();
    await expect(b.getByText('revoked 1 workspace session')).toBeVisible();

    // And the shell notices, on its own, within one liveness poll.
    await expect(entry.getByText('Workspace session ended')).toBeVisible({ timeout: 30_000 });
    await expect(entry.getByRole('button', { name: 'Open workspace' })).toBeVisible();

    // --- kill switch 2: revoked from the remote's active-session list -------
    await onB(b, '/remotes');
    await b.getByRole('textbox', { name: 'Origin' }).fill(VIEWING_ORIGIN);
    await b.getByRole('button', { name: 'Allow origin' }).click();
    await expect(b.getByText(VIEWING_ORIGIN, { exact: true })).toBeVisible();

    await entry.getByRole('button', { name: 'Open workspace' }).click();
    const proceedAgain = entry.getByRole('button', { name: /^Continue to / });
    await expect(proceedAgain).toBeVisible({ timeout: 30_000 });
    const second = context.waitForEvent('page');
    await proceedAgain.click();
    const popup2 = await second;
    await popup2.waitForLoadState();
    await popup2.getByRole('button', { name: 'Authorize' }).click();
    await expect(entry.getByText('Workspace open')).toBeVisible({ timeout: 30_000 });

    // The workspace session appears in the REMOTE'S own list as its own
    // artifact type, carrying the origin it was issued to — criterion 5.
    await onB(b, '/settings');
    const workspaceRow = b.locator('.session').filter({ hasText: 'workspace' });
    await expect(workspaceRow).toBeVisible();
    await expect(workspaceRow).toContainText(VIEWING_ORIGIN);
    await workspaceRow.getByRole('button', { name: /^Revoke the workspace session/ }).click();
    await expect(workspaceRow).toHaveCount(0);

    // Mid-flight: the shell finds out at its next request, which is what
    // "bites at the next presentation" means from out here.
    await expect(entry.getByText('Workspace session ended')).toBeVisible({ timeout: 30_000 });

    await b.close();
  });

  /**
   * THE SIGNED-OUT ARRIVAL, which is the FIRST establishment's real shape.
   *
   * A popup opened at a remote the human has never signed into on this device
   * lands with no session for that instance. Bouncing it to /login would throw
   * away the `state` the transaction is addressed by, so the approve page
   * renders the login itself and the URL survives — a small piece of routing
   * with nothing else asserting it. The suite's shared storage state carries
   * sessions for BOTH instances, so the happy path above never reaches this
   * branch at all: breaking the public signed-out route, the state-preserving
   * login, or the post-login approval would have left it green.
   */
  test('a popup arriving signed out logs in in place and still approves', async ({
    page,
    context,
  }) => {
    const b = await context.newPage();
    await onB(b, '/remotes');
    await b.getByRole('textbox', { name: 'Origin' }).fill(VIEWING_ORIGIN);
    await b.getByRole('button', { name: 'Allow origin' }).click();
    await expect(b.getByText(VIEWING_ORIGIN, { exact: true })).toBeVisible();
    await b.close();

    // Sign the context OUT of the SERVING instance only. The viewing shell must
    // stay signed in — this is the state a human is in the first time they open
    // a workspace at a remote. B's cookies are kept so the fully stepped-up
    // administrator session can be restored for the cleanup at the end: the
    // password login this test performs in the popup is single-factor, and
    // every instance-scope surface on B is MFA-mandatory, so it cannot reach
    // B's own remotes page afterwards.
    // Captured by DOMAIN, not by URL. `context.cookies(url)` applies the
    // browser's own delivery rules, and a `Secure` cookie is not delivered to
    // an `http://` URL whose host is an IP LITERAL — Chrome's plaintext
    // carve-out for secure cookies is `localhost` by name. B is the address
    // literal (A holds `localhost`, which WebAuthn requires of the instance
    // that runs passkey ceremonies), so the URL form silently returns nothing
    // here and the restore below would put back an empty jar.
    const bSession = (await context.cookies()).filter((c) => c.domain === HOST_B);
    await context.clearCookies({ domain: HOST_B });

    await page.goto('/remotes');
    const entry = card(page);
    await entry.getByRole('button', { name: 'Open workspace' }).click();
    const proceed = entry.getByRole('button', { name: /^Continue to / });
    await expect(proceed).toBeVisible({ timeout: 30_000 });
    const popupOpened = context.waitForEvent('page');
    await proceed.click();

    const popup = await popupOpened;
    await popup.waitForLoadState();
    const arrivedAt = popup.url();
    expect(new URL(arrivedAt).origin).toBe(new URL(BASE_URL_B).origin);

    // The login is rendered IN PLACE, on the approve route, not at /login.
    await expect(popup.getByRole('heading', { name: 'Sign in to Hikyo' })).toBeVisible();
    expect(new URL(popup.url()).pathname, 'the popup was bounced off the approve route').toBe(
      new URL(arrivedAt).pathname,
    );
    expect(new URL(popup.url()).search, 'the transaction state was lost at the login').toBe(
      new URL(arrivedAt).search,
    );

    await popup.getByLabel('Username').fill(ADMIN.username);
    await popup.getByLabel('Password').fill(ADMIN.password);
    await popup.getByRole('button', { name: 'Sign in' }).click();

    // And the transaction the popup arrived holding is the one it approves.
    await popup.getByRole('button', { name: 'Authorize' }).click();
    await expect(entry.getByText('Workspace open')).toBeVisible({ timeout: 30_000 });

    // Clean up the session this test opened. Both Playwright projects run
    // against the SAME pair of instances, so a workspace session left behind
    // here is one the other project's kill-switch test would find and count —
    // its "revoked 1 workspace session" assertion is a real assertion and must
    // not be loosened to absorb this one's litter.
    await context.clearCookies({ domain: HOST_B });
    await context.addCookies(bSession);
    const cleanup = await context.newPage();
    await onB(cleanup, '/remotes');
    await cleanup
      .getByRole('button', { name: `Remove ${VIEWING_ORIGIN} and kill its workspace sessions` })
      .click();
    await expect(cleanup.getByText('revoked 1 workspace session')).toBeVisible();
    await cleanup.close();
  });

  // The matrix is DERIVED from the registry, not re-listed beside it: this flow
  // asserts exactly the surfaces it claims. Both themes, because the palette is
  // a dual-theme palette and half of it going unchecked is half a claim.
  for (const surface of surfacesForFlow('workspace')) {
    for (const scheme of ['dark', 'light'] as const) {
      test(`meets the pinned assertion set on ${surface.label} (${scheme})`, async ({ page }) => {
        await page.emulateMedia({ colorScheme: scheme });
        // The two ceremony pages are reached by a redirect in life, so they are
        // visited with the query they are addressed by — the approve page with
        // a state to consent to, the callback page with none, which is its own
        // refusal state and the one that renders without closing the window.
        await page.goto(surface.id === 'workspace-approve' ? `${surface.path}?state=hik_1_test` : surface.path);

        const heading = page.getByRole('heading', { level: 1 }).first();
        await expect(heading).toBeVisible();
        const container = page.locator('.card, .login__card').first();

        await expectPinnedAssertionSet(page, {
          flow: 'workspace',
          surface: surface.id,
          theme: scheme,
          text: [heading],
          radii: [[container, 'container']],
          fonts: [[heading, 'ui']],
          colours: [
            [heading, 'color', '--tx'],
            [container, 'backgroundColor', '--bg-raise'],
            [container, 'borderTopColor', '--line'],
          ],
          hairlines: [container],
          density: [],
        });
      });
    }
  }
});
