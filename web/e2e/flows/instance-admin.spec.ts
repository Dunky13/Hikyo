import { expect, test } from '@playwright/test';
import {
  zGrantList,
  zOrgList,
  zSamlProviderMutationResult,
  zScimBinding,
  zScimMappingResult,
  zScimMintResult,
} from '@hikyo/zod';
import { z } from 'zod';

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { expectPinnedAssertionSet, expectStatusIsTextAndAria } from '../fixtures/assertions.ts';
import {
  browserApi,
  BASE_URL,
  establishSession,
  INSTANCE_GRANT_TARGET,
  nextTotpCode,
  readSeed,
  STORAGE_STATE,
} from '../fixtures/instance.ts';

/**
 * Flow: instance administration (registry surface `instance-admin`) —
 * mvp-boundary S3's "instance administration", against the locked prototype
 * #29 iteration 15.
 *
 * Three properties this flow exists to hold:
 *
 *  - the organisation enumeration is the OPERATOR's, and it is MFA-mandatory.
 *    A password-only session gets the honest "second factor required" state,
 *    never an empty list — the empty list would be the UI answering a question
 *    it was refused;
 *  - the instance grant listing shows origins, so a break-glass grant is
 *    distinguishable from an ordinary one after an incident. The fixture's own
 *    seeding grants are break-glass, which is what makes this assertable;
 *  - the SystemProof local set is stated as absent rather than drawn as
 *    disabled controls, and the one key operation that does have a network
 *    surface warns before it runs.
 */

const seed = readSeed();

function samlMetadata(slug: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'hikyo-saml-e2e-'));
  const key = join(dir, 'idp.key');
  const cert = join(dir, 'idp.crt');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', key, '-out', cert, '-days', '365',
      '-subj', `/CN=${slug}`,
    ], { stdio: 'ignore' });
    const certificate = readFileSync(cert, 'utf8')
      .split('\n')
      .filter((line) => !line.startsWith('-----'))
      .join('');
    return (
      '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ' +
      'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
      `entityID="https://idp.example/${slug}">` +
      '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
      '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
      certificate +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>' +
      `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/${slug}/sso"/>` +
      '</md:IDPSSODescriptor></md:EntityDescriptor>'
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test.describe('instance administration', () => {
  test.describe.configure({ mode: 'serial' });
  test.use({ storageState: STORAGE_STATE });

  test.beforeEach(async ({ page }) => {
    await page.goto('/instance');
    await expect(
      page.getByRole('heading', { name: 'Instance administration', level: 1 }),
    ).toBeVisible();
  });

  test('enumerates the organisations on the instance', async ({ page }) => {
    const orgs = page.locator('#instance-orgs');
    const count = orgs.getByRole('status');
    await expectStatusIsTextAndAria(page, count);
    // The fixture creates two: the tenant every other flow addresses, and a
    // second one that holds nothing.
    await expect(orgs).toContainText(seed.orgName);
    await expect(orgs).toContainText(seed.orgBName);
    await expect(orgs.getByRole('link', { name: 'Settings' }).first()).toBeVisible();
  });

  test('shows instance grants with the origin that holds them', async ({ page }) => {
    const grants = page.locator('#instance-grants');
    // The seeding grants are written by the host-local `admin grant` verb, so
    // they carry the break-glass origin — the one distinction the membership
    // surface exists to preserve.
    await expect(grants.getByText('break-glass').first()).toBeVisible();
    await expect(grants.getByText(seed.principal).first()).toBeVisible();
    await expect(grants).toContainText('manage-projects');
    await expect(grants).toContainText('inherit downward into every organisation');
  });

  test('states the pruner health and where else the same fact lives', async ({ page }) => {
    const health = page.locator('#instance-retention');
    await expectStatusIsTextAndAria(page, health.getByRole('status'));
    await expect(health).toContainText('Payload pruning');
    await expect(health).toContainText('hikyo doctor');
  });

  test('warns before rotating the change-token key, and does not rotate on cancel', async ({
    page,
  }) => {
    const keys = page.locator('#instance-keys');
    // The local-host-authority set is named as absent, not drawn as disabled
    // buttons: they have no network surface at all, by ADR.
    await expect(keys).toContainText('local host authority');
    await expect(keys).toContainText('CLI-at-the-box, not CLI-over-network');
    await expect(keys.getByRole('button', { name: /rotate/i })).toHaveCount(1);

    await keys.getByRole('button', { name: 'Rotate the change-token key' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Every conditional-fetch cursor in circulation stops');
    await expect(dialog).toContainText('cannot be undone');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(keys.getByRole('button', { name: 'Rotate the change-token key' })).toBeFocused();
  });

  test('reads and saves the machine-credential ceiling', async ({ page }) => {
    const settings = page.locator('#instance-settings');
    const lifetime = settings.getByLabel('Maximum finite lifetime (seconds)');
    const live = settings.getByLabel('Maximum live credentials per service account');
    await expect(lifetime).not.toHaveValue('');
    await expect(live).not.toHaveValue('');
    await settings.getByRole('button', { name: 'Save credential policy' }).click();
    const done = page.locator('.notice').filter({ hasText: 'Credential policy updated' });
    await expectStatusIsTextAndAria(page, done);
  });

  test('clears an affected-credential preview on edit and confirms its exact snapshot', async ({
    page,
  }) => {
    const requestSchema = z.object({
      max_finite_lifetime_seconds: z.number().int().positive(),
      allow_indefinite: z.boolean(),
      max_live_credentials: z.number().int().positive(),
      confirm: z.boolean().optional(),
    });
    type PolicyRequest = z.infer<typeof requestSchema>;
    const requests: PolicyRequest[] = [];
    await page.route('**/api/v1/instance/credential-policy', async (route) => {
      if (route.request().method() !== 'PUT') {
        await route.continue();
        return;
      }
      const body = requestSchema.parse(route.request().postDataJSON());
      requests.push(body);
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          applied: body.confirm === true,
          policy: {
            max_finite_lifetime_seconds: body.max_finite_lifetime_seconds,
            allow_indefinite: body.allow_indefinite,
            max_live_credentials: body.max_live_credentials,
          },
          affected: [
            {
              id: 'mcr_00000000-0000-4000-8000-000000000001',
              service_account_id: 'svc_00000000-0000-4000-8000-000000000002',
              reason: 'clamped',
            },
          ],
          clamped_count: body.confirm === true ? 1 : 0,
        }),
      });
    });

    const settings = page.locator('#instance-settings');
    const lifetime = settings.getByLabel('Maximum finite lifetime (seconds)');
    const live = settings.getByLabel('Maximum live credentials per service account');
    await lifetime.fill(String(Math.max(1, Number(await lifetime.inputValue()) - 1)));
    await settings.getByRole('button', { name: 'Save credential policy' }).click();
    await expect(settings.getByRole('alert')).toContainText('Nothing has changed yet');

    await live.fill(String(Number(await live.inputValue()) + 1));
    await expect(settings.getByRole('alert')).toHaveCount(0);

    await settings.getByRole('button', { name: 'Save credential policy' }).click();
    await expect(settings.getByRole('alert')).toContainText('Nothing has changed yet');
    const previewed = requests[requests.length - 1];
    if (previewed === undefined) {
      throw new Error('the credential-policy preview request was not captured');
    }
    await settings.getByRole('button', { name: 'Apply and affect these credentials' }).click();
    await expect(page.locator('.notice').filter({ hasText: 'Credential policy updated' })).toBeVisible();
    expect(requests[requests.length - 1]).toEqual({ ...previewed, confirm: true });
  });

  test('creates and revokes an instance grant with visible provenance', async ({ page }) => {
    const grants = page.locator('#instance-grants');
    await grants.getByLabel('Principal ID').fill(INSTANCE_GRANT_TARGET);
    await grants.getByRole('checkbox', { name: /^read —/ }).check();
    await grants.getByRole('button', { name: 'Create instance grant' }).click();
    const row = grants.locator('li.factor').filter({ hasText: INSTANCE_GRANT_TARGET }).filter({ hasText: 'read' });
    await expect(row).toContainText(`manual: ${seed.principal}`);
    await row.getByRole('button', { name: 'Revoke' }).click();
    const revoked = page.locator('.notice').filter({ hasText: 'refreshed list confirms it is absent' });
    await expectStatusIsTextAndAria(page, revoked);
    await expect(row).toHaveCount(0);
  });

  test('applies the instance role template through the UI and revokes every created line', async ({
    page,
  }, testInfo) => {
    testInfo.setTimeout(60_000);
    const slug = `instance-template-${testInfo.project.name}`;
    const metadata = samlMetadata(slug);
    const providerInput = {
      display_name: slug,
      entity_id: `https://idp.example/${slug}`,
      metadata_source: 'file',
      metadata_document: metadata,
      metadata_url: null,
      assurance_policy: null,
      allow_email_nameid: false,
      force_sign_requests: false,
      enabled: true,
    } as const;
    const preview = await browserApi(
      page,
      'PUT',
      `/api/v1/instance/saml-providers/${slug}`,
      zSamlProviderMutationResult,
      providerInput,
    );
    expect(preview.applied).toBe(false);
    const applied = await browserApi(
      page,
      'PUT',
      `/api/v1/instance/saml-providers/${slug}`,
      zSamlProviderMutationResult,
      {
        ...providerInput,
        confirmed_fingerprints: preview.required_fingerprints,
        confirmed_endpoints: preview.required_endpoints,
      },
    );
    if (!applied.applied || applied.provider === null || applied.provider === undefined) {
      throw new Error('the throwaway SAML provider did not apply after its trust diff was confirmed');
    }
    const provider = applied.provider;
    const binding = await browserApi(
      page,
      'POST',
      `/api/v1/orgs/${seed.org}/scim-bindings`,
      zScimBinding,
      {
        provider_kind: 'saml',
        provider_slug: provider.slug,
        subject_source: 'externalId',
        nameid_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        nameid_qualifier_present: false,
        nameid_sp_qualifier_present: false,
      },
    );
    const minted = await browserApi(
      page,
      'POST',
      `/api/v1/orgs/${seed.org}/scim-bindings/${binding.id}/credentials`,
      zScimMintResult,
      { proof: await nextTotpCode() },
    );
    const userResponse = await fetch(
      `${BASE_URL}/api/v1/orgs/${seed.org}/scim/v2/${binding.id}/Users`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${minted.token}`,
          'Content-Type': 'application/scim+json',
        },
        body: JSON.stringify({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: `${slug}@example.invalid`,
          externalId: `${slug}-subject`,
          active: true,
        }),
      },
    );
    const userResponseText = await userResponse.text();
    expect(userResponse.status, userResponseText).toBe(201);
    const userBody: unknown = JSON.parse(userResponseText);
    const user = z.object({ id: z.string() }).parse(userBody);
    const groupResponse = await fetch(
      `${BASE_URL}/api/v1/orgs/${seed.org}/scim/v2/${binding.id}/Groups`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${minted.token}`,
          'Content-Type': 'application/scim+json',
        },
        body: JSON.stringify({
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
          displayName: `${slug}-group`,
          members: [{ value: user.id }],
        }),
      },
    );
    const groupResponseText = await groupResponse.text();
    expect(groupResponse.status, groupResponseText).toBe(201);
    const groupBody: unknown = JSON.parse(groupResponseText);
    const group = z.object({ id: z.string() }).parse(groupBody);
    const mapping = await browserApi(
      page,
      'POST',
      `/api/v1/orgs/${seed.org}/scim-bindings/${binding.id}/mappings`,
      zScimMappingResult,
      { group_id: group.id, template: 'viewer' },
    );
    const orgGrants = await browserApi(
      page,
      'GET',
      `/api/v1/orgs/${seed.org}/grants`,
      zGrantList,
    );
    const seededGrant = orgGrants.items.find((grant) =>
      grant.origins.some(
        (origin) => origin.kind === 'scim' && origin.subject.includes(mapping.mapping.id),
      ),
    );
    if (seededGrant === undefined) {
      throw new Error('the throwaway SCIM mapping did not expose its human principal in grants');
    }
    const principal = seededGrant.principal_id;
    try {
      const grants = page.locator('#instance-grants');
      await grants.getByLabel('Principal ID').fill(principal);
      await grants.getByLabel('Role-template shortcut').selectOption('operator');
      await grants.getByRole('button', { name: 'Create instance grant' }).click();
      await expect(page.locator('.notice').filter({ hasText: 'instance grant line' })).toContainText(
        principal,
      );
      const listed = await browserApi(page, 'GET', '/api/v1/instance/grants', zGrantList);
      expect(listed.items.filter((grant) => grant.principal_id === principal).length).toBeGreaterThan(0);
    } finally {
      const listed = await browserApi(page, 'GET', '/api/v1/instance/grants', zGrantList);
      for (const grant of listed.items.filter((item) => item.principal_id === principal)) {
        const query = `principal=${encodeURIComponent(principal)}&capability=${encodeURIComponent(grant.capability)}`;
        await browserApi(page, 'DELETE', `/api/v1/instance/grants?${query}`, z.null());
      }
      await browserApi(
        page,
        'DELETE',
        `/api/v1/orgs/${seed.org}/scim-bindings/${binding.id}/mappings?group=${encodeURIComponent(group.id)}`,
        zScimMappingResult,
      );
      const deletedGroup = await fetch(
        `${BASE_URL}/api/v1/orgs/${seed.org}/scim/v2/${binding.id}/Groups/${group.id}`,
        { method: 'DELETE', headers: { Authorization: `Bearer ${minted.token}` } },
      );
      expect(deletedGroup.status).toBe(204);
      const deleted = await fetch(
        `${BASE_URL}/api/v1/orgs/${seed.org}/scim/v2/${binding.id}/Users/${user.id}`,
        { method: 'DELETE', headers: { Authorization: `Bearer ${minted.token}` } },
      );
      expect(deleted.status).toBe(204);
      await browserApi(page, 'DELETE', `/api/v1/orgs/${seed.org}/scim-bindings/${binding.id}`, z.null());
      await browserApi(page, 'DELETE', `/api/v1/instance/saml-providers/${provider.slug}`, z.null());
    }
  });

  test('creates an organisation and says what it did not do', async ({ page }, testInfo) => {
    const name = `Instance drill ${testInfo.project.name}`;
    let created = '';
    try {
      await page.getByLabel('New organisation name').fill(name);
      await page.getByRole('button', { name: 'Create organisation' }).click();
      const done = page.locator('.notice').filter({ hasText: `Created ${name}` });
      await expectStatusIsTextAndAria(page, done);
      // Creating an organisation seeds its creator NOTHING: the permission
      // model refuses to hand the creator standing authority inside it.
      await expect(done).toContainText('seeds its creator nothing');
      await expect(page.locator('#instance-orgs')).toContainText(name);

      const orgs = await browserApi(page, 'GET', '/api/v1/orgs', zOrgList);
      const createdOrg = orgs.items.find((org) => org.name === name);
      if (createdOrg === undefined) throw new Error(`created organisation ${name} was not listed`);
      created = createdOrg.id;
    } finally {
      if (created !== '') {
        await browserApi(page, 'DELETE', `/api/v1/orgs/${created}`, z.null());
      }
    }
  });

  test('answers a password-only session with the second-factor state, not an empty list', async ({
    browser,
  }) => {
    // Its own context, with an EMPTY jar: `browser.newContext()` still picks
    // up the describe's `storageState`, and a live session cookie on a login
    // POST is refused 401 by the CSRF gate before the handler ever sees it —
    // which looks exactly like a wrong password. This session is deliberately
    // weaker than the suite's, and it must not replace it.
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    try {
      const page = await context.newPage();
      await page.goto('/');
      await establishSession(page, false);
      await page.goto('/instance');

      const panels = [
        ['#instance-orgs', 'needs a second factor', 'organisations on this instance'],
        ['#instance-grants', 'require a second factor', 'No instance-scope grants'],
        ['#instance-retention', 'requires a second factor', 'Payload pruning'],
        ['#instance-settings', 'requires a second factor', 'Maximum finite lifetime'],
      ] as const;
      for (const [selector, refusalText, forbiddenText] of panels) {
        const panel = page.locator(selector);
        await expect(panel.getByRole('alert')).toContainText(refusalText);
        await expect(panel).not.toContainText(forbiddenText);
      }
    } finally {
      await context.close();
    }
  });

  for (const scheme of ['dark', 'light'] as const) {
    test(`meets the pinned assertion set on instance administration (${scheme})`, async ({
      page,
    }) => {
      await page.emulateMedia({ colorScheme: scheme });
      try {
        const heading = page.getByRole('heading', {
          name: 'Instance administration',
          level: 1,
        });
        const well = page.locator('.panel').first();
        const create = page.getByRole('button', { name: 'Create organisation' });
        const badge = page.locator('.badge').first();

        await expectPinnedAssertionSet(page, {
          flow: 'instance-admin',
          surface: 'instance-admin',
          theme: scheme,
          text: [heading, page.locator('.factor__meta').first(), page.locator('.page__lede')],
          radii: [
            [well, 'container'],
            [create, 'control'],
            [badge, 'badge'],
          ],
          fonts: [
            [heading, 'ui'],
            [page.locator('.factor__meta').first(), 'mono'],
          ],
          colours: [
            [heading, 'color', '--tx'],
            [well, 'backgroundColor', '--bg-raise'],
            [well, 'borderTopColor', '--line'],
          ],
          hairlines: [well],
          density: [[create, '--touch']],
        });
      } finally {
        await page.emulateMedia({ colorScheme: null });
      }
    });
  }
});
