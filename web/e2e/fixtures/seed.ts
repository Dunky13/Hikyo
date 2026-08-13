import { createHmac } from 'node:crypto';

import { z } from 'zod';

import { ADMIN, BASE_URL } from './instance.ts';

/**
 * The fixture tenant the reveal flow needs (#58).
 *
 * It is seeded through the REAL API with a real session, never by writing to
 * the datastore: a value is a sealed envelope bound to its own row, and a
 * fixture that inserted bytes directly would produce cells nothing can open —
 * a flow that then "passed" would be proving something about a broken row.
 *
 * Two capabilities on the seeding path are MFA-mandatory (`instance-config`
 * creates the org, `reveal` is the one under test), so the seeding session
 * enrols TOTP and steps up.
 *
 * The TOTP code is computed here rather than pulled from a library. It is
 * FIXTURE-GRADE and deliberately so: the product's own TOTP lives in
 * `internal/crypto/totp.go` and is not reachable from Node, there is no
 * TypeScript equivalent anywhere in this repo to reuse, and RFC 6238 with the
 * server's fixed parameters (SHA-1, six digits, 30-second steps) is a dozen
 * lines of `node:crypto`. Adding a dependency to a test harness for that is a
 * dependency to audit and pin forever. It is checked against the RFC's own
 * vectors, and it authenticates nothing in production.
 *
 * Every response crosses a Zod schema before anything reads it, exactly as the
 * SPA's own client does: a fixture that trusted `resp.json()` would fail three
 * frames from the mistake, in setup, where the message matters most.
 */

export type Seeded = {
  org: string;
  project: string;
  /** The open environment: a sliding window applies. */
  dev: string;
  /** The protected environment: the window is capped at 0. */
  prod: string;
  /** The secret keys, in the order they were created. */
  secrets: readonly string[];
  /**
   * The secret the write-only flow REPLACES.
   *
   * Its own key, because a blind rotation changes what is stored — and a test
   * that rotated a value another test asserts by literal would pass alone and
   * fail in the suite, which is the worst kind of failure to read.
   */
  rotatable: string;
  /** One config key, so "non-secret copy is free" has a subject. */
  config: string;
  /** The seeding session's bearer token — the flows use cookies, not this. */
  token: string;
  principal: string;
  /**
   * The administrator's TOTP provisioning URI.
   *
   * The flows need it to drive the ceremony's CODE path, which is the factor a
   * non-protected environment offers and which no other assertion in the suite
   * exercises to success. It is a fixture secret for a throwaway instance, in
   * a gitignored file, on a temp database that is deleted at teardown.
   */
  otpauth: string;
  /**
   * The newest TOTP step the SEEDING session spent a code on.
   *
   * Every code is single-use per (account, step), and seeding spends several
   * in a row — so a flow presenting a code has to pick a step beyond this one
   * or be refused as a replay, which looks exactly like a wrong code.
   */
  lastTotpStep: number;
  /**
   * The machine-access fixture (#67).
   *
   * Three service accounts because the surface has three shapes to show: a
   * workload that has been granted `read` (its journey is under way), a
   * workload with no grants at all (whose mint therefore needs no disclosure
   * ceremony, and whose credential count the mint flow may move), and an
   * automation principal (which has no setup journey at all).
   */
  machine: {
    /** The workload holding `read` on development, with a federated binding. */
    workload: string;
    /** The automation principal — no journey, different allowlist. */
    automation: string;
    /** The workload the mint flow mints on, so counts stay predictable. */
    mintable: string;
    /** The configured issuer, byte-exact. */
    issuer: string;
    /** The bound subject, byte-exact. */
    subject: string;
    /** The bound audience, which is never the issuer's default. */
    audience: string;
  };
};

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** decodeBase32 turns the otpauth secret into bytes. */
function decodeBase32(secret: string): Buffer {
  const clean = secret.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index < 0) {
      throw new Error(`the TOTP secret carried a non-base32 character: ${char}`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      // Drop the bits just emitted. JavaScript's bitwise operators are 32-bit,
      // so an accumulator that kept its whole history would overflow after the
      // sixth character and every byte from there on would be wrong.
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

/** totpCode is RFC 6238, SHA-1, 6 digits, 30-second steps — the server's parameters. */
export function totpCode(otpauthURI: string, at: Date = new Date()): string {
  const secret = new URL(otpauthURI).searchParams.get('secret');
  if (secret === null) {
    throw new Error('the enrolment URI carried no secret');
  }
  const step = Math.floor(at.getTime() / 1000 / 30);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac('sha1', decodeBase32(secret)).update(counter).digest();
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;
  const binary =
    (((digest[offset] ?? 0) & 0x7f) << 24) |
    (((digest[offset + 1] ?? 0) & 0xff) << 16) |
    (((digest[offset + 2] ?? 0) & 0xff) << 8) |
    ((digest[offset + 3] ?? 0) & 0xff);
  return String(binary % 1_000_000).padStart(6, '0');
}

type Json = Record<string, unknown>;

/** zCreated is every create response this fixture reads: it needs the id. */
const zCreated = z.object({ id: z.string() });
const zServiceAccount = z.object({ id: z.string(), principal_id: z.string() });
const zStaged = z.object({ version_id: z.string() });
const zEnrolStart = z.object({ otpauth_uri: z.string() });
const zRotated = z.object({ session_token: z.string() });
const zWhoAmI = z.object({ principal: z.object({ id: z.string() }) });
// The fixture reads nothing out of these responses. The parse still earns its
// place: it proves the server answered an OBJECT rather than, say, an error
// page that happened to arrive with a 200.
const zIgnored = z.object({});

async function call<T>(
  token: string,
  method: string,
  path: string,
  schema: z.ZodType<T>,
  body?: Json,
): Promise<T> {
  const resp = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      // A bearer caller has no cookie leg and therefore no CSRF contract, which
      // is what makes seeding a plain fetch rather than a cookie dance.
      Authorization: `Bearer ${token}`,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!resp.ok) {
    throw new Error(`${method} ${path} answered ${resp.status}: ${await resp.text()}`);
  }
  // Parsed, never trusted — the same rule the SPA's own client keeps. A
  // fixture that read `resp.json()` straight would fail three frames from the
  // mistake, in setup, where a clear message matters most.
  const raw: unknown = resp.status === 204 ? {} : await resp.json();
  const result = schema.safeParse(raw);
  if (!result.success) {
    throw new Error(
      `${method} ${path} answered a shape the fixture does not expect: ${result.error.message}`,
    );
  }
  return result.data;
}

/**
 * lastStep is the newest time step this process has spent a code on.
 *
 * Every TOTP code is single-use per (account, step) — enrolment's confirming
 * code included — so two presentations in the same second cannot both succeed,
 * and a step two ahead of now is outside the server's accepted skew. The only
 * honest way through is to wait for the clock, which is what `consumeCode`
 * does: at most one 30-second step per presentation, in global setup, once.
 */
let lastStep = -1;

async function consumeCode(token: string, uri: string, path: string): Promise<string> {
  const step = () => Math.floor(Date.now() / 1000 / 30);
  // The next step nothing has spent. A code is single-use per (account, step)
  // — the enrolment's own start reserves one too — so each presentation has to
  // move forward.
  const want = Math.max(step(), lastStep + 1);
  // Wait ONLY when the wanted step is out of the server's ±1 skew. One step
  // ahead is presentable now, which is what keeps global setup short: the
  // instance is a child of the setup process, and a setup that sits waiting
  // for minutes is a setup whose instance does not survive to serve the run.
  while (want - step() > 1) {
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  lastStep = want;
  const result = await call(token, 'POST', path, zRotated, {
    code: totpCode(uri, new Date(want * 30_000 + 1_000)),
  });
  return result.session_token;
}

/** signIn is a fresh password session, as a bearer artifact. */
async function signIn(): Promise<string> {
  const resp = await fetch(`${BASE_URL}/api/v1/auth/local/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: ADMIN.username,
      password: ADMIN.password,
    }),
  });
  if (!resp.ok) {
    throw new Error(`the seeding login answered ${resp.status}`);
  }
  const body: unknown = await resp.json();
  if (typeof body !== 'object' || body === null) {
    throw new Error('the seeding login answered a non-object body');
  }
  const record: Record<string, unknown> = { ...body };
  const token = record['session_token'];
  if (typeof token !== 'string') {
    throw new Error('the seeding login returned no bearer token');
  }
  return token;
}


/**
 * seedTenant creates the org, project, two environments, three keys and their
 * values, and marks production protected.
 *
 * `runAdminGrant` is the break-glass local-authority verb: the bootstrap
 * administrator holds `operator` at instance scope and deliberately NO
 * disclosure capability (the permission model refuses to hand the first admin
 * secret access over every org that will ever exist), so the value authority
 * has to be granted explicitly — exactly as an operator would.
 */
/** REVEAL_GRANT is the instance-scope `reveal` row the write-only flow toggles. */
export const REVEAL_GRANT = { capability: 'reveal', scope: 'instance' } as const;

/**
 * MACHINE is the machine-access fixture's fixed vocabulary (#67).
 *
 * The issuer, subject and audience are byte-exact strings the flow asserts on
 * screen: the whole federation rule is that nothing folds case, resolves a URL
 * or strips a slash, so what is seeded and what is rendered must be one string.
 */
export const MACHINE = {
  workload: 'web-api',
  automation: 'nightly-export',
  mintable: 'batch-worker',
  issuer: 'https://kubernetes.default.svc.cluster.local',
  subject: 'system:serviceaccount:hikyo-system:hikyo-fetch',
  // Never the issuer's default: a token minted for the API server must not
  // authenticate here, which is what the refused-audience list enforces.
  audience: 'hikyo.example.org/main',
} as const;

/** grantReveal creates the revocable instance-scope `reveal` grant. */
export async function grantReveal(token: string, principal: string): Promise<void> {
  await call(token, 'POST', '/api/v1/instance/grants', zIgnored, {
    principal,
    capability: REVEAL_GRANT.capability,
  });
}

export async function seedTenant(
  runAdminGrant: (args: readonly string[]) => void,
): Promise<Seeded> {
  // The order below is dictated by ONE rule: granting advances the target's
  // session generation and kills every session they hold. So the grants that
  // need no session go first, the two MFA-mandatory acts share one stepped-up
  // session, and the rest runs on a plain one.
  //
  // A CLI-artifact session throughout: the flows use the browser one, and
  // mixing the two would let a seeding step silently rotate the cookie the
  // tests hold.
  const {
    principal: { id: principal },
  } = await call(await signIn(), 'GET', '/api/v1/auth/whoami', zWhoAmI);

  // Break-glass grants at INSTANCE scope: everything the value surface needs,
  // each one its own visible, revocable row, reaching this org by the ordinary
  // downward inheritance every scope has.
  //
  // Instance rather than org scope for a reason worth keeping: `listMyOrgs`
  // projects the orgs a caller's own grants NAME, so org-scoped grants would
  // put this fixture's org in the bootstrap administrator's rail and quietly
  // delete the shell flow's zero-organisation state — a locked surface state
  // that has nothing to do with this ticket.
  //
  // `reveal` is deliberately NOT here: it is granted through the API below, so
  // it carries a `manual` origin. Break-glass grants carry a `break-glass`
  // origin, and the grant API releases only the origins it owns — so a
  // break-glass `reveal` could not be revoked over the network, and the
  // write-only editing flow needs to take it away and give it back.
  for (const capability of [
    'read',
    'edit',
    'publish',
    'manage-projects',
    'definitions-edit',
    'project-settings',
    // The machine-access surface's own authority (#67): listing service
    // accounts, minting and binding are all `manage-identities`, which is a
    // separate atom from administering members.
    'manage-identities',
  ]) {
    runAdminGrant(['--principal', principal, '--capability', capability]);
  }

  // Now the MFA session. `instance-config` (which creates the org) and
  // `manage-members` (which grants `reveal`) are the only MFA-mandatory acts
  // in this fixture, and they share one stepped-up session because every TOTP
  // presentation costs a wait for a free time step.
  let token = await signIn();
  const { otpauth_uri: uri } = await call(
    token,
    'POST',
    '/api/v1/auth/totp/enrol/start',
    zEnrolStart,
    { password: ADMIN.password },
  );
  // Enrolment RESERVES the step it started in: confirmation must consume a
  // LATER one, because a code is single-use per (account, step) and the start
  // already recorded that step as spent.
  lastStep = Math.floor(Date.now() / 1000 / 30);
  token = await consumeCode(token, uri, '/api/v1/auth/totp/enrol/confirm');
  // Confirmation reissues the session carrying only the PASSWORD class: the
  // factor was enrolled, not presented, and a human steps up separately.
  token = await consumeCode(token, uri, '/api/v1/auth/totp/step-up');

  const { id: org } = await call(token, 'POST', '/api/v1/orgs', zCreated, {
    name: 'Ceremonies',
  });

  // The federation issuer is instance-scoped configuration, so it is
  // `instance-config` and belongs in this same stepped-up session. Static JWKS
  // rather than discovery: nothing in this fixture presents a token, and a
  // discovery issuer would make setup depend on an unreachable network host.
  await call(token, 'POST', '/api/v1/instance/federation-issuers', zCreated, {
    issuer: MACHINE.issuer,
    issuer_type: 'kubernetes',
    jwks_mode: 'static',
    static_jwks: '{"keys":[]}',
    // The API server's own audience, which no binding may name and no token may
    // carry — the rule the mandatory audience exists to enforce.
    refused_audiences: ['https://kubernetes.default.svc'],
  });

  const { id: project } = await call(token, 'POST', `/api/v1/orgs/${org}/projects`, zCreated, {
    name: 'payments',
  });
  const { id: dev } = await call(
    token,
    'POST',
    `/api/v1/orgs/${org}/projects/${project}/environments`,
    zCreated,
    { name: 'development' },
  );
  const { id: prod } = await call(
    token,
    'POST',
    `/api/v1/orgs/${org}/projects/${project}/environments`,
    zCreated,
    { name: 'production' },
  );

  // The machine-identity fixture, still on the stepped-up session: granting a
  // capability to the service account is `manage-members`, which is
  // MFA-mandatory, so it cannot wait for the plain session below.
  const created = async (name: string, kind: 'workload' | 'automation') =>
    call(
      token,
      'POST',
      `/api/v1/orgs/${org}/projects/${project}/service-accounts`,
      zServiceAccount,
      { name, kind },
    );
  const workload = await created(MACHINE.workload, 'workload');
  await created(MACHINE.automation, 'automation');
  await created(MACHINE.mintable, 'workload');

  await call(
    token,
    'POST',
    `/api/v1/orgs/${org}/projects/${project}/environments/${dev}/grants`,
    zIgnored,
    { principal: workload.principal_id, capability: 'read' },
  );
  // A binding whose service account reaches no plaintext: `read` delivers
  // configuration and secret presence, so the mint formula's disclosure
  // conjunct is vacuous and no reauthentication is required here.
  await call(
    token,
    'POST',
    `/api/v1/orgs/${org}/projects/${project}/service-accounts/${workload.id}/bindings`,
    zIgnored,
    {
      issuer: MACHINE.issuer,
      subject: MACHINE.subject,
      audience: MACHINE.audience,
      required_claims: [
        { claim: '/kubernetes.io/serviceaccount/uid', string_value: '9f2c-fixture-uid' },
      ],
    },
  );

  // `reveal` through the API, under the instance `manage-members` the operator
  // template seeds — the ADR's own unheld-capability granting power, at the
  // scope where the threat model actually extends that trust.
  await grantReveal(token, principal);

  // That grant killed the session with it. Nothing left to seed is
  // MFA-mandatory — `manage-projects`, `definitions-edit`, `edit`, `publish`
  // and `project-settings` are all ordinary capabilities — so a plain password
  // session finishes the job with no further codes.
  token = await signIn();

  const secrets = ['DB_PASSWORD', 'STRIPE_SECRET_KEY', 'ROTATE_ME'];
  const rotatable = 'ROTATE_ME';
  const config = 'LOG_LEVEL';
  for (const name of [...secrets, config]) {
    await call(token, 'POST', `/api/v1/orgs/${org}/projects/${project}/keys`, zCreated, {
      name,
      classification: secrets.includes(name) ? 'secret' : 'config',
      declaration: { rule: { type: 'string' } },
    });
  }
  // Since #51 a value PUT only STAGES a pending change; delivery and the
  // matrix's published state come from the selective publish that follows.
  // The fixture publishes everything it staged, per environment, because the
  // flows exercise PUBLISHED values — staging is its own surface.
  const devVersions: string[] = [];
  for (const [name, value] of [
    ['DB_PASSWORD', 'hunter2-development'],
    ['STRIPE_SECRET_KEY', 'sk_test_development'],
    ['ROTATE_ME', 'rotate-me-development'],
    ['LOG_LEVEL', 'debug'],
  ] as const) {
    const staged = await call(
      token,
      'PUT',
      `/api/v1/orgs/${org}/projects/${project}/environments/${dev}/values/${name}`,
      zStaged,
      { value },
    );
    devVersions.push(staged.version_id);
  }
  await call(
    token,
    'POST',
    `/api/v1/orgs/${org}/projects/${project}/environments/${dev}/publish`,
    zIgnored,
    { version_ids: devVersions },
  );

  // Production carries its own material, so the protected-environment flow
  // stands on its own rather than on whatever an earlier test copied there.
  // Seeded BEFORE the protected flag is set, because a protected destination
  // is exactly what the ceremony gates.
  const prodVersions: string[] = [];
  for (const [name, value] of [
    ['DB_PASSWORD', 'hunter2-production'],
    ['STRIPE_SECRET_KEY', 'sk_live_production'],
    ['ROTATE_ME', 'rotate-me-production'],
    ['LOG_LEVEL', 'warn'],
  ] as const) {
    const staged = await call(
      token,
      'PUT',
      `/api/v1/orgs/${org}/projects/${project}/environments/${prod}/values/${name}`,
      zStaged,
      { value },
    );
    prodVersions.push(staged.version_id);
  }
  await call(
    token,
    'POST',
    `/api/v1/orgs/${org}/projects/${project}/environments/${prod}/publish`,
    zIgnored,
    { version_ids: prodVersions },
  );

  // Development gets an explicit sliding window. The INSTANCE default is 0 —
  // fail-closed, and the concrete default is the operations spec's to fix — so
  // without this every environment would take a ceremony per disclosure and
  // the sliding half of the guard would have no subject.
  await call(
    token,
    'PUT',
    `/api/v1/orgs/${org}/projects/${project}/environments/${dev}/settings`,
    zIgnored,
    { protected: false, reauth_window_seconds: 300 },
  );

  // Production is protected, which caps its window at 0 — the state the
  // "WebAuthn per disclosure, TOTP refused" criterion is about.
  await call(
    token,
    'PUT',
    `/api/v1/orgs/${org}/projects/${project}/environments/${prod}/settings`,
    zIgnored,
    { protected: true },
  );

  return {
    org,
    project,
    dev,
    prod,
    secrets,
    rotatable,
    config,
    token,
    principal,
    otpauth: uri,
    lastTotpStep: lastStep,
    machine: MACHINE,
  };
}
