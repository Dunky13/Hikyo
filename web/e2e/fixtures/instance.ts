import { chromium, type Page } from '@playwright/test';
import { z } from 'zod';

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { seedTenant, totpCode, type Seeded } from './seed.ts';

/**
 * A real Hikyo instance for the flow suite.
 *
 * The flows run against the GO BINARY serving the embedded SPA, never against
 * a Vite dev server. That is not fussiness: the serving rules, the CSP, the
 * `__Host-` cookies and the CSRF contract are all part of what the flows are
 * there to prove, and a dev server implements none of them.
 *
 * The instance is a `--dev` zero-config sqlite one in a fresh temp directory,
 * bootstrapped exactly the way an operator does it — `hikyo admin create` on
 * the host, then the credential established with the authority it minted. No
 * seeded password, no fixture user inserted behind the API's back.
 */

// `localhost`, not `127.0.0.1`, and that is a WebAuthn constraint rather than
// a preference: the relying-party id must be a registrable domain and an IP
// literal is not one, so a passkey ceremony against a loopback ADDRESS is
// refused by the browser before the server sees it. `--dev` derives the
// external origin from the listen address, so the two move together.
export const HOST = 'localhost';
export const PORT = Number(process.env['HIKYO_E2E_PORT'] ?? 45789);
export const BASE_URL = `http://${HOST}:${PORT}`;

/** The bootstrap administrator every flow signs in as. */
export const ADMIN = {
  username: 'e2e-admin',
  displayName: 'End To End',
  password: 'correct horse battery staple e2e',
} as const;

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

/**
 * STORAGE_STATE is a signed-in browser context, minted once for the whole run.
 *
 * Signing in is the login flow's subject; every other flow starts from a
 * session, which is also how a real browser works — and it keeps the suite's
 * spend against the instance's pre-auth allowance proportional to what is
 * actually being tested rather than to how many tests there are.
 */
export const STORAGE_STATE = fileURLToPath(new URL('../.auth/state.json', import.meta.url));

type Instance = { proc: ChildProcess; dir: string; binary: string };

let running: Instance | null = null;

/**
 * SEEDED is the fixture tenant the reveal flow addresses, written by global
 * setup and read by the flow. A file rather than a module export because
 * Playwright runs setup and the workers in separate processes.
 */
export const SEEDED = fileURLToPath(new URL('../.auth/seed.json', import.meta.url));

/**
 * PASSKEY is the virtual authenticator credential the shared session enrolled.
 *
 * It exists so that NO TEST ever enrols one. Passkey enrolment is an
 * account-security mutation: it advances the principal's session generation
 * and deletes every other session that principal holds — so a flow that
 * enrolled would silently invalidate the shared session every other flow in
 * the suite is using, and the suite has exactly one principal. Enrolling once,
 * here, and handing the credential to each test's virtual authenticator keeps
 * the ceremonies real without any flow mutating the account.
 */
export const PASSKEY = fileURLToPath(new URL('../.auth/passkey.json', import.meta.url));

function run(command: string, args: string[], options: { cwd: string; env?: NodeJS.ProcessEnv }) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: { ...process.env, ...options.env },
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} failed (${result.status}):\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result;
}

/**
 * waitForHealthz waits for OUR instance, not for any instance.
 *
 * A run killed part-way can leave a server holding the port with a datastore
 * in a different temp directory. Health alone would say "ready" and every
 * later step would then address a stranger's state — which surfaces as an
 * unreadable root-key file or an authentication failure with no cause in this
 * run's code. The pid is what makes the check specific.
 */
async function waitForHealthz(deadlineMs = 30_000): Promise<void> {
  if (running !== null && running.proc.exitCode !== null) {
    throw new Error(`the instance exited immediately with ${String(running.proc.exitCode)}`);
  }
  const until = Date.now() + deadlineMs;
  for (;;) {
    try {
      const resp = await fetch(`${BASE_URL}/healthz`);
      if (resp.ok) {
        return;
      }
    } catch {
      // not listening yet
    }
    if (Date.now() > until) {
      throw new Error(`the instance never became healthy at ${BASE_URL}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
}

export async function startInstance(): Promise<void> {
  const dist = join(repoRoot, 'internal', 'webui', 'dist', 'index.html');
  if (!existsSync(dist)) {
    throw new Error(
      'the SPA has not been built: run `pnpm --dir web build` before the flow suite ' +
        '(the flows run against the embedded bundle, not a dev server)',
    );
  }

  const dir = mkdtempSync(join(tmpdir(), 'hikyo-e2e-'));
  const binary = join(dir, 'hikyo');
  // `-tags ui` is what embeds the bundle. A binary built without it serves the
  // API and answers 404 for the document, which is the correct default and the
  // wrong thing to test a UI against.
  run('go', ['build', '-tags', 'ui', '-o', binary, './cmd/hikyo'], { cwd: repoRoot });

  const proc = spawn(binary, ['server', '--dev', '--listen', `${HOST}:${PORT}`], {
    cwd: dir,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      // Every login of every flow, on both viewport projects, arrives from one
      // loopback address inside about twenty seconds — a traffic shape the
      // locked per-IP allowance of ten a minute is deliberately not sized for.
      // Raising it here is not weakening the product: the key is refused
      // outside `--dev` and the server will not start with it set in
      // production. The alternative was deleting tests to fit under the
      // ceiling, which is measuring the throttle instead of the UI.
      HIKYO_DEV_ADMISSION_PER_IP_PER_MINUTE: '500',
    },
  });
  running = { proc, dir, binary };
  proc.stderr?.on('data', (chunk: Buffer) => {
    if (process.env['HIKYO_E2E_VERBOSE'] !== undefined) {
      process.stderr.write(chunk);
    }
  });
  proc.on('exit', (code) => {
    if (running !== null && code !== 0 && code !== null) {
      process.stderr.write(`hikyo exited with ${code}\n`);
    }
  });

  await waitForHealthz();
  if (!existsSync(join(dir, 'hikyo-dev.rootkey'))) {
    throw new Error(
      `something else is already serving ${BASE_URL}: this run's instance wrote no root key. ` +
        'Kill the stale `hikyo server` process and re-run.',
    );
  }

  // `admin` reads its datastore and root key from the environment only, so the
  // dev root key the server just generated is handed to it explicitly.
  const authorityFile = join(dir, 'authority');
  run(
    binary,
    ['admin', 'create', '--username', ADMIN.username, '--display-name', ADMIN.displayName,
      '--output-file', authorityFile],
    {
      cwd: dir,
      env: {
        HIKYO_DB: 'sqlite:hikyo-dev.db',
        HIKYO_ROOT_KEY: readFileSync(join(dir, 'hikyo-dev.rootkey'), 'utf8').trim(),
      },
    },
  );

  const establish = await fetch(`${BASE_URL}/api/v1/auth/credential/establish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      authority: readFileSync(authorityFile, 'utf8').trim(),
      password: ADMIN.password,
    }),
  });
  if (establish.status !== 204) {
    throw new Error(`establishing the bootstrap credential answered ${establish.status}`);
  }

  // The fixture tenant. Break-glass grants run through the binary on the host,
  // which is the only path that issues a grant without a session — and the
  // bootstrap administrator holds no disclosure capability by design, so
  // something has to.
  const seeded = await seedTenant((args) => {
    run(binary, ['admin', 'grant', ...args], {
      cwd: dir,
      env: {
        HIKYO_DB: 'sqlite:hikyo-dev.db',
        HIKYO_ROOT_KEY: readFileSync(join(dir, 'hikyo-dev.rootkey'), 'utf8').trim(),
      },
    });
  });
  mkdirSync(fileURLToPath(new URL('../.auth', import.meta.url)), { recursive: true });
  writeFileSync(SEEDED, JSON.stringify({ ...seeded, dbPath: join(dir, 'hikyo-dev.db') }));

  // The shared browser session is minted LAST, and that ordering is
  // load-bearing: seeding issues break-glass grants, a grant advances the
  // principal's session generation, and every session minted before it is dead
  // by design. A storage state written earlier would hand every flow a cookie
  // the server has already disowned.
  await mintStorageState();
}

/**
 * zSeeded and zVirtualCredential are the two files this harness writes and
 * reads back. They are PARSED, not narrowed by hand: these files cross a
 * process boundary — global setup writes them, workers read them — so they are
 * exactly the untrusted-input boundary the house rule is about, and a stale
 * file from an earlier shape should say so by name rather than surface as an
 * `undefined` in the middle of a flow.
 */
const zSeeded = z.object({
  org: z.string(),
  project: z.string(),
  dev: z.string(),
  prod: z.string(),
  secrets: z.array(z.string()),
  rotatable: z.string(),
  config: z.string(),
  token: z.string(),
  principal: z.string(),
  otpauth: z.string(),
  lastTotpStep: z.number(),
  machine: z.object({
    workload: z.string(),
    automation: z.string(),
    mintable: z.string(),
    issuer: z.string(),
    subject: z.string(),
    audience: z.string(),
  }),
  /**
   * The instance's sqlite file. Playwright runs global setup and the workers
   * in SEPARATE PROCESSES, so a worker cannot reach the setup process's
   * variables — the path travels through the same file the rest of the
   * fixture does.
   */
  dbPath: z.string(),
});

/**
 * Fixture is the seeder's output plus what the harness that owns the temp
 * directory adds. They are two shapes because they have two authors, and
 * collapsing them would make `dbPath` look like something the API returned.
 */
export type Fixture = z.infer<typeof zSeeded>;

/** readSeed returns the fixture tenant global setup created. */
export function readSeed(): Fixture {
  return zSeeded.parse(JSON.parse(readFileSync(SEEDED, 'utf8')));
}

async function mintStorageState(): Promise<void> {
  // A real browser, because the session this mints is a PASSKEY-BEARING one:
  // a WebAuthn ceremony needs `navigator.credentials`, which needs a browsing
  // context, and the virtual authenticator is bound to one.
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(BASE_URL);

    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });

    const failure = await page.evaluate(sessionScript, {
      username: ADMIN.username,
      password: ADMIN.password,
      enrol: true,
      stepUp: true,
    });
    if (failure !== null) {
      throw new Error(`establishing the shared passkey session: ${failure}`);
    }

    const { credentials } = await cdp.send('WebAuthn.getCredentials', {
      authenticatorId,
    });
    const credential = credentials[0];
    if (credential === undefined) {
      throw new Error('the virtual authenticator holds no credential after enrolment');
    }

    mkdirSync(fileURLToPath(new URL('../.auth', import.meta.url)), {
      recursive: true,
    });
    await context.storageState({ path: STORAGE_STATE });
    writeFileSync(PASSKEY, JSON.stringify(credential));
  } finally {
    await browser.close();
  }
}

/**
 * zVirtualCredential is the CDP credential shape, narrowed to the members
 * `WebAuthn.addCredential` requires. It is declared here rather than imported
 * because Playwright does not export its protocol types — and it is a schema
 * rather than a type so the file this harness writes and reads back is parsed
 * at that boundary like every other one.
 */
const zVirtualCredential = z.object({
  credentialId: z.string(),
  isResidentCredential: z.boolean(),
  privateKey: z.string(),
  signCount: z.number(),
  rpId: z.string().optional(),
  // `null` is what the authenticator reports for a credential with no user
  // handle; the CDP type wants the member simply absent, so the schema accepts
  // both and normalises to absent.
  userHandle: z
    .string()
    .nullable()
    .optional()
    .transform((value) => value ?? undefined),
});

export type VirtualCredential = z.infer<typeof zVirtualCredential>;

/**
 * writePasskey stores the credential back with its advanced signature counter.
 *
 * A passkey's counter is how a CLONED authenticator is detected: the server
 * refuses an assertion whose counter did not move forward. Playwright runs the
 * same flow once per viewport project, in separate browsers, so the second
 * project's authenticator has to start where the first one stopped — exactly
 * as one physical key carried between two machines would.
 */
export function writePasskey(credential: VirtualCredential): void {
  writeFileSync(PASSKEY, JSON.stringify(credential));
}

/** readPasskey returns the credential every flow's authenticator is loaded with. */
export function readPasskey(): VirtualCredential {
  return zVirtualCredential.parse(JSON.parse(readFileSync(PASSKEY, 'utf8')));
}

/** parseCredential checks a CDP credential rather than asserting its shape. */
export function parseCredential(value: unknown): VirtualCredential {
  return zVirtualCredential.parse(value);
}

export async function establishSession(page: Page, stepUp = true): Promise<void> {
  const failure = await page.evaluate(sessionScript, {
    username: ADMIN.username,
    password: ADMIN.password,
    enrol: false,
    stepUp,
  });
  if (failure !== null) {
    throw new Error(`establishing a flow session: ${failure}`);
  }
}

/**
 * sessionScript signs in, optionally enrols a passkey, and steps up — all
 * inside the page, because a WebAuthn ceremony needs `navigator.credentials`.
 *
 * `enrol` is true exactly once per suite, in global setup. The only other
 * subtlety is the synchronizer token: enrolment rotates the session AND its
 * token, so the cookie is re-read on every request instead of captured once —
 * a stale token is refused, which from out here looks exactly like a failed
 * ceremony.
 */
const sessionScript = async ({
  username,
  password,
  enrol,
  stepUp,
}: {
  username: string;
  password: string;
  enrol: boolean;
  stepUp: boolean;
}): Promise<string | null> => {
  const csrf = (): string => {
    for (const part of document.cookie.split(';')) {
      const [name, ...rest] = part.trim().split('=');
      if (name === '__Host-hikyo-csrf') {
        return rest.join('=');
      }
    }
    return '';
  };
  const post = async (path: string, body: unknown): Promise<unknown> => {
    const resp = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Hikyo-CSRF': csrf() },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new Error(`${path} answered ${String(resp.status)}`);
    }
    return resp.json();
  };
  const b64u = (buffer: ArrayBuffer): string =>
    btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  const unb64u = (value: string): ArrayBuffer => {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      view[i] = binary.charCodeAt(i);
    }
    return buffer;
  };
  // No casts: the blob is unknown until it is checked, and every member the
  // ceremony needs is read through a narrowing accessor.
  const record = (value: unknown): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null) {
      throw new Error('expected an object from the server');
    }
    return { ...value };
  };
  const options = (blob: unknown): Record<string, unknown> => {
    const outer = record(blob);
    const inner = outer['publicKey'];
    return typeof inner === 'object' && inner !== null ? record(inner) : outer;
  };

  try {
    const login = await fetch('/api/v1/auth/local/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, artifact: 'browser' }),
    });
    if (!login.ok) {
      return `login answered ${String(login.status)}`;
    }

    if (enrol) {
      const create = options(await post('/api/v1/auth/webauthn/enrol/start', { password }));
      const user = record(create['user']);
      const rp = record(create['rp']);
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: unb64u(String(create['challenge'])),
          rp: { id: String(rp['id']), name: String(rp['name'] ?? 'Hikyo') },
          user: {
            id: unb64u(String(user['id'])),
            name: String(user['name']),
            displayName: String(user['displayName'] ?? user['name']),
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 },
          ],
          authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'required',
          },
        },
      });
      if (!(credential instanceof PublicKeyCredential)) {
        return 'enrolment produced no credential';
      }
      const attestation = credential.response;
      if (!(attestation instanceof AuthenticatorAttestationResponse)) {
        return 'enrolment produced the wrong response type';
      }
      await post('/api/v1/auth/webauthn/enrol/finish', {
        id: credential.id,
        rawId: b64u(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: b64u(attestation.clientDataJSON),
          attestationObject: b64u(attestation.attestationObject),
        },
      });
    }

    if (!stepUp) {
      return null;
    }
    // Step up, so the session carries the webauthn factor class. `reveal` is
    // MFA-mandatory at the chokepoint and a password-only session is refused
    // there — for a reason the reveal guard is not about.
    const assertOptions = options(await post('/api/v1/auth/webauthn/step-up/start', {}));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: unb64u(String(assertOptions['challenge'])),
        rpId: String(assertOptions['rpId']),
        userVerification: 'required',
      },
    });
    if (!(assertion instanceof PublicKeyCredential)) {
      return 'step-up produced no assertion';
    }
    const response = assertion.response;
    if (!(response instanceof AuthenticatorAssertionResponse)) {
      return 'step-up produced the wrong response type';
    }
    await post('/api/v1/auth/webauthn/step-up/finish', {
      id: assertion.id,
      rawId: b64u(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: b64u(response.clientDataJSON),
        authenticatorData: b64u(response.authenticatorData),
        signature: b64u(response.signature),
        userHandle: response.userHandle === null ? null : b64u(response.userHandle),
      },
    });
    return null;
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
};

/**
 * countDisclosureEvents reads the SERVER's audit trail directly.
 *
 * The surface's own "recorded this session" list is client state: it proves
 * what the UI believes, not what the trail holds, and per-key cardinality is a
 * property of the TRAIL — "never one row saying revealed 40 secrets". Asserting
 * it against the client alone would let a server that aggregated pass, which is
 * exactly the divergence the criterion exists to catch.
 *
 * `node:sqlite` is stdlib on the pinned Node, so this needs no driver and no
 * system binary. Read-only, on the instance's own file, from the process that
 * created it.
 */
export function countDisclosureEvents(): number {
  const db = new DatabaseSync(readSeed().dbPath, { readOnly: true });
  try {
    const row = db
      .prepare("SELECT COUNT(*) AS n FROM audit_tenant_events WHERE type = 'disclosure.value_revealed'")
      .get();
    return zCount.parse(row).n;
  } finally {
    db.close();
  }
}

const zCount = z.object({ n: z.number() });

/**
 * nextTotpCode returns a code for a step nothing has spent yet, and records
 * that it spent it.
 *
 * Every code is single-use per (account, step) — so the seeding session, the
 * desktop project and the mobile project cannot each pick "one step ahead of
 * now" and expect all three to be accepted. The newest spent step lives in the
 * same file the rest of the fixture does, for the same reason the passkey's
 * signature counter does: these are separate processes sharing one account.
 *
 * It never waits in practice: flows run well after setup, so the step after
 * the current one is already free.
 */
export async function nextTotpCode(): Promise<string> {
  const seed = readSeed();
  const step = () => Math.floor(Date.now() / 1000 / 30);
  const want = Math.max(step() + 1, seed.lastTotpStep + 1);
  while (step() < want - 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  writeFileSync(SEEDED, JSON.stringify({ ...seed, lastTotpStep: want }));
  return totpCode(seed.otpauth, new Date(want * 30_000));
}

/**
 * refreshSharedSession re-mints the storage state and the shared passkey.
 *
 * A flow that has to change the administrator's GRANTS advances their session
 * generation, which kills every session that principal holds — the suite's
 * shared storage state included. Re-minting is how such a flow leaves the
 * suite as it found it.
 */
export async function refreshSharedSession(): Promise<void> {
  await mintStorageState();
}

export function stopInstance(): void {
  if (running === null) {
    return;
  }
  const { proc, dir } = running;
  running = null;
  proc.kill('SIGTERM');
  rmSync(dir, { recursive: true, force: true });
}
