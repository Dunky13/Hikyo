import { chromium, type Page } from '@playwright/test';
import { z, type ZodType } from 'zod';

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer, type Server } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { seedTenant, totpCode } from './seed.ts';

/**
 * TWO real Hikyo instances for the flow suite.
 *
 * The flows run against the GO BINARY serving the embedded SPA, never against
 * a Vite dev server. That is not fussiness: the serving rules, the CSP, the
 * `__Host-` cookies, the CORS echo and the CSRF contract are all part of what
 * the flows are there to prove, and a dev server implements none of them.
 *
 * Both instances are `--dev` zero-config sqlite ones in fresh temp directories,
 * bootstrapped exactly the way an operator does it — `hikyo admin create` on the
 * host, then the credential established with the authority it minted. No seeded
 * password, no fixture user inserted behind the API's back, and no assurance
 * handed out that was not demonstrated: every instance-scope surface is
 * MFA-mandatory, so a password-only session could not open the remotes page at
 * all.
 *
 * ## Why two hosts and not two ports
 *
 * A(viewing) is `http://localhost:PORT_A` and B(serving) is
 * `http://127.0.0.1:PORT_B`, and the differing HOSTNAME is load-bearing:
 * cookies are not partitioned by port, so two instances on one hostname would
 * share `__Host-hikyo` and B's login would silently destroy A's session. Two
 * loopback names are two cookie jars, two origins, and a real cross-origin arc.
 *
 * WHICH name goes where is not free, and it is a WebAuthn constraint rather
 * than a preference: the relying-party id must be a registrable domain and an
 * IP literal is not one, so a passkey ceremony against a loopback ADDRESS is
 * refused by the browser before the server sees it. A is where the shared
 * passkey session lives and where the reveal flow's ceremonies run, so A takes
 * `localhost`. B authenticates with a password and a real TOTP factor only, so
 * the address literal is fine there.
 *
 * ## Why the browser leg is http (decision, #71)
 *
 * `service.CanonicalOrigin` accepts http so a loopback ORIGIN is representable
 * as an allowlist entry, while `remotefetch.ValidateRemoteURL` refuses plaintext
 * so a REMOTE URL never is. That asymmetry is deliberate in the product and the
 * harness leans on it: what the browser leg proves — popup on the remote's
 * origin, CORS, `noopener` + BroadcastChannel, header-borne bearer, the kill
 * switch — is ORIGIN-shaped, not pin-shaped, so http loopback exercises it
 * honestly and no certificate exception is needed anywhere. The pinned TLS half
 * is proven where it belongs, in `internal/isolation/two_instance_test.go`,
 * against two real routers over real TLS.
 *
 * The one seam that falls out of that decision is `repointRemoteAtB` below: an
 * entry can only be CREATED over https (correctly), so it is created through the
 * real API against a pinned TLS front that proxies B's own directory, and then
 * repointed at B's loopback http origin for the browser leg. The credential is
 * really sealed, the snapshot is really B's, and the card lands in the
 * `unreachable — last known` state, which is itself one of the states the
 * directory card owes a human.
 */

export const HOST = 'localhost';
export const PORT = Number(process.env['HIKYO_E2E_PORT'] ?? 45789);
export const BASE_URL = `http://${HOST}:${PORT}`;

/** The serving instance: a different loopback NAME, hence a different origin. */
export const HOST_B = '127.0.0.1';
export const PORT_B = Number(process.env['HIKYO_E2E_PORT_B'] ?? 45790);
export const BASE_URL_B = `http://${HOST_B}:${PORT_B}`;

/** The TLS front that exists only so `remote add` can be performed for real. */
const PORT_TLS = Number(process.env['HIKYO_E2E_PORT_TLS'] ?? 45791);

/** The name the viewing instance knows the serving instance by. */
export const REMOTE_NAME = 'peer-b';

/** The bootstrap administrator every flow signs in as, on both instances. */
export const ADMIN = {
  username: 'e2e-admin',
  displayName: 'End To End',
  password: 'correct horse battery staple e2e',
} as const;

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

/**
 * STORAGE_STATE is a signed-in browser context for BOTH instances, minted once
 * for the whole run.
 *
 * Signing in is the login flow's subject; every other flow starts from a
 * session, which is also how a real browser works — and it keeps the suite's
 * spend against each instance's pre-auth allowance proportional to what is
 * actually being tested rather than to how many tests there are.
 */
export const STORAGE_STATE = fileURLToPath(new URL('../.auth/state.json', import.meta.url));

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
 * the suite is using, and the suite has exactly one principal per instance.
 * Enrolling once, here, and handing the credential to each test's virtual
 * authenticator keeps the ceremonies real without any flow mutating the
 * account.
 */
export const PASSKEY = fileURLToPath(new URL('../.auth/passkey.json', import.meta.url));

type Instance = {
  proc: ChildProcess;
  dir: string;
  binary: string;
  base: string;
  host: string;
  cookies: Cookie[];
  /** Set before a deliberate kill so the death-report handler stays quiet. */
  expectedExit?: boolean;
};

type Cookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax';
};

let instances: Instance[] = [];
let tlsFront: Server | null = null;

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
 * run's code. The process's own exit is what makes the wait specific; the
 * root-key file written into THIS instance's directory is what makes the
 * answer specific.
 */
async function waitForHealthz(instance: Instance, deadlineMs = 30_000): Promise<void> {
  const until = Date.now() + deadlineMs;
  for (;;) {
    if (instance.proc.exitCode !== null) {
      throw new Error(`the instance exited immediately with ${String(instance.proc.exitCode)}`);
    }
    try {
      const resp = await fetch(`${instance.base}/healthz`);
      if (resp.ok) {
        break;
      }
    } catch {
      // not listening yet
    }
    if (Date.now() > until) {
      throw new Error(`the instance never became healthy at ${instance.base}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  if (!existsSync(join(instance.dir, 'hikyo-dev.rootkey'))) {
    throw new Error(
      `something else is already serving ${instance.base}: this run's instance wrote no root key. ` +
        'Kill the stale `hikyo server` process and re-run.',
    );
  }
}

/** cookieHeader renders one instance's jar for a raw fetch. */
function cookieHeader(instance: Instance): string {
  return instance.cookies.map((c) => `${c.name}=${c.value}`).join('; ');
}

function csrfToken(instance: Instance): string {
  const token = instance.cookies.find((cookie) => cookie.name === '__Host-hikyo-csrf')?.value;
  if (token === undefined || token === '') {
    throw new Error('the fixture instance has no CSRF cookie');
  }
  return token;
}

/**
 * api is an authenticated call as the instance's administrator, with the
 * synchronizer token echoed exactly as the SPA echoes it. It is used for the
 * setup a flow is not about — minting a connection credential, adding the
 * entry — never for anything a flow claims to prove.
 */
async function api(
  instance: Instance,
  method: string,
  path: string,
  body?: unknown,
): Promise<unknown> {
  const resp = await fetch(instance.base + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookieHeader(instance),
      'X-Hikyo-CSRF': csrfToken(instance),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(
      `${method} ${path} on ${instance.base} answered ${resp.status}: ${await resp.text()}`,
    );
  }
  // Several account-security mutations REISSUE the session — the TOTP family
  // rotates the verifier — so the jar is refreshed from every response that
  // carries one. Holding the pre-call cookies made the very next request
  // answer `unauthenticated`, which reads exactly like a wrong code and is not.
  adoptCookies(instance, resp);
  if (process.env['HIKYO_E2E_VERBOSE'] !== undefined) {
    process.stderr.write(
      `DEBUG ${method} ${path} set-cookie=${JSON.stringify(resp.headers.getSetCookie())}\n`,
    );
  }
  return resp.status === 204 ? null : await resp.json();
}

/**
 * adoptCookies MERGES whatever a response reissued into the jar, by name.
 *
 * By name and not wholesale: a reissue may set the session cookie alone, and a
 * jar replaced with that one cookie loses the synchronizer token, which then
 * fails the NEXT mutation with a refusal that looks nothing like its cause.
 */
function adoptCookies(instance: Instance, resp: Response): void {
  const reissued = parseSetCookie(resp.headers.getSetCookie(), instance.host);
  if (reissued.length === 0) {
    return;
  }
  const jar = new Map(instance.cookies.map((c) => [c.name, c]));
  for (const cookie of reissued) {
    jar.set(cookie.name, cookie);
  }
  instance.cookies = [...jar.values()];
}

function parseSetCookie(raw: string[], host: string): Cookie[] {
  return raw.map((line) => {
    const [pair = ''] = line.split(';');
    const [name = '', ...value] = pair.split('=');
    return {
      name,
      value: value.join('='),
      domain: host,
      path: '/',
      expires: -1,
      httpOnly: /httponly/i.test(line),
      secure: /secure/i.test(line),
      sameSite: /samesite=strict/i.test(line) ? ('Strict' as const) : ('Lax' as const),
    };
  });
}

/** signIn mints a browser session the same way the SPA does. */
async function signIn(instance: Instance): Promise<void> {
  const resp = await fetch(`${instance.base}/api/v1/auth/local/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: ADMIN.username,
      password: ADMIN.password,
      artifact: 'browser',
    }),
  });
  if (!resp.ok) {
    throw new Error(`signing in at ${instance.base} answered ${resp.status}`);
  }
  const cookies = parseSetCookie(resp.headers.getSetCookie(), instance.host);
  if (cookies.length !== 2) {
    throw new Error(`the login set ${cookies.length} cookies, want the session and CSRF pair`);
  }
  instance.cookies = cookies;
}

/**
 * enrolTotp gives the serving instance's administrator a real second factor.
 *
 * Only B needs this. A's administrator is enrolled by `seedTenant`, whose
 * provisioning URI and spent-step bookkeeping travel to the workers in the
 * SEEDED file — enrolling a second time here would rotate the secret out from
 * under `nextTotpCode` and stale every flow that uses it.
 *
 * Every instance-scope capability is MFA-mandatory, so without this the setup
 * would be testing the refusal rather than the surface.
 */
async function enrolTotp(instance: Instance): Promise<string> {
  const started = await api(instance, 'POST', '/api/v1/auth/totp/enrol/start', {
    password: ADMIN.password,
  });
  if (typeof started !== 'object' || started === null || !('otpauth_uri' in started)) {
    throw new Error('TOTP enrolment did not disclose an otpauth URI');
  }
  const uri = started.otpauth_uri;
  if (typeof uri !== 'string') {
    throw new Error('the otpauth URI is not a string');
  }
  await presentTotp(instance, uri, '/api/v1/auth/totp/enrol/confirm');
  return uri;
}

/**
 * presentTotp posts a TOTP code, after waiting for a step the server has not
 * already consumed.
 *
 * TRAP, recorded because it cost real time. A code is single-use PER STEP —
 * `last_step < ?`, strictly — and the validation window is only +/-1 step wide,
 * so two ceremonies inside the same 30 seconds have NO code that is both fresh
 * and acceptable. The server names that case (409, "already used for its time
 * step") rather than answering the uniform `unauthenticated`; a wrong code is
 * still a 401, and the two implementations generate identical codes for
 * identical instants (checked against `pquerna/otp` directly).
 *
 * So every presentation waits for the step counter to advance and then sends
 * the code for NOW. That is deterministic — one request, no failed attempts to
 * feed the per-account backoff — at the cost of up to 30 seconds per ceremony.
 */
async function presentTotp(instance: Instance, otpauth: string, path: string): Promise<void> {
  const deadline = Date.now() + 3 * TOTP_PERIOD * 1000;
  let last = '';
  for (;;) {
    for (const steps of [0, 1, 2]) {
      const code = totpCode(otpauth, new Date(Date.now() + steps * TOTP_PERIOD * 1000));
      const resp = await fetch(instance.base + path, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookieHeader(instance),
          'X-Hikyo-CSRF': csrfToken(instance),
        },
        body: JSON.stringify({ code }),
      });
      if (resp.ok) {
        adoptCookies(instance, resp);
        return;
      }
      last = `${resp.status}: ${await resp.text()}`;
      // 409 is the server naming a REPLAY: the code's step was already
      // consumed by an earlier ceremony in this same 30-second window. That is
      // the one refusal worth waiting out; everything else is a real fault.
      if (resp.status === 409 && last.includes('already used for its time step')) {
        break;
      }
      if (resp.status !== 401) {
        throw new Error(`${path} at ${instance.base} answered ${last}`);
      }
    }
    if (Date.now() > deadline) {
      throw new Error(`no TOTP code was accepted for ${path} at ${instance.base}; last ${last}`);
    }
    await waitForNextStep();
  }
}

/** The server's TOTP step, in seconds. `seed.ts`'s generator assumes the same. */
const TOTP_PERIOD = 30;

/** waitForNextStep sleeps until the TOTP step counter has advanced. */
async function waitForNextStep(): Promise<void> {
  const step = () => Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  const from = step();
  while (step() <= from) {
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

/** portTaken reports whether anything accepts a connection on host:port. */
function portTaken(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host, port });
    const done = (taken: boolean) => {
      socket.destroy();
      resolve(taken);
    };
    socket.setTimeout(1000);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

/**
 * startInstanceAt brings up one instance and establishes its bootstrap
 * credential. It stops there: what each instance needs NEXT differs (A is
 * seeded and takes a passkey, B enrols TOTP), and folding both into one
 * function would mean a flag deciding half the body.
 */
async function startInstanceAt(host: string, port: number, base: string): Promise<Instance> {
  // Fail loud on a squatter. A previous run killed mid-flight (a timeout, a
  // ^C) leaves a server on this port with ANOTHER datastore behind it, and the
  // health probe below cannot tell the difference — the bootstrap then writes
  // to a database nobody is serving and the first authenticated call answers
  // 401, which reads like a credential bug and is not.
  //
  // A raw TCP connect rather than a fetch: `fetch` to a closed port rejects
  // with an opaque `TypeError: fetch failed` that is easy to swallow in the
  // wrong place, and "is the port taken" is a question about the socket.
  if (await portTaken(host, port)) {
    throw new Error(
      `something is already listening on ${host}:${port}. A previous flow run was killed ` +
        `without teardown; stop it before running the suite again.`,
    );
  }

  const dir = mkdtempSync(join(tmpdir(), 'hikyo-e2e-'));
  const prebuiltBinary = process.env.HIKYO_E2E_BINARY;
  const binary = prebuiltBinary ?? join(dir, 'hikyo');
  // `-tags ui` is what embeds the bundle. A binary built without it serves the
  // API and answers 404 for the document, which is the correct default and the
  // wrong thing to test a UI against. CI supplies the exact app-build artifact
  // once for both isolated instances; local runs retain the self-contained
  // source-build path. `admin` selects its datastore from cwd, not binary path.
  if (prebuiltBinary === undefined) {
    run('go', ['build', '-tags', 'ui', '-o', binary, './cmd/hikyo'], { cwd: repoRoot });
  } else if (!existsSync(prebuiltBinary)) {
    throw new Error(`HIKYO_E2E_BINARY does not exist: ${prebuiltBinary}`);
  }

  const proc = spawn(binary, ['server', '--dev', '--listen', `${host}:${port}`], {
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
  const instance: Instance = { proc, dir, binary, base, host, cookies: [] };
  instances.push(instance);
  // The last 64 KiB of output is kept regardless of verbosity: when the server
  // dies unexpectedly mid-suite, the diagnosis lives in this buffer and nowhere
  // else — the suite has been killed by an undiagnosable ERR_CONNECTION_REFUSED
  // before. stdout gets the same treatment so a full pipe can never block the
  // server either.
  const tail: Buffer[] = [];
  let tailBytes = 0;
  const keep = (chunk: Buffer): void => {
    tail.push(chunk);
    tailBytes += chunk.length;
    while (tailBytes > 64 * 1024 && tail.length > 1) {
      tailBytes -= tail[0]!.length;
      tail.shift();
    }
  };
  proc.stdout?.on('data', keep);
  proc.stderr?.on('data', (chunk: Buffer) => {
    keep(chunk);
    if (process.env['HIKYO_E2E_VERBOSE'] !== undefined) {
      process.stderr.write(chunk);
    }
  });
  proc.on('exit', (code, signal) => {
    if (instance.expectedExit) {
      return;
    }
    process.stderr.write(
      `\ninstance at ${base} exited unexpectedly (code=${String(code)} signal=${String(signal)}); ` +
        `last output follows\n${Buffer.concat(tail).toString()}\n`,
    );
  });

  await waitForHealthz(instance);

  // `admin` reads its datastore and root key from the environment only, so the
  // dev root key the server just generated is handed to it explicitly.
  const authorityFile = join(dir, 'authority');
  run(
    binary,
    ['admin', 'create', '--username', ADMIN.username, '--display-name', ADMIN.displayName,
      '--output-file', authorityFile],
    { cwd: dir, env: adminEnv(instance) },
  );

  return instance;
}

/** adminEnv is what the `admin` verb needs to address this instance's store. */
function adminEnv(instance: Instance): NodeJS.ProcessEnv {
  return {
    HIKYO_DB: 'sqlite:hikyo-dev.db',
    HIKYO_ROOT_KEY: readFileSync(join(instance.dir, 'hikyo-dev.rootkey'), 'utf8').trim(),
  };
}

async function establishCredential(instance: Instance): Promise<void> {
  const establish = await fetch(`${instance.base}/api/v1/auth/credential/establish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      authority: readFileSync(join(instance.dir, 'authority'), 'utf8').trim(),
      password: ADMIN.password,
    }),
  });
  if (establish.status !== 204) {
    throw new Error(`establishing the bootstrap credential answered ${establish.status}`);
  }
}

/**
 * seedDirectoryGrant gives the bootstrap administrator `instance-directory`
 * before anyone signs in.
 *
 * A store-level seam, and it is here for a reason that is about the fixture
 * rather than the product. `instance-directory` is deliberately NOT in the
 * operator set — reading another installation's org and project names is its
 * own grantable power — so an operator really does have to grant it. Doing that
 * through the API is a three-ceremony detour: the grant surface is
 * MFA-mandatory, and granting to oneself invalidates one's own sessions, so the
 * fixture would have to enrol, step up, grant, sign in and step up again, at one
 * 30-second TOTP step boundary per ceremony. The grant surface is #55's to prove
 * and is proven there; what these flows are about starts after it.
 *
 * Written before the first sign-in on purpose: a grant that predates every
 * session cannot invalidate one.
 */
const DIRECTORY_GRANT_ID = 'grt_00000000-0000-7000-8000-00000000e2e1';
const DIRECTORY_ORIGIN_ID = 'gor_00000000-0000-7000-8000-00000000e2e2';
export const INSTANCE_GRANT_TARGET = 'usr_00000000-0000-7000-8000-00000000e2e3';

function seedDirectoryGrant(dir: string): void {
  const db = new DatabaseSync(join(dir, 'hikyo-dev.db'));
  try {
    const row = db.prepare(`SELECT id FROM principals WHERE kind = 'human' LIMIT 1`).get();
    const principal = row === undefined ? undefined : Object(row)['id'];
    if (typeof principal !== 'string') {
      throw new Error('no bootstrap principal to grant instance-directory to');
    }
    const at = new Date().toISOString().replace('Z', '000Z');
    // A non-login human target for the instance-grant flow. Machine
    // principals are intentionally invalid here: workloads require explicit
    // environment depth and automations require project depth. An account row
    // is unnecessary because this principal never authenticates; it only lets
    // the UI prove a valid create/revoke lifecycle without invalidating the
    // sole administrator's own session.
    db.prepare(
      `INSERT INTO principals (id, kind, created_at, session_generation, reconciled_epoch)
       VALUES (?, 'human', ?, 1, (SELECT restore_epoch FROM auth_instance_state WHERE id = 1))`,
    ).run(INSTANCE_GRANT_TARGET, at);
    // The ids obey the contract's ID grammar (`^[a-z]{2,8}_[0-9a-fA-F-]{36}$`),
    // and that is not cosmetics. Every listing that carries a grant row is
    // parsed against the generated schema at the SPA boundary, so a
    // hand-written id like `grn_e2e_directory` makes the whole instance-grant
    // listing fail to parse — which is the client being right and the fixture
    // being wrong. Fixed rather than accommodated (#60).
    db.prepare(
      `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at)
       VALUES (?, ?, 'instance-directory', NULL, NULL, NULL, ?)`,
    ).run(DIRECTORY_GRANT_ID, principal, at);
    // A grant row with no origin is the state the permission model forbids:
    // the membership surface INNER JOINs origins, so a grant nobody can point
    // at the reason for would simply not be seen.
    db.prepare(
      `INSERT INTO grant_origins (id, grant_id, kind, subject, created_at)
       VALUES (?, ?, 'manual', ?, ?)`,
    ).run(DIRECTORY_ORIGIN_ID, DIRECTORY_GRANT_ID, principal, at);
  } finally {
    db.close();
  }
}

/**
 * The serving instance's operable project (#71). A workspace can only be proven
 * to OPERATE a remote if the remote has something to operate — so B gets one
 * org, one project, one development environment and one CONFIG value (config is
 * delivered in plaintext, so the matrix renders it without a reveal ceremony,
 * which keeps this flow off the TOTP-in-a-popup path). Written to a file because
 * setup and the workers are separate processes.
 */
export const SERVING = fileURLToPath(new URL('../.auth/serving.json', import.meta.url));

const zServing = z.object({
  org: z.string(),
  project: z.string(),
  dev: z.string(),
  key: z.string(),
  value: z.string(),
  dbPath: z.string(),
});

export type ServingSeed = z.infer<typeof zServing>;

/** readServing returns the serving instance's operable-project fixture. */
export function readServing(): ServingSeed {
  return zServing.parse(JSON.parse(readFileSync(SERVING, 'utf8')));
}

/** servingPrincipal reads the bootstrap human's id from the serving store. */
function servingPrincipal(dir: string): string {
  const db = new DatabaseSync(join(dir, 'hikyo-dev.db'));
  try {
    const row = db.prepare(`SELECT id FROM principals WHERE kind = 'human' LIMIT 1`).get();
    const id = row === undefined ? undefined : Object(row)['id'];
    if (typeof id !== 'string') {
      throw new Error('no serving principal to grant capabilities to');
    }
    return id;
  } finally {
    db.close();
  }
}

/**
 * grantServingAdmin gives the serving instance's administrator the operating
 * capabilities a workspace exercises over there. Break-glass, at instance scope,
 * BEFORE the first sign-in — a grant that predates every session invalidates
 * none, which is the ordering rule the whole fixture obeys.
 */
function grantServingAdmin(serving: Instance): void {
  const principal = servingPrincipal(serving.dir);
  for (const capability of ['read', 'edit', 'publish', 'manage-projects', 'definitions-edit']) {
    run(serving.binary, ['admin', 'grant', '--principal', principal, '--capability', capability], {
      cwd: serving.dir,
      env: adminEnv(serving),
    });
  }
}

/**
 * grantServingOrgRead grants an ORG-scoped read so the org appears in the
 * serving admin's `listMyOrgs` — which is what the workspace project picker
 * reads. Instance-scoped grants operate the project but do not NAME an org, so
 * without this the picker would be empty even though every operation is allowed.
 * Break-glass, so it needs no session; it invalidates the one held, which the
 * caller re-establishes.
 */
function grantServingOrgRead(serving: Instance, org: string): void {
  run(
    serving.binary,
    ['admin', 'grant', '--principal', servingPrincipal(serving.dir), '--capability', 'read', '--org', org],
    { cwd: serving.dir, env: adminEnv(serving) },
  );
}

/**
 * seedServingProject creates the one operable project on the serving instance,
 * as its stepped-up administrator. Returns the ids the workspace flow navigates
 * by and the config value it asserts renders from the remote.
 */
async function seedServingProject(serving: Instance): Promise<Omit<ServingSeed, 'dbPath'>> {
  const zId = z.object({ id: z.string() });
  const created = async (path: string, body: unknown): Promise<string> =>
    zId.parse(await api(serving, 'POST', path, body)).id;

  const org = await created('/api/v1/orgs', { name: 'serving-co' });
  const project = await created(`/api/v1/orgs/${org}/projects`, { name: 'vault' });
  const dev = await created(`/api/v1/orgs/${org}/projects/${project}/environments`, {
    name: 'development',
  });
  await created(`/api/v1/orgs/${org}/projects/${project}/keys`, {
    name: 'API_URL',
    classification: 'config',
    folder_path: 'app',
    declaration: { rule: { type: 'string' } },
  });
  const value = 'https://seeded-on-b.example';
  const staged = z
    .object({ version_id: z.string() })
    .parse(
      await api(
        serving,
        'PUT',
        `/api/v1/orgs/${org}/projects/${project}/environments/${dev}/values/API_URL`,
        { value },
      ),
    );
  await api(serving, 'POST', `/api/v1/orgs/${org}/projects/${project}/environments/${dev}/publish`, {
    version_ids: [staged.version_id],
  });
  return { org, project, dev, key: 'API_URL', value };
}

/**
 * startTLSFront brings up the pinned https peer `remote add` is performed
 * against. It PROXIES B's own directory endpoint, so the snapshot the entry
 * stores is B's real listing rather than a fabricated one.
 *
 * The certificate is generated here and its SPKI fingerprint is what the entry
 * pins — the same construction the product uses, so the add ceremony is the
 * real one including pin verification. The front is bound to the loopback
 * ADDRESS regardless of which name A wears, because the certificate names it
 * and because the pin, not the name, is what the product verifies.
 */
function startTLSFront(dir: string): string {
  const key = join(dir, 'front.key');
  const cert = join(dir, 'front.crt');
  run('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
  ], { cwd: dir });

  const pem = readFileSync(cert, 'utf8');
  const spki = new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' });
  const pin = createHash('sha256').update(spki).digest('base64');

  tlsFront = createHttpsServer(
    { key: readFileSync(key), cert: readFileSync(cert) },
    (incoming, outgoing) => {
      const proxied = httpRequest(
        {
          host: HOST_B,
          port: PORT_B,
          path: incoming.url ?? '/',
          method: incoming.method ?? 'GET',
          headers: { ...incoming.headers, host: `${HOST_B}:${PORT_B}` },
        },
        (answer) => {
          outgoing.writeHead(answer.statusCode ?? 502, answer.headers);
          answer.pipe(outgoing);
        },
      );
      proxied.on('error', () => {
        outgoing.writeHead(502).end();
      });
      incoming.pipe(proxied);
    },
  );
  tlsFront.listen(PORT_TLS, TLS_FRONT_HOST);
  return pin;
}

const TLS_FRONT_HOST = '127.0.0.1';

/**
 * repointRemoteAtB rewrites the entry's URL to B's loopback http origin.
 *
 * THE ONLY OTHER store-level seam in this harness, and it is here because the
 * product is right and the harness is constrained: an entry may only be CREATED
 * over https, which it was, through the real API, against a real pin. What the
 * browser leg needs afterwards is B's real ORIGIN, and the workspace tier is
 * origin-shaped rather than pin-shaped. The card then renders the
 * `unreachable — last known` state honestly: the server genuinely cannot fetch
 * a plaintext URL, and the snapshot it shows is genuinely the last one it got.
 */
function repointRemoteAtB(instance: Instance): void {
  const db = new DatabaseSync(join(instance.dir, 'hikyo-dev.db'));
  try {
    db.prepare('UPDATE remotes SET url = ? WHERE name = ?').run(BASE_URL_B, REMOTE_NAME);
  } finally {
    db.close();
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

  // Concurrently, so the one unavoidable TOTP step-boundary wait is paid once
  // rather than once per instance.
  const [viewing, serving] = await Promise.all([
    startInstanceAt(HOST, PORT, BASE_URL),
    startInstanceAt(HOST_B, PORT_B, BASE_URL_B),
  ]);

  // Only the VIEWING instance needs `instance-directory`: it is the one that
  // reads a foreign directory. The serving side's work — minting a connection
  // credential, managing the origin allowlist — is `instance-config`, which the
  // bootstrap operator already holds.
  seedDirectoryGrant(viewing.dir);
  await Promise.all([establishCredential(viewing), establishCredential(serving)]);

  // The fixture tenant, on the VIEWING instance — the reveal flow's subject and
  // the instance every non-#71 flow addresses. Break-glass grants run through
  // the binary on the host, which is the only path that issues a grant without
  // a session, and the bootstrap administrator holds no disclosure capability
  // by design, so something has to. It also enrols the administrator's TOTP
  // factor, which is why nothing here enrols a second one.
  const seeded = await seedTenant((args) => {
    run(viewing.binary, ['admin', 'grant', ...args], {
      cwd: viewing.dir,
      env: adminEnv(viewing),
    });
  });
  mkdirSync(fileURLToPath(new URL('../.auth', import.meta.url)), { recursive: true });
  writeFileSync(SEEDED, JSON.stringify({ ...seeded, dbPath: join(viewing.dir, 'hikyo-dev.db') }));

  // The serving admin's operating capabilities, break-glass BEFORE any B
  // session, so no session is invalidated (#71). This is what lets a workspace
  // read and edit B's project once the human has authenticated over there.
  grantServingAdmin(serving);

  // B enrols its own factor: it has no seeded tenant and no passkey, and every
  // #71 act below it performs is instance-scope and therefore MFA-mandatory.
  await signIn(serving);
  const servingOtpauth = await enrolTotp(serving);
  // A fresh sign-in before the step-up: the enrolment's confirm REISSUES the
  // session, and re-presenting the credential is both cheaper to reason about
  // than tracking a rotation across two ceremonies and closer to what a human
  // does — enrol, then sign in again and present the new factor.
  await signIn(serving);
  await presentTotp(serving, servingOtpauth, '/api/v1/auth/totp/step-up');

  // The operable project on B, created by its now-stepped-up administrator, then
  // made visible to the project picker with an org-scoped read. That grant kills
  // B's session (it advances the principal's generation), so the 2-factor
  // session is re-established afterwards — the workspace inherits the factors the
  // approving B session holds, and edit/publish over there are MFA-mandatory.
  const serving_ = await seedServingProject(serving);
  grantServingOrgRead(serving, serving_.org);
  await signIn(serving);
  await presentTotp(serving, servingOtpauth, '/api/v1/auth/totp/step-up');
  writeFileSync(SERVING, JSON.stringify({ ...serving_, dbPath: join(serving.dir, 'hikyo-dev.db') }));

  // A's raw setup session, stepped up with the factor `seedTenant` enrolled.
  // `nextTotpCode` is what keeps the single-use-per-step bookkeeping honest
  // across this process and the workers.
  await signIn(viewing);
  await stepUpWithSeededTotp(viewing);

  // B mints the connection credential A will hold. Display-once: this response
  // is the only time the value exists outside a verifier.
  const minted = await api(serving, 'POST', '/api/v1/instance/connections', {
    label: 'viewing instance',
  });
  if (typeof minted !== 'object' || minted === null || !('value' in minted)) {
    throw new Error('minting a connection credential disclosed no value');
  }
  const credential = minted.value;
  if (typeof credential !== 'string') {
    throw new Error('the minted credential is not a string');
  }

  const pin = startTLSFront(viewing.dir);
  await api(viewing, 'POST', '/api/v1/instance/remotes', {
    name: REMOTE_NAME,
    url: `https://${TLS_FRONT_HOST}:${PORT_TLS}`,
    spki_pin: pin,
    credential,
  });
  repointRemoteAtB(viewing);

  // The shared browser session is minted LAST, and that ordering is
  // load-bearing: seeding issues break-glass grants, a grant advances the
  // principal's session generation, and every session minted before it is dead
  // by design. A storage state written earlier would hand every flow a cookie
  // the server has already disowned. It also carries B's jar, which the raw
  // setup above is the only thing that ever mints.
  await mintStorageState(serving.cookies);
}

/**
 * stepUpWithSeededTotp presents a code for a step nothing has spent, through
 * the browser-cookie surface rather than seed.ts's bearer one.
 */
async function stepUpWithSeededTotp(instance: Instance): Promise<void> {
  const resp = await fetch(`${instance.base}/api/v1/auth/totp/step-up`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookieHeader(instance),
      'X-Hikyo-CSRF': csrfToken(instance),
    },
    body: JSON.stringify({ code: await nextTotpCode() }),
  });
  if (!resp.ok) {
    throw new Error(`stepping up at ${instance.base} answered ${resp.status}`);
  }
  adoptCookies(instance, resp);
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
  orgName: z.string(),
  orgB: z.string(),
  orgBName: z.string(),
  project: z.string(),
  dev: z.string(),
  prod: z.string(),
  secrets: z.array(z.string()),
  rotatable: z.string(),
  config: z.string(),
  matrixRequired: z.string(),
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
  history: z.object({
    project: z.string(),
    dev: z.string(),
    staging: z.string(),
    configKey: z.string(),
    configKeyId: z.string(),
    secretKey: z.string(),
    secretKeyId: z.string(),
    secretValues: z.array(z.string()),
    tightenedKey: z.string(),
    tightenedKeyId: z.string(),
    pinnedWorkload: z.string(),
    pinnedWorkloadPrincipal: z.string(),
    spareWorkload: z.string(),
    pinExpiryDays: z.number(),
    revisionCount: z.number(),
    pinnedRevision: z.number(),
    pinExpiresAt: z.string(),
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

/**
 * zStorageState is the Playwright storage state, parsed because this harness
 * READS ITS OWN FILE BACK — `mintStorageState` has to preserve the serving
 * instance's cookies across a re-mint, and a worker calling
 * `refreshSharedSession` cannot reach the setup process's variables.
 */
const zStorageState = z.object({
  cookies: z.array(
    z.object({
      name: z.string(),
      value: z.string(),
      domain: z.string(),
      path: z.string(),
      expires: z.number(),
      httpOnly: z.boolean(),
      secure: z.boolean(),
      sameSite: z.enum(['Strict', 'Lax', 'None']),
    }),
  ),
  origins: z.array(z.unknown()),
});

/**
 * mintStorageState re-mints the VIEWING instance's browser session and leaves
 * every other origin's cookies alone.
 *
 * `keepForeign` is only passed during initial setup, when the serving jar
 * exists in memory. Every later call — `refreshSharedSession`, from a WORKER
 * process where `instances` is empty — recovers it from the file instead. The
 * file is the cross-process medium here for the same reason SEEDED and PASSKEY
 * are: a re-mint that dropped B's session would kill the workspace flow
 * halfway through the suite, from a cause several tests in the past.
 */
async function mintStorageState(keepForeign?: readonly Cookie[]): Promise<void> {
  const initialMint = keepForeign !== undefined;
  const foreign =
    keepForeign ??
    (existsSync(STORAGE_STATE)
      ? zStorageState
          .parse(JSON.parse(readFileSync(STORAGE_STATE, 'utf8')))
          .cookies.filter((c) => c.domain !== HOST && c.domain !== `.${HOST}`)
          .map((c) => ({ ...c, sameSite: c.sameSite === 'None' ? ('Lax' as const) : c.sameSite }))
      : []);

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
    if (!initialMint) {
      await cdp.send('WebAuthn.addCredential', {
        authenticatorId,
        credential: readPasskey(),
      });
    }

    const failure = await page.evaluate(sessionScript, {
      username: ADMIN.username,
      password: ADMIN.password,
      enrol: initialMint,
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
      throw new Error('the virtual authenticator holds no credential after the session mint');
    }

    mkdirSync(fileURLToPath(new URL('../.auth', import.meta.url)), {
      recursive: true,
    });
    const state = await context.storageState();
    writeFileSync(
      STORAGE_STATE,
      JSON.stringify({ ...state, cookies: [...state.cookies, ...foreign] }),
    );
    writePasskey(parseCredential(credential));
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

/** Attach a virtual authenticator and persist the shared credential when it is loaded. */
export async function installPasskeyAuthenticator(
  page: Page,
  credential: 'shared' | 'empty' = 'shared',
): Promise<() => Promise<void>> {
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
  // Most flows load the already-enrolled credential instead of enrolling
  // again. The account enrolment drill deliberately uses an empty, second
  // authenticator: creating another discoverable credential for the same user
  // on one authenticator replaces its resident entry locally.
  const sharedPasskey = credential === 'shared' ? readPasskey() : null;
  if (sharedPasskey !== null) {
    await session.send('WebAuthn.addCredential', { authenticatorId, credential: sharedPasskey });
  }
  return async () => {
    if (sharedPasskey === null) {
      return;
    }
    const { credentials } = await session.send('WebAuthn.getCredentials', { authenticatorId });
    const advanced = credentials.find(
      (credential) => credential.credentialId === sharedPasskey.credentialId,
    );
    if (advanced === undefined) {
      throw new Error('the shared virtual authenticator lost its passkey credential');
    }
    // Persist the authenticator's advanced signature counter: replaying a seen
    // counter looks like a cloned authenticator and disables the credential.
    writePasskey(parseCredential(advanced));
  };
}

/**
 * browserApi performs one API call on the PAGE's own session — its cookies,
 * its synchronizer token.
 *
 * Flows use it for fixture work a surface has no control for (creating the
 * throwaway project a settings drill deletes, reading a service account's
 * principal id). Deliberately the page's session rather than a bearer one: a
 * second artifact would be a second thing that can be stale, and the CSRF
 * contract is exercised on the way through rather than bypassed.
 */
export async function browserApi<T>(
  page: Page,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  schema: ZodType<T>,
  body?: unknown,
): Promise<T> {
  // Scoped to THIS instance's origin. The shared jar also carries the serving
  // instance's cookies (#71 runs two instances), and an unscoped read can hand
  // back the other origin's synchronizer token — which the CSRF gate refuses
  // with a 401 that looks exactly like a dead session, several calls from the
  // mistake.
  const cookies = await page.context().cookies(BASE_URL);
  const csrf = cookies.find((cookie) => cookie.name === '__Host-hikyo-csrf')?.value;
  if (csrf === undefined || csrf === '') {
    throw new Error(`${method} ${path} cannot run: the page has no CSRF cookie for ${BASE_URL}`);
  }
  const response = await page.request.fetch(`${BASE_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Hikyo-CSRF': csrf },
    ...(body === undefined ? {} : { data: body }),
  });
  if (!response.ok()) {
    throw new Error(`${method} ${path} answered ${response.status()}: ${await response.text()}`);
  }
  const value: unknown = response.status() === 204 ? null : await response.json();
  return schema.parse(value);
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
 * Every code is single-use per (account, step) — so the seeding session, this
 * harness's own step-up, the desktop project and the mobile project cannot each
 * pick "one step ahead of now" and expect all of them to be accepted. The
 * newest spent step lives in the same file the rest of the fixture does, for
 * the same reason the passkey's signature counter does: these are separate
 * processes sharing one account.
 *
 * It never waits in practice: flows run well after setup, so the step after
 * the current one is already free.
 */
export async function nextTotpCode(): Promise<string> {
  const seed = readSeed();
  const step = () => Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  const want = Math.max(step() + 1, seed.lastTotpStep + 1);
  while (step() < want - 1) {
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  writeFileSync(SEEDED, JSON.stringify({ ...seed, lastTotpStep: want }));
  return totpCode(seed.otpauth, new Date(want * TOTP_PERIOD * 1000));
}

/**
 * refreshSharedSession re-mints the storage state and the shared passkey.
 *
 * A flow that has to change the administrator's GRANTS advances their session
 * generation, which kills every session that principal holds — the suite's
 * shared storage state included. Re-minting is how such a flow leaves the
 * suite as it found it, and it preserves the serving instance's jar by reading
 * it back out of the file it is about to rewrite.
 */
export async function refreshSharedSession(): Promise<void> {
  await mintStorageState();
}

export function stopInstance(): void {
  tlsFront?.close();
  tlsFront = null;
  for (const instance of instances) {
    // SIGKILL, not SIGTERM: a server still inside boot may not have installed
    // its signal handler yet, and a survivor holds the port for the NEXT run —
    // where it answers /healthz from another datastore and turns every
    // authenticated call into a 401 that looks like a credential bug.
    instance.expectedExit = true;
    instance.proc.kill('SIGKILL');
    rmSync(instance.dir, { recursive: true, force: true });
  }
  instances = [];
}
