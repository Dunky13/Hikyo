import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

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

export const HOST = '127.0.0.1';
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

type Instance = { proc: ChildProcess; dir: string };

let running: Instance | null = null;

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

async function waitForHealthz(deadlineMs = 30_000): Promise<void> {
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
  running = { proc, dir };
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

  await mintStorageState();
}

/**
 * mintStorageState signs in over HTTP and writes the resulting cookie pair as
 * a Playwright storage state. It uses the same endpoint and the same
 * `artifact: browser` request the SPA makes, so the state is a real browser
 * session and not a fixture shortcut around the auth path.
 */
async function mintStorageState(): Promise<void> {
  const resp = await fetch(`${BASE_URL}/api/v1/auth/local/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: ADMIN.username,
      password: ADMIN.password,
      artifact: 'browser',
    }),
  });
  if (!resp.ok) {
    throw new Error(`minting the shared session answered ${resp.status}`);
  }
  const cookies = resp.headers.getSetCookie().map((raw) => {
    const [pair = ''] = raw.split(';');
    const [name = '', ...value] = pair.split('=');
    return {
      name,
      value: value.join('='),
      domain: HOST,
      path: '/',
      expires: -1,
      httpOnly: /httponly/i.test(raw),
      secure: /secure/i.test(raw),
      sameSite: /samesite=strict/i.test(raw) ? ('Strict' as const) : ('Lax' as const),
    };
  });
  if (cookies.length !== 2) {
    throw new Error(`the login set ${cookies.length} cookies, want the session and CSRF pair`);
  }
  mkdirSync(fileURLToPath(new URL('../.auth', import.meta.url)), { recursive: true });
  writeFileSync(STORAGE_STATE, JSON.stringify({ cookies, origins: [] }));
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
