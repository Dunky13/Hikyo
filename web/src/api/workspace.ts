import { zMeta, zSessionList, zWorkspaceHandoffStarted, zWorkspaceSession } from '@hikyo/zod';
import { useSyncExternalStore } from 'react';
import type { ZodType } from 'zod';

/**
 * The workspace tier's CROSS-ORIGIN half (#71, multi-instance ADR § The handoff
 * and the workspace session).
 *
 * Nothing here goes through `api/client.ts`. That client carries cookies and a
 * synchronizer token, and neither may cross an origin: the workspace bearer
 * rides an `Authorization` header precisely so the remote's CORS runs WITHOUT
 * credentials mode and its CSRF posture is untouched. `credentials: 'omit'` is
 * therefore load-bearing, not tidiness.
 *
 * The structural rule everything below obeys: THE BROWSER TALKS TO THE REMOTE
 * DIRECTLY. This module never asks its own server about another instance —
 * there is no endpoint that would answer, and `api/noproxy_test.go` is what
 * keeps it that way.
 *
 * Responses are parsed by the GENERATED Zod schemas, never cast: a remote is a
 * foreign server, and "it is probably the shape we expect" is exactly the
 * assumption a foreign server should not get.
 */

/**
 * The minimum API revision a remote must serve before this shell will operate
 * it. Read LIVE from the remote's own meta endpoint before establishing or
 * resuming — never from the directory's cached `version`, which can race a
 * downgrade or a restore. The shell refuses BY NAME rather than rendering a
 * secrets matrix it half understands.
 */
export const WORKSPACE_MIN_API_REVISION = 1;

/** WorkspaceBearer is one live workspace session, held in MEMORY ONLY. */
export type WorkspaceBearer = {
  readonly origin: string;
  readonly value: string;
  readonly session: string;
  readonly idleExpiresAt: string;
  readonly absoluteExpiresAt: string;
};

/**
 * The workspace session store: one module-level Map and nothing else.
 *
 * Never a cookie, never localStorage, never sessionStorage — the ADR's rule,
 * and the reason is stated plainly there: in-memory narrows the AT-REST window,
 * it is not non-stealability. A reload is a re-establishment, which costs one
 * popup and one passkey tap.
 */
export type WorkspaceSessionReference = {
  readonly bearer: WorkspaceBearer;
  readonly epoch: number;
};

type WorkspaceSessionState = WorkspaceSessionReference & {
  consecutiveFailures: number;
};

const workspaceSessions = new Map<string, WorkspaceSessionState>();
const listeners = new Set<() => void>();
let snapshot: readonly WorkspaceBearer[] = [];
let nextWorkspaceEpoch = 0;

function publish(): void {
  snapshot = [...workspaceSessions.values()].map((state) => state.bearer);
  for (const listener of listeners) {
    listener();
  }
}

export function workspaceBearer(origin: string): WorkspaceBearer | undefined {
  return workspaceSessions.get(origin)?.bearer;
}

/** Captures the aggregate identity an asynchronous workspace request belongs to. */
export function workspaceSession(origin: string): WorkspaceSessionReference | undefined {
  return workspaceSessions.get(origin);
}

function workspaceSessionFor(bearer: WorkspaceBearer): WorkspaceSessionState | undefined {
  const session = workspaceSessions.get(bearer.origin);
  if (
    session === undefined ||
    session.bearer.session !== bearer.session ||
    session.bearer.value !== bearer.value
  ) {
    return undefined;
  }
  return session;
}

export function forgetWorkspace(origin: string): void {
  // One delete removes bearer identity and health together. A later session at
  // this origin receives a new epoch and starts with its full strike allowance.
  if (workspaceSessions.delete(origin)) {
    publish();
  }
}

/**
 * dropWorkspaceSession drops one origin ONLY IF the captured aggregate is
 * still current. The transport's 401 kill path and liveness probe both use it.
 *
 * The aggregate reference is the epoch boundary. Comparing bearer text is not
 * enough: even an adversarial value collision must not let old asynchronous
 * work mutate a replacement session.
 */
export function dropWorkspaceSession(session: WorkspaceSessionReference): void {
  if (workspaceSessions.get(session.bearer.origin) !== session) {
    return;
  }
  workspaceSessions.delete(session.bearer.origin);
  publish();
}

/** Counts one unreachable probe only against the aggregate that launched it. */
function strike(session: WorkspaceSessionState): boolean {
  if (workspaceSessions.get(session.bearer.origin) !== session) {
    return false;
  }
  session.consecutiveFailures += 1;
  if (session.consecutiveFailures < UNREACHABLE_STRIKES) {
    return true;
  }
  dropWorkspaceSession(session);
  return false;
}

/** useWorkspaces re-renders the shell when a workspace opens or is dropped. */
export function useWorkspaces(): readonly WorkspaceBearer[] {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => snapshot,
    () => snapshot,
  );
}

/**
 * How often the shell asks the remote whether the workspace is still alive.
 *
 * This is the ADR's "expiry surfaces in the shell as session expired —
 * reconnect", and it is also how the two server-side kill switches become
 * visible over here: de-allowlisting this origin and revoking the session in
 * the remote's own active-session list both take effect at the remote's next
 * request, and this is that request. Polling, again, because the bearer is a
 * header and `EventSource` cannot carry one.
 */
const LIVENESS_POLL_MS = 5_000;

export const livenessPollMs = LIVENESS_POLL_MS;

/**
 * probeWorkspace asks the remote, WITH the bearer, whether it still resolves.
 *
 * `/api/v1/me/sessions` is the right probe rather than a convenient one: it is
 * self-scoped, needs no capability, and is exactly the surface a revoked or
 * de-allowlisted session stops answering. A false answer drops the bearer here
 * too — keeping a value the remote has already forgotten would let the card
 * claim a workspace that is not there.
 */
export async function probeWorkspace(bearer: WorkspaceBearer): Promise<boolean> {
  const session = workspaceSessionFor(bearer);
  if (session === undefined) {
    return false;
  }
  let response: Response;
  try {
    response = await fetch(`${bearer.origin}/api/v1/me/sessions`, {
      mode: 'cors',
      credentials: 'omit',
      headers: { Authorization: `Bearer ${bearer.value}` },
      // A DEADLINE, because a hung fetch is worse than a failed one: without
      // it a single stalled probe never settles, and since the poll waits for
      // its predecessor no later probe ever runs. The workspace would then
      // survive forever on the strength of a request that never finished.
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
  } catch {
    // An opaque failure, and the shell cannot see which kind: a remote that is
    // briefly down and a remote that has just DE-ALLOWLISTED this origin look
    // identical from here, because withdrawing consent withdraws the CORS
    // headers with it and the browser then refuses to show script the status.
    //
    // So a single failure is not death — a blip must not cost a ceremony — but
    // a run of them is: whatever the cause, a workspace this shell cannot
    // reach is not a workspace, and claiming it is open is the one thing the
    // card must not do.
    return strike(session);
  }
  // Only a 401 is the session dying (revoked, expired, origin-binding mismatch —
  // all ErrUnauthenticated).
  if (response.status === 401) {
    dropWorkspaceSession(session);
    return false;
  }
  // A 403 is NOT death and NOT unreachability — it is a "forbidden" from a
  // remote that is up and did not 401 the session. This endpoint is self-scoped
  // and cannot legitimately 403 a live session, so a 403 here is anomalous (a
  // proxy, a WAF); treating it as a strike would let two spurious ones kill a
  // valid workspace. Matches the transport's own 403 handling — keep the
  // session — so a forbidden never becomes a false reconnect. It does not clear
  // the strike count either: it is not the clean answer that proves liveness.
  if (response.status === 403) {
    return workspaceSessions.get(bearer.origin) === session;
  }
  // ONLY A WELL-FORMED SUCCESS CLEARS THE STRIKE COUNT. Anything else is a
  // strike: a 404 or a 500 is not this endpoint answering, and a 200 carrying
  // HTML is something in the path — a captive portal, a proxy error page —
  // that is not the remote at all. Treating those as "alive" is how the card
  // ends up claiming a workspace nobody can use, which is the exact failure the
  // strike counter exists to prevent.
  if (!response.ok) {
    return strike(session);
  }
  try {
    zSessionList.parse(await response.json());
  } catch {
    return strike(session);
  }
  if (workspaceSessions.get(bearer.origin) !== session) {
    return false;
  }
  session.consecutiveFailures = 0;
  return true;
}

/** How many consecutive unreachable probes end a workspace. */
const UNREACHABLE_STRIKES = 2;

/**
 * How long one probe may take. Shorter than the poll interval on purpose: a
 * probe still running when the next is due has already answered the question.
 */
const PROBE_TIMEOUT_MS = 4_000;

/** WorkspaceError is a refusal this shell can put in front of a human. */
export class WorkspaceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WorkspaceError';
  }
}

/**
 * remoteJSON is the one door to a foreign instance: no cookies, no synchronizer
 * token, CORS mode, and a generated schema on the way back.
 */
async function remoteJSON<T>(
  origin: string,
  path: string,
  schema: ZodType<T>,
  init?: { body: unknown },
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(origin + path, {
      method: init === undefined ? 'GET' : 'POST',
      mode: 'cors',
      // The bearer is a header, so nothing ambient may travel. Omitting
      // credentials is what keeps the remote's CORS out of credentials mode.
      credentials: 'omit',
      headers: init === undefined ? {} : { 'Content-Type': 'application/json' },
      body: init === undefined ? null : JSON.stringify(init.body),
    });
  } catch {
    // A CORS refusal and a dead host are the same opaque failure to script,
    // and saying which would be guessing.
    throw new WorkspaceError(
      `${origin} could not be reached, or it does not allow this origin to talk to it.`,
    );
  }
  if (!response.ok) {
    throw new WorkspaceError(
      response.status === 403
        ? `${origin} refused the handoff. Its administrator has to allowlist this origin first.`
        : `${origin} answered ${response.status}.`,
    );
  }
  return schema.parse(await response.json());
}

/**
 * assertCompatible performs the LIVE pre-auth meta read the ADR requires before
 * establishing or resuming a workspace.
 */
export async function assertCompatible(origin: string): Promise<void> {
  // The live protection is right here in `remoteJSON`: a remote that is
  // unreachable, refuses this origin, or serves a meta that does not PARSE as
  // this protocol throws, and the caller refuses the workspace. The numeric
  // check below is the second half — the per-operation minimum-revision gate —
  // and it is dormant while this shell's floor equals the meta contract's own
  // (`zMeta` already rejects a revision below 1). It becomes live the day a
  // future operation raises `WORKSPACE_MIN_API_REVISION` above that floor.
  const meta = await remoteJSON(origin, '/api/v1/meta', zMeta);
  if (meta.api_revision < WORKSPACE_MIN_API_REVISION) {
    throw new WorkspaceError(
      `${origin} serves API revision ${meta.api_revision}; this shell needs at least ` +
        `${WORKSPACE_MIN_API_REVISION}. Upgrade that instance before operating it from here — ` +
        `degraded rendering of a secrets matrix is not a graceful state.`,
    );
  }
}

// --- PKCE (RFC 7636, S256) ---------------------------------------------------

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function newVerifier(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

// --- the ceremony ------------------------------------------------------------

/** The path the viewing UI's own callback page is served at. */
export const CALLBACK_PATH = '/workspace/callback';
/** The path a serving instance's authorization page is served at. */
export const APPROVE_PATH = '/workspace/approve';

/** channelName is the nonce-named BroadcastChannel for one transaction. */
export function channelName(state: string): string {
  return `hikyo.workspace.${state}`;
}

type FrontChannelResult = { readonly code: string; readonly state: string };

/**
 * awaitFrontChannel listens for the callback page's hand-off.
 *
 * `window.opener` is deliberately unavailable — the popup is opened with
 * `noopener` so a hostile remote cannot navigate this window into a phishing
 * page — so the return path is a same-origin callback page of THIS UI, talking
 * over a channel only this origin can open.
 */
function awaitFrontChannel(state: string, timeoutMs: number): Promise<FrontChannelResult> {
  return new Promise((resolve, reject) => {
    const channel = new BroadcastChannel(channelName(state));
    const timer = setTimeout(() => {
      channel.close();
      reject(new WorkspaceError('The sign-in window was closed or timed out. Try again.'));
    }, timeoutMs);
    channel.onmessage = (event: MessageEvent<unknown>) => {
      const parsed = frontChannelMessage(event.data);
      // A message for a different transaction is not this one's business. It
      // cannot normally arrive — the channel is named for the state — but
      // matching anyway keeps "whose code is this" answerable rather than
      // assumed.
      if (parsed === null || parsed.state !== state) {
        return;
      }
      clearTimeout(timer);
      channel.close();
      resolve(parsed);
    };
  });
}

/**
 * frontChannelMessage validates the callback's payload. It is a message from
 * another document, so it is PARSED rather than trusted, and a shape that does
 * not match yields null instead of a half-populated object.
 */
function frontChannelMessage(data: unknown): FrontChannelResult | null {
  if (typeof data !== 'object' || data === null) {
    return null;
  }
  const record: Record<string, unknown> = { ...data };
  const { code, state } = record;
  if (typeof code !== 'string' || typeof state !== 'string' || code === '' || state === '') {
    return null;
  }
  return { code, state };
}

/** How long the shell waits for the popup before giving up on it. */
const CEREMONY_TIMEOUT_MS = 5 * 60_000;

/**
 * PreparedWorkspace is a handoff transaction that exists but has not been shown
 * to the human yet.
 *
 * The ceremony is TWO clicks and that is forced by the platform, not chosen:
 * `window.open` only survives the popup blocker inside the task of a real user
 * gesture, and the transaction cannot be opened without a network round trip
 * first. Preparing on the first click and opening on the second keeps the open
 * synchronous — and it buys something worth having anyway, since the human sees
 * exactly which origin they are about to be sent to sign in at before a window
 * appears, which is the one anti-phishing check a popup ceremony can offer.
 */
export type PreparedWorkspace = {
  readonly origin: string;
  readonly state: string;
  readonly verifier: string;
  /** The remote's authorization page, ready to be opened on a gesture. */
  readonly approveURL: string;
};

/**
 * StepUpParams turns a `prepareWorkspace` into an elevation rather than an
 * establishment (#71, multi-instance ADR § The handoff and the workspace
 * session). Every field is bound into the remote's own transaction row, so an
 * elevated consent cannot be replayed against a different operation, environment
 * or key set.
 */
export type StepUpParams = {
  /** The workspace session being elevated. A step-up NEVER mints a second one. */
  readonly session: string;
  /** What the reauthentication authorizes, as the reveal endpoint consumes it. */
  readonly operation: 'reveal' | 'copy' | 'publish';
  /** The environment the elevation covers. */
  readonly environment: string;
  /** The enumerated key unit the elevation covers. */
  readonly keySet: readonly string[];
};

/**
 * prepareWorkspace performs the live compatibility check and opens the handoff
 * transaction on the remote. It touches no window.
 *
 * With `stepUp` it opens an ELEVATION of an existing session rather than a first
 * establishment. The bound fields ride the approve URL as well as the start
 * body: the approve page needs the environment and key set to run the remote's
 * OWN reauthentication ceremony over them before it may approve — while the
 * server still validates the fresh reauth window against the transaction's own
 * bound environment, so a tampered URL parameter only fails closed.
 */
export async function prepareWorkspace(
  origin: string,
  stepUp?: StepUpParams,
): Promise<PreparedWorkspace> {
  await assertCompatible(origin);

  const verifier = newVerifier();
  const base = {
    origin: globalThis.location.origin,
    redirect_uri: globalThis.location.origin + CALLBACK_PATH,
    pkce_challenge: await challengeFor(verifier),
  };
  const body =
    stepUp === undefined
      ? { ...base, purpose: 'establishment' as const }
      : {
          ...base,
          purpose: 'step-up' as const,
          session: stepUp.session,
          operation: stepUp.operation,
          environment: stepUp.environment,
          key_set: [...stepUp.keySet],
        };
  const started = await remoteJSON(origin, '/api/v1/auth/workspace/start', zWorkspaceHandoffStarted, {
    body,
  });
  // The approve URL carries only STATE and (for a step-up) the tiny purpose
  // flag. The operation, environment and enumerated key set the approve page
  // needs are NOT here: they are bound in the remote's own transaction row and
  // the approve page reads them back by state (`showWorkspaceHandoff`). Putting
  // the key set on the URL would cap a reveal-all at the browser's URL length;
  // the server-bound transaction has no such ceiling and is the authoritative
  // copy anyway, so a tampered parameter could never move the elevation's scope.
  const approve = new URL(`${origin}${APPROVE_PATH}`);
  approve.searchParams.set('state', started.state);
  if (stepUp !== undefined) {
    approve.searchParams.set('purpose', 'step-up');
  }
  return { origin, state: started.state, verifier, approveURL: approve.toString() };
}

/**
 * openPrepared opens the popup and completes the ceremony.
 *
 * It MUST be called straight from a click handler: the `window.open` below is
 * the first statement for that reason, and everything asynchronous happens
 * after it. `noopener` is the ADR's requirement — a hostile or compromised
 * remote must not be able to navigate the opener into a phishing page — which
 * is why this returns no handle and why the popup closes itself from the
 * callback page.
 *
 * The front channel carries code and state ONLY. The artifact never crosses a
 * redirect: it comes back on the redemption response, into memory, and stays
 * there.
 */
export async function openPrepared(prepared: PreparedWorkspace): Promise<WorkspaceBearer> {
  const waiting = awaitFrontChannel(prepared.state, CEREMONY_TIMEOUT_MS);
  globalThis.open(prepared.approveURL, '_blank', 'noopener,popup=yes,width=520,height=680');
  const { code } = await waiting;

  const session = await remoteJSON(
    prepared.origin,
    '/api/v1/auth/workspace/redeem',
    zWorkspaceSession,
    { body: { code, pkce_verifier: prepared.verifier, origin: globalThis.location.origin } },
  );
  const bearer: WorkspaceBearer = {
    origin: prepared.origin,
    value: session.value,
    session: session.session,
    idleExpiresAt: session.idle_expires_at,
    absoluteExpiresAt: session.absolute_expires_at,
  };
  rememberWorkspace(bearer);
  return bearer;
}

/**
 * rememberWorkspace installs a redeemed bearer as the live one for its origin.
 *
 * It is the ONLY writer of the store, so bearer identity and health change in
 * one Map write. Every replacement gets a new local epoch and zero failures;
 * old asynchronous work retains the outgoing aggregate reference and cannot
 * spend a strike, clear health, or evict the replacement.
 */
export function rememberWorkspace(bearer: WorkspaceBearer): void {
  nextWorkspaceEpoch += 1;
  workspaceSessions.set(bearer.origin, {
    bearer,
    epoch: nextWorkspaceEpoch,
    consecutiveFailures: 0,
  });
  publish();
}
