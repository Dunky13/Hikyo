/**
 * Non-secret inputs frozen when the operator opens mint review.
 *
 * Keep this narrower than ServiceAccount and MachineEnvScope: retry needs the
 * addressed account, the review labels, and the disclosure environments. It
 * must not inherit unrelated query data or any credential response field.
 */
export type MintRequest = {
  readonly id: number;
  readonly sessionId: string;
  readonly org: string;
  readonly project: string;
  readonly accountId: string;
  readonly accountName: string;
  readonly rotating: boolean;
  readonly reach: readonly { readonly id: string; readonly name: string }[];
};

export type MintResult = {
  readonly value: string;
  readonly clamped: boolean;
};

export type MintLifecycle =
  | { readonly kind: 'idle' }
  | { readonly kind: 'reviewing'; readonly request: MintRequest }
  | { readonly kind: 'submitting'; readonly request: MintRequest }
  | { readonly kind: 'failed'; readonly request: MintRequest; readonly error: string }
  | {
      readonly kind: 'disclosed';
      readonly request: MintRequest;
      readonly result: MintResult;
      readonly stored: boolean;
      readonly heldBack: boolean;
      readonly copyStatus: string | null;
    };

export type MintLifecycleEvent =
  | { readonly type: 'review'; readonly request: MintRequest }
  | { readonly type: 'submit' }
  | { readonly type: 'succeeded'; readonly requestId: number; readonly result: MintResult }
  | { readonly type: 'failed'; readonly requestId: number; readonly error: string }
  | { readonly type: 'confirm-stored'; readonly stored: boolean }
  | { readonly type: 'copy-status'; readonly requestId: number; readonly message: string }
  | { readonly type: 'dismiss' }
  | {
      readonly type: 'clear';
      readonly reason: 'close' | 'navigation' | 'session-transition';
    };

export const idleMintLifecycle: MintLifecycle = { kind: 'idle' };

export type MintBoundary = {
  readonly sessionId: string | null;
  readonly org: string;
  readonly project: string;
};

/** Mask lifecycle state synchronously when its route or session no longer owns it. */
export function mintLifecycleAtBoundary(
  state: MintLifecycle,
  boundary: MintBoundary,
): MintLifecycle {
  if (state.kind === 'idle') {
    return state;
  }
  return state.request.sessionId === boundary.sessionId &&
    state.request.org === boundary.org &&
    state.request.project === boundary.project
    ? state
    : idleMintLifecycle;
}

/**
 * Closed mint state machine.
 *
 * Invalid events return the same object. Callers use that identity to avoid
 * starting a second transport while React is still scheduling the first
 * submitting render. Async completion is request-addressed, so an old response
 * cannot put plaintext back after navigation, a new mint, or a session exit.
 */
export function transitionMintLifecycle(
  state: MintLifecycle,
  event: MintLifecycleEvent,
): MintLifecycle {
  switch (event.type) {
    case 'review':
      return { kind: 'reviewing', request: event.request };
    case 'submit':
      return state.kind === 'reviewing' || state.kind === 'failed'
        ? { kind: 'submitting', request: state.request }
        : state;
    case 'succeeded':
      return state.kind === 'submitting' && state.request.id === event.requestId
        ? {
            kind: 'disclosed',
            request: state.request,
            result: event.result,
            stored: false,
            heldBack: false,
            copyStatus: null,
          }
        : state;
    case 'failed':
      return state.kind === 'submitting' && state.request.id === event.requestId
        ? { kind: 'failed', request: state.request, error: event.error }
        : state;
    case 'confirm-stored':
      return state.kind === 'disclosed'
        ? { ...state, stored: event.stored, heldBack: false }
        : state;
    case 'copy-status':
      return state.kind === 'disclosed' && state.request.id === event.requestId
        ? { ...state, copyStatus: event.message }
        : state;
    case 'dismiss':
      if (state.kind === 'submitting' || state.kind === 'idle') {
        return state;
      }
      if (state.kind === 'disclosed' && !state.stored) {
        return { ...state, heldBack: true };
      }
      return idleMintLifecycle;
    case 'clear':
      return state.kind === 'idle' ? state : idleMintLifecycle;
  }
}
