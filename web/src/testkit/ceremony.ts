import type { RevealWindow } from '../api/values.ts';
import type { CeremonyRequest } from '../routes/Ceremony.tsx';

export type Deferred<T> = {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
};

/** A manually settled promise for latest-task and unmount regressions. */
export function deferred<T>(): Deferred<T> {
  let resolve = (_value: T) => {};
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

/** The minimum guard state needed to choose live-window or modal behavior. */
export function revealWindow(live: boolean): RevealWindow {
  return {
    protected: true,
    effective_window_seconds: 0,
    live,
    single_decision: false,
    can_reveal: true,
    totp_offered: false,
  };
}

/** One protected reveal request for controller and modal ownership tests. */
export function ceremonyRequest(name: string): CeremonyRequest {
  return {
    purpose: 'reveal',
    environmentId: name,
    environmentName: name,
    keys: [{ id: `key-${name}`, name: `KEY_${name.toUpperCase()}` }],
    window: revealWindow(false),
  };
}
