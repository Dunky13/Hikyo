import { useRef, useState } from 'react';

import { fetchRevealWindow, type EnvRef } from '../api/values.ts';
import type { CeremonyRequest } from './Ceremony.tsx';

export type ProtectedPublishTarget = {
  readonly environmentId: string;
  readonly environmentName: string;
  readonly keys: CeremonyRequest['keys'];
};

/**
 * Runs the #21 ceremony once per protected destination before one guarded act.
 *
 * Copy and publish intentionally share this controller: copying into a
 * protected destination is the same publish-into-protected decision, so both
 * use purpose `publish` and must not drift in sequencing or refusal handling.
 */
export function useProtectedPublishCeremony(refData: Omit<EnvRef, 'environment'>) {
  const [request, setRequest] = useState<CeremonyRequest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const resume = useRef<(() => void) | null>(null);

  const run = async (
    targets: readonly ProtectedPublishTarget[],
    onComplete: () => void,
    failureMessage: string,
  ): Promise<void> => {
    const target = targets[0];
    if (target === undefined) {
      onComplete();
      return;
    }
    if (target.keys.length === 0) {
      throw new Error(
        `protected publish environment ${target.environmentId} has no addressed keys`,
      );
    }
    setError(null);
    try {
      const window = await fetchRevealWindow({
        ...refData,
        environment: target.environmentId,
      });
      if (window.live && !window.single_decision) {
        await run(targets.slice(1), onComplete, failureMessage);
        return;
      }
      resume.current = () => {
        void run(targets.slice(1), onComplete, failureMessage);
      };
      setRequest({
        purpose: 'publish',
        environmentId: target.environmentId,
        environmentName: target.environmentName,
        keys: target.keys,
        window,
      });
    } catch (cause) {
      setError(`${failureMessage}: ${errorMessage(cause)}`);
    }
  };

  const onAuthorised = () => {
    setRequest(null);
    const continuation = resume.current;
    resume.current = null;
    if (continuation === null) {
      throw new Error('protected publish ceremony completed without a continuation');
    }
    continuation();
  };

  const onCancel = () => {
    setRequest(null);
    resume.current = null;
  };

  return { request, error, run, onAuthorised, onCancel };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
