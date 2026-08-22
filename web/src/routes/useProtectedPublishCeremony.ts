import { useEffect, useState } from 'react';

import { useTransport } from '../api/transport.tsx';
import { fetchRevealWindow, type EnvRef } from '../api/values.ts';
import type { CeremonyPurpose, CeremonyRequest } from './Ceremony.tsx';
import {
  useCeremonyTask,
  type CeremonyTaskIdentity,
} from './useCeremonyTask.ts';

export type ProtectedPublishTarget = {
  readonly environmentId: string;
  readonly environmentName: string;
  readonly keys: CeremonyRequest['keys'];
  /**
   * What the human is TOLD they are authorising. `publish` by default, because
   * that is what publish and copy-into-protected share. The history drawer
   * (#59) passes `restore` and `pin`: the server gates both as reveals over an
   * enumerated secret-key unit, so the sequencing and refusal handling here are
   * exactly the ones those two need, and re-deriving them would be a second
   * place for the "prompt or not" decision to drift.
   */
  readonly purpose?: CeremonyPurpose;
};

/**
 * Runs the #21 ceremony once per named target before one guarded act.
 *
 * Copy and publish intentionally share this controller: copying into a
 * protected destination is the same publish-into-protected decision, so both
 * use purpose `publish` and must not drift in sequencing or refusal handling.
 * Restore staging and historical pinning (#59) join them for the same reason —
 * one place decides whether a live sliding window already covers the act.
 */
export function useProtectedPublishCeremony(
  refData: Omit<EnvRef, 'environment'>,
  scope: CeremonyTaskIdentity,
) {
  const [error, setError] = useState<string | null>(null);
  const transport = useTransport();
  const ceremony = useCeremonyTask([refData.org, refData.project, scope]);

  useEffect(
    () => setError(null),
    [refData.org, refData.project, ceremony.scopeKey],
  );

  const run = async (
    targets: readonly ProtectedPublishTarget[],
    onComplete: () => void,
    failureMessage: string,
  ): Promise<void> => {
    for (const target of targets) {
      if (target.keys.length === 0) {
        throw new Error(
          `protected publish environment ${target.environmentId} has no addressed keys`,
        );
      }
    }

    const operationKey = targets.map((target) => [
        target.purpose ?? 'publish',
        target.environmentId,
        target.keys.map((key) => key.id),
      ]);
    const task = ceremony.begin(operationKey);
    setError(null);

    const advance = async (remaining: readonly ProtectedPublishTarget[]): Promise<void> => {
      if (!ceremony.isCurrent(task)) return;
      const target = remaining[0];
      if (target === undefined) {
        if (ceremony.finish(task)) onComplete();
        return;
      }
      try {
        const window = await fetchRevealWindow(
          {
            ...refData,
            environment: target.environmentId,
          },
          transport.client,
          task.signal,
        );
        if (!ceremony.isCurrent(task)) return;
        if (window.live && !window.single_decision) {
          await advance(remaining.slice(1));
          return;
        }
        ceremony.stage(
          task,
          {
            purpose: target.purpose ?? 'publish',
            environmentId: target.environmentId,
            environmentName: target.environmentName,
            keys: target.keys,
            window,
          },
          () => void advance(remaining.slice(1)),
        );
      } catch (cause) {
        if (ceremony.commit(task, () => {
          setError(`${failureMessage}: ${errorMessage(cause)}`);
        })) {
          ceremony.finish(task);
        }
      }
    };

    await advance(targets);
  };

  return {
    request: ceremony.request,
    requestKey: ceremony.requestKey,
    error,
    run,
    onAuthorised: ceremony.onAuthorised,
    onCancel: ceremony.onCancel,
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}
