import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type { CeremonyRequest } from './Ceremony.tsx';

/**
 * CeremonyTask owns one protected operation from guard lookup through its
 * final continuation. The signal is best-effort network cancellation; task
 * identity remains the mandatory guard when a dispatched request cannot stop.
 */
export type CeremonyTask = {
  readonly key: string;
  readonly scopeKey: string;
  readonly signal: AbortSignal;
};

/** Structured identity parts; canonical string encoding stays inside this module. */
export type CeremonyTaskIdentity = readonly (string | CeremonyTaskIdentity)[];

type ActiveCeremonyTask = {
  readonly task: CeremonyTask;
  readonly controller: AbortController;
  continuation: (() => void) | null;
};

type StagedRequest = {
  readonly task: CeremonyTask;
  readonly request: CeremonyRequest;
};

/**
 * Owns the latest ceremony task for one mounted surface.
 *
 * A scope is the route/target identity visible to the human. Changing it makes
 * the old task obsolete synchronously during render; the effect then aborts
 * its request and releases its continuation. Starting a newer operation does
 * the same, including when the operation key itself is unchanged.
 */
export function useCeremonyTask(scope: CeremonyTaskIdentity) {
  const scopeKey = JSON.stringify(scope);
  const scopeRef = useRef(scopeKey);
  scopeRef.current = scopeKey;
  const attemptSequence = useRef(0);
  const mounted = useRef(true);
  const current = useRef<ActiveCeremonyTask | null>(null);
  const [staged, setStaged] = useState<StagedRequest | null>(null);

  const isCurrent = useCallback((task: CeremonyTask): boolean => {
    return (
      mounted.current &&
      current.current?.task === task &&
      task.scopeKey === scopeRef.current &&
      !task.signal.aborted
    );
  }, []);

  const release = useCallback((task: CeremonyTask): boolean => {
    if (!isCurrent(task)) return false;
    const active = current.current;
    if (active === null) return false;
    active.continuation = null;
    current.current = null;
    active.controller.abort();
    setStaged(null);
    return true;
  }, [isCurrent]);

  const abortCurrent = useCallback(() => {
    const active = current.current;
    current.current = null;
    if (active !== null) {
      active.continuation = null;
      active.controller.abort();
    }
  }, []);

  const begin = useCallback((operationKey: CeremonyTaskIdentity): CeremonyTask => {
    abortCurrent();
    attemptSequence.current += 1;
    const controller = new AbortController();
    const task: CeremonyTask = {
      key: JSON.stringify([scopeRef.current, operationKey, attemptSequence.current]),
      scopeKey: scopeRef.current,
      signal: controller.signal,
    };
    current.current = { task, controller, continuation: null };
    setStaged(null);
    return task;
  }, [abortCurrent]);

  const stage = useCallback((
    task: CeremonyTask,
    request: CeremonyRequest,
    continuation: () => void,
  ): boolean => {
    if (!isCurrent(task)) return false;
    const active = current.current;
    if (active === null) return false;
    if (active.continuation !== null) {
      throw new Error(`protected ceremony ${task.key} already has a continuation`);
    }
    active.continuation = continuation;
    setStaged({ task, request });
    return true;
  }, [isCurrent]);

  const commit = useCallback((task: CeremonyTask, action: () => void): boolean => {
    if (!isCurrent(task)) return false;
    action();
    return true;
  }, [isCurrent]);

  const finish = useCallback((task: CeremonyTask): boolean => release(task), [release]);

  const authorise = useCallback((task: CeremonyTask) => {
    const active = current.current;
    if (active === null || active.task !== task || !isCurrent(task)) return;
    const continuation = active.continuation;
    if (continuation === null) {
      throw new Error('protected ceremony completed without a continuation');
    }
    active.continuation = null;
    setStaged(null);
    continuation();
  }, [isCurrent]);

  const cancel = useCallback((task: CeremonyTask) => {
    if (!isCurrent(task)) return;
    abortCurrent();
    setStaged(null);
  }, [abortCurrent, isCurrent]);

  useEffect(() => {
    if (current.current !== null && current.current.task.scopeKey !== scopeKey) {
      abortCurrent();
      setStaged(null);
    }
  }, [abortCurrent, scopeKey]);

  useEffect(() => {
    // React StrictMode deliberately mounts effects twice in development. Mark
    // each setup live so its probe cleanup cannot permanently stale the hook.
    mounted.current = true;
    return () => {
      mounted.current = false;
      abortCurrent();
    };
  }, [abortCurrent]);

  const currentStaged = staged !== null && isCurrent(staged.task) ? staged : null;
  const request = currentStaged?.request ?? null;
  const stagedTask = currentStaged?.task ?? null;
  const requestKey = stagedTask?.key ?? null;
  const onAuthorised = useCallback(() => {
    if (stagedTask !== null) authorise(stagedTask);
  }, [authorise, stagedTask]);
  const onCancel = useCallback(() => {
    if (stagedTask !== null) cancel(stagedTask);
  }, [cancel, stagedTask]);

  return useMemo(() => ({
    scopeKey,
    request,
    requestKey,
    begin,
    stage,
    commit,
    finish,
    isCurrent,
    onAuthorised,
    onCancel,
  }), [begin, commit, finish, isCurrent, onAuthorised, onCancel, request, scopeKey, stage]);
}
