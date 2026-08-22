import {
  clearValueOp,
  copyValuesOp,
  getEnvironmentSignalsOp,
  listKeyGroupsOp,
  listKeysOp,
  listPendingDraftsOp,
  listValuesOp,
  publishPendingChangesOp,
  reclassifyKeyOp,
  setValueOp,
} from '@hikyo/operations';
import {
  zEnvironmentList,
  zEnvironmentSettings,
  zEnvironmentSignals,
  zKeyList,
  zPendingDraftList,
  zPublishResult,
  zScanFinding,
  zValueList,
} from '@hikyo/zod';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo } from 'react';
import { z } from 'zod';

import { ApiError, parsed } from './client.ts';
import { callerSafeRefusal } from './history.ts';
import {
  invalidateAfterCopy,
  matrixGroupsKey,
  matrixKeysKey,
  pendingDraftsKey,
  pinsKey,
  revisionsKey,
  signalsKey,
  valuesKey,
  windowKey,
  type MatrixRef,
} from './keys.ts';
import { environmentSettingsQueryOptions, useEnvironments } from './settings.ts';
import { useTransport } from './transport.tsx';

export { useProjects } from './settings.ts';
export type { MatrixRef } from './keys.ts';

/**
 * Whole-project matrix API boundary.
 *
 * The matrix reads one project catalogue and then fans out over the project's
 * environments. Every body crosses the generated Zod schema at this boundary;
 * the component receives only parsed domain records. Signals poll because the
 * API documents this endpoint as the fallback when the advisory SSE stream is
 * unavailable, and this surface does not need a second live-update protocol.
 */

export type MatrixKeyList = z.infer<typeof zKeyList>;
/**
 * A redacted secret-scanning finding (#74, secret-scanning ADR §4). It rides
 * a config value-write response and carries a rule id, an immutable locator,
 * and — for a keep-as-config dismissal — an opaque acknowledgement token. It
 * never carries the matched text, so the UI renders only what it holds.
 */
export type ScanFinding = z.infer<typeof zScanFinding>;
export type MatrixEnvironmentSignals = z.infer<typeof zEnvironmentSignals>;
export type MatrixSignalCell = MatrixEnvironmentSignals['cells'][number];

type MatrixEnvironment = z.infer<typeof zEnvironmentList>['items'][number];
type MatrixEnvironmentSettings = z.infer<typeof zEnvironmentSettings>;
type MatrixValueList = z.infer<typeof zValueList>;
type MatrixPendingDraftList = z.infer<typeof zPendingDraftList>;

export type MatrixQueryState<T> = {
  readonly data: T | undefined;
  readonly isPending: boolean;
  readonly isError: boolean;
};

export type MatrixEnvironmentQuery<T> = {
  readonly environmentId: string;
  readonly query: MatrixQueryState<T>;
};

type EnvironmentQueryData<T> = {
  readonly environmentId: string;
  readonly value: T;
};

/** One ordered display row with every per-environment query attached by identity. */
export type MatrixEnvironmentRow = {
  readonly environmentId: string;
  readonly environment: MatrixEnvironment;
  readonly values: MatrixQueryState<MatrixValueList>;
  readonly signals: MatrixQueryState<MatrixEnvironmentSignals>;
  readonly settings: MatrixQueryState<MatrixEnvironmentSettings>;
  readonly pendingDrafts: MatrixQueryState<MatrixPendingDraftList>;
};

type MatrixEnvironmentQueries = {
  readonly values: readonly MatrixEnvironmentQuery<MatrixValueList>[];
  readonly signals: readonly MatrixEnvironmentQuery<MatrixEnvironmentSignals>[];
  readonly settings: readonly MatrixEnvironmentQuery<MatrixEnvironmentSettings>[];
  readonly pendingDrafts: readonly MatrixEnvironmentQuery<MatrixPendingDraftList>[];
};

function matrixQueryIndex<T>(
  label: string,
  entries: readonly MatrixEnvironmentQuery<T>[],
): ReadonlyMap<string, MatrixQueryState<T>> {
  const queries = new Map<string, MatrixQueryState<T>>();
  for (const entry of entries) {
    if (queries.has(entry.environmentId)) {
      throw new Error(
        `matrix ${label} queries contain duplicate environment ${entry.environmentId}`,
      );
    }
    queries.set(entry.environmentId, entry.query);
  }
  return queries;
}

function requiredMatrixQuery<T>(
  label: string,
  environmentId: string,
  queries: ReadonlyMap<string, MatrixQueryState<T>>,
): MatrixQueryState<T> {
  const query = queries.get(environmentId);
  if (query === undefined) {
    throw new Error(`matrix ${label} query is missing environment ${environmentId}`);
  }
  return query;
}

/**
 * Join independently updating query families by environment ID while keeping
 * the server's environment order as the explicit display order.
 */
export function assembleMatrixEnvironmentRows(
  environments: readonly MatrixEnvironment[],
  input: MatrixEnvironmentQueries,
): readonly MatrixEnvironmentRow[] {
  const values = matrixQueryIndex('values', input.values);
  const signals = matrixQueryIndex('signals', input.signals);
  const settings = matrixQueryIndex('settings', input.settings);
  const pendingDrafts = matrixQueryIndex('pending drafts', input.pendingDrafts);
  return environments.map((environment) => ({
    environmentId: environment.id,
    environment,
    values: requiredMatrixQuery('values', environment.id, values),
    signals: requiredMatrixQuery('signals', environment.id, signals),
    settings: requiredMatrixQuery('settings', environment.id, settings),
    pendingDrafts: requiredMatrixQuery('pending drafts', environment.id, pendingDrafts),
  }));
}

export function bindMatrixEnvironmentQueries<T>(
  label: string,
  environments: readonly MatrixEnvironment[],
  queries: readonly MatrixQueryState<EnvironmentQueryData<T>>[],
): readonly MatrixEnvironmentQuery<T>[] {
  if (environments.length !== queries.length) {
    throw new Error(
      `matrix ${label} query count ${String(queries.length)} does not match environment count ${String(environments.length)}`,
    );
  }
  return environments.map((environment, index) => {
    const query = queries[index];
    if (query === undefined) {
      throw new Error(`matrix ${label} query is missing position ${String(index)}`);
    }
    if (query.data !== undefined && query.data.environmentId !== environment.id) {
      throw new Error(
        `matrix ${label} query for ${environment.id} returned data for ${query.data.environmentId}`,
      );
    }
    return {
      environmentId: environment.id,
      query: {
        data: query.data?.value,
        isPending: query.isPending,
        isError: query.isError,
      },
    };
  });
}

type RestorePreview = { readonly versionIds: readonly string[]; readonly token: string };

/**
 * Restore previews intentionally live only for this page load, but outside any
 * route component so matrix/history SPA navigation cannot drop them. A browser
 * reload clears the store and requires the restore to be staged again.
 */
const restorePreviews = new Map<string, readonly RestorePreview[]>();
const previewAttachedErrors = new WeakSet<Error>();

class RestorePreviewSelectionError extends Error {}

const restorePreviewKey = (ref: MatrixRef): string => `${ref.org}/${ref.project}`;
const sortedVersionIds = (versionIds: readonly string[]): readonly string[] =>
  [...new Set(versionIds)].sort((left, right) => left.localeCompare(right));

function sameVersionSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((versionId, index) => versionId === right[index]);
}

export function rememberRestorePreview(
  ref: MatrixRef,
  versionIds: readonly string[],
  token: string,
): void {
  const normalized = sortedVersionIds(versionIds);
  if (normalized.length === 0) {
    throw new Error('Cannot remember a restore preview without version ids.');
  }
  const key = restorePreviewKey(ref);
  const existing = restorePreviews.get(key) ?? [];
  restorePreviews.set(key, [
    ...existing.filter((entry) => !sameVersionSet(entry.versionIds, normalized)),
    { versionIds: normalized, token },
  ]);
}

export function restorePreviewFor(
  ref: MatrixRef,
  selectedVersionIds: readonly string[],
): { readonly token: string } | { readonly conflict: readonly string[] } | null {
  const selected = sortedVersionIds(selectedVersionIds);
  const remembered = restorePreviews.get(restorePreviewKey(ref)) ?? [];
  const exact = remembered.find((entry) => sameVersionSet(entry.versionIds, selected));
  if (exact !== undefined) {
    return { token: exact.token };
  }
  const selectedSet = new Set(selected);
  const overlaps = sortedVersionIds(
    remembered.flatMap((entry) => entry.versionIds.filter((versionId) => selectedSet.has(versionId))),
  );
  return overlaps.length === 0 ? null : { conflict: overlaps };
}

export function forgetRestorePreviews(ref: MatrixRef, versionIds: readonly string[]): void {
  const key = restorePreviewKey(ref);
  const forgotten = new Set(versionIds);
  const remaining = (restorePreviews.get(key) ?? []).filter(
    (entry) => !entry.versionIds.some((versionId) => forgotten.has(versionId)),
  );
  if (remaining.length === 0) {
    restorePreviews.delete(key);
  } else {
    restorePreviews.set(key, remaining);
  }
}

export function restorePreviewWasAttached(error: Error): boolean {
  return previewAttachedErrors.has(error);
}

const zMatrixEnvironmentSignals = zEnvironmentSignals.superRefine((signals, context) => {
  signals.cells.forEach((cell, index) => {
    if ((cell.pending_version_id === undefined) !== (cell.pending_operation === undefined)) {
      context.addIssue({
        code: 'custom',
        message: 'pending_version_id and pending_operation must be present together',
        path: ['cells', index],
      });
    }
  });
});

export function parseMatrixEnvironmentSignals(input: unknown): MatrixEnvironmentSignals {
  return zMatrixEnvironmentSignals.parse(input);
}

export function revisionAdvanced(previous: bigint | undefined, next: bigint): boolean {
  return previous !== undefined && next > previous;
}

export function signalsRequireValuesRefresh(
  previous: bigint | undefined,
  next: bigint,
): boolean {
  // Values carry no revision. The first signal snapshot therefore establishes
  // ordering by refreshing once; later snapshots refresh only on advancement.
  return previous === undefined || revisionAdvanced(previous, next);
}

/**
 * The caller's own drafts, as the publish sheet previews them.
 *
 * Previews come from the server (`listPendingDrafts`), bound to the immutable
 * pending version id, so they survive a reload and a second browser alike and
 * are never cached in client storage. The refinement pins the contract the
 * endpoint promises: `value` iff `revealed`, and secret or unset drafts never
 * carry material on this surface.
 */
export const zMatrixPendingDraftList = zPendingDraftList.superRefine((drafts, context) => {
  drafts.items.forEach((draft, index) => {
    const hasValue = draft.value !== undefined;
    if (draft.revealed !== hasValue) {
      context.addIssue({
        code: 'custom',
        path: ['items', index, 'value'],
        message: 'pending draft value must appear if and only if revealed is true',
      });
    }
    if (draft.classification === 'secret' && draft.revealed) {
      context.addIssue({
        code: 'custom',
        path: ['items', index, 'revealed'],
        message: 'secret pending drafts must remain unrevealed',
      });
    }
    if (draft.operation === 'unset' && draft.revealed) {
      context.addIssue({
        code: 'custom',
        path: ['items', index, 'revealed'],
        message: 'unset pending drafts must remain unrevealed',
      });
    }
  });
});

export type MatrixPendingDraft = z.infer<typeof zMatrixPendingDraftList>['items'][number];

export function parseMatrixPendingDrafts(input: unknown): z.infer<typeof zMatrixPendingDraftList> {
  return zMatrixPendingDraftList.parse(input);
}

/** The config material a signal's own pending set previews, if the server revealed it. */
export function pendingConfigPreview(
  signal: MatrixSignalCell | undefined,
  draftsByVersion: ReadonlyMap<string, MatrixPendingDraft>,
): string | undefined {
  if (signal?.pending_version_id === undefined) {
    return undefined;
  }
  const draft = draftsByVersion.get(signal.pending_version_id);
  if (draft === undefined) {
    return undefined;
  }
  if (draft.key_id !== signal.key_id) {
    throw new Error(`pending draft ${draft.version_id} is bound to the wrong key`);
  }
  if (draft.classification !== 'config' || draft.operation !== 'set' || !draft.revealed) {
    return undefined;
  }
  return draft.value;
}

export function matrixPublishValidation(
  error: Error,
  keys: readonly { readonly id: string; readonly name: string }[],
  environmentIds: readonly string[],
): { readonly keyId: string; readonly environmentId: string; readonly message: string } | null {
  if (!(error instanceof ApiError) || error.status !== 400 || error.detail === undefined) {
    return null;
  }
  const match = /^key "([^"]+)" is `(?:required_in|forbidden_in)` environment ([^ ]+) /.exec(
    error.detail,
  );
  if (match === null) {
    return null;
  }
  const [, keyName, environmentId] = match;
  const key = keys.find((candidate) => candidate.name === keyName);
  if (key === undefined || environmentId === undefined || !environmentIds.includes(environmentId)) {
    return null;
  }
  return { keyId: key.id, environmentId, message: error.detail };
}

export function useMatrixProject(ref: MatrixRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  const environments = useEnvironments(ref.org, ref.project);
  const keys = useQuery({
    queryKey: matrixKeysKey(ref),
    queryFn: () => parsed(listKeysOp, { path: ref, ...transport }),
    enabled: ref.org !== '' && ref.project !== '',
    retry: false,
  });
  const groups = useQuery({
    queryKey: matrixGroupsKey(ref),
    queryFn: () => parsed(listKeyGroupsOp, { path: ref, ...transport }),
    enabled: ref.org !== '' && ref.project !== '',
    retry: false,
  });
  const environmentItems = environments.data === undefined ? [] : environments.data.items;
  const values = useQueries({
    queries: environmentItems.map((environment) => ({
      queryKey: valuesKey({ ...ref, environment: environment.id }),
      queryFn: () =>
        parsed(listValuesOp, {
          path: { ...ref, environment: environment.id },
          ...transport,
        }),
      select: (value: MatrixValueList) => ({ environmentId: environment.id, value }),
      retry: false,
    })),
  });
  const settings = useQueries({
    queries: environmentItems.map((environment) => {
      const options = environmentSettingsQueryOptions(
        ref.org,
        ref.project,
        environment.id,
        transport.client,
      );
      return {
        ...options,
        select: (value: MatrixEnvironmentSettings) => ({
          environmentId: environment.id,
          value,
        }),
      };
    }),
  });
  const signals = useQueries({
    queries: environmentItems.map((environment) => ({
      queryKey: signalsKey(ref, environment.id),
      queryFn: async () => {
        const key = signalsKey(ref, environment.id);
        const previous = queries.getQueryData<MatrixEnvironmentSignals>(key);
        const next = zMatrixEnvironmentSignals.parse(
          await parsed(getEnvironmentSignalsOp, {
            path: { ...ref, environment: environment.id },
            ...transport,
          }),
        );
        if (signalsRequireValuesRefresh(previous?.revision, next.revision)) {
          await queries.invalidateQueries({
            queryKey: valuesKey({ ...ref, environment: environment.id }),
          });
        }
        if (next.environment_id !== environment.id) {
          throw new Error(
            `matrix signals query for ${environment.id} returned data for ${next.environment_id}`,
          );
        }
        return next;
      },
      select: (value: MatrixEnvironmentSignals) => ({ environmentId: environment.id, value }),
      refetchInterval: 2_000,
      retry: false,
    })),
  });
  const pendingDrafts = useQueries({
    queries: environmentItems.map((environment) => ({
      queryKey: pendingDraftsKey(ref, environment.id),
      queryFn: async () =>
        zMatrixPendingDraftList.parse(
          await parsed(listPendingDraftsOp, {
            path: { ...ref, environment: environment.id },
            ...transport,
          }),
        ),
      select: (value: MatrixPendingDraftList) => ({ environmentId: environment.id, value }),
      retry: false,
    })),
  });

  const environmentRows = useMemo(
    () =>
      assembleMatrixEnvironmentRows(environmentItems, {
        values: bindMatrixEnvironmentQueries('values', environmentItems, values),
        signals: bindMatrixEnvironmentQueries('signals', environmentItems, signals),
        settings: bindMatrixEnvironmentQueries('settings', environmentItems, settings),
        pendingDrafts: bindMatrixEnvironmentQueries(
          'pending drafts',
          environmentItems,
          pendingDrafts,
        ),
      }),
    [environmentItems, pendingDrafts, settings, signals, values],
  );

  return { environments, keys, groups, environmentRows };
}

export function useStageMatrixValue(ref: MatrixRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    // `acknowledgements` carries a keep-as-config token to dismiss a Surface-1
    // warning (#74): re-staging the SAME value with its token records the
    // dismissal so the identical value no longer re-warns. The save succeeds
    // either way — the token only settles whether the finding rides back.
    mutationFn: (input: {
      readonly environment: string;
      readonly key: string;
      readonly value: string;
      readonly acknowledgements?: readonly string[];
    }) =>
      parsed(setValueOp, {
          path: { ...ref, environment: input.environment, key: input.key },
          body: {
            value: input.value,
            ...(input.acknowledgements === undefined
              ? {}
              : { acknowledgements: [...input.acknowledgements] }),
          },
          ...transport,
        }),
    onSuccess: (_result, input) =>
      Promise.all([
        queries.invalidateQueries({ queryKey: valuesKey({ ...ref, environment: input.environment }) }),
        queries.invalidateQueries({ queryKey: signalsKey(ref, input.environment) }),
        queries.invalidateQueries({ queryKey: pendingDraftsKey(ref, input.environment) }),
      ]),
  });
}

/**
 * useReclassifyKey drives the reclassification ceremony (#12). The scanner's
 * warn dialog reaches it as the primary "reclassify as secret" resolution
 * (#74, ADR §4): moving the key to `secret` routes every value through secret
 * handling and drops the key's config-dismissals server-side. The keys query
 * is invalidated so the matrix reflects the new classification (the 🔒 lock).
 */
export function useReclassifyKey(ref: MatrixRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (input: { readonly key: string; readonly classification: 'secret' | 'config' }) =>
      parsed(reclassifyKeyOp, {
          path: { ...ref, key: input.key },
          body: { classification: input.classification },
          ...transport,
        }),
    onSuccess: () => queries.invalidateQueries({ queryKey: matrixKeysKey(ref) }),
  });
}

export function useClearMatrixValue(ref: MatrixRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (input: { readonly environment: string; readonly key: string }) =>
      parsed(clearValueOp, { path: { ...ref, environment: input.environment, key: input.key }, ...transport }),
    onSuccess: (_result, input) =>
      Promise.all([
        queries.invalidateQueries({ queryKey: valuesKey({ ...ref, environment: input.environment }) }),
        queries.invalidateQueries({ queryKey: signalsKey(ref, input.environment) }),
        queries.invalidateQueries({ queryKey: pendingDraftsKey(ref, input.environment) }),
      ]),
  });
}

export function usePublishMatrix(ref: MatrixRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: async (input: {
      readonly addressedEnvironment: string;
      readonly environmentIds: readonly string[];
      readonly versionIds: readonly string[];
    }) => {
      const preview = restorePreviewFor(ref, input.versionIds);
      if (preview !== null && 'conflict' in preview) {
        throw new RestorePreviewSelectionError(
          'Restore drafts must be published exactly as previewed — deselect the other drafts or ' +
          `stage the restore again. Overlapping version ids: ${preview.conflict.join(', ')}.`,
        );
      }
      const previewToken = preview?.token;
      let result: z.infer<typeof zPublishResult>;
      try {
        result = await parsed(publishPendingChangesOp, {
            path: { ...ref, environment: input.addressedEnvironment },
            body: {
              version_ids: [...input.versionIds],
              ...(previewToken === undefined ? {} : { preview_token: previewToken }),
            },
            ...transport,
          });
      } catch (error) {
        if (previewToken !== undefined && error instanceof Error) {
          previewAttachedErrors.add(error);
        }
        throw error;
      }
      const publishedEnvironmentIds = new Set(
        result.environments.map((environment) => environment.environment_id),
      );
      const missingEnvironment = input.environmentIds.find(
        (environmentId) => !publishedEnvironmentIds.has(environmentId),
      );
      if (missingEnvironment !== undefined) {
        throw new Error(
          `publish succeeded without a revision for environment ${missingEnvironment}`,
        );
      }
      return result;
    },
    onSuccess: (result, input) => {
      forgetRestorePreviews(ref, input.versionIds);
      return Promise.all([
        queries.invalidateQueries({ queryKey: ['values', ref.org, ref.project] }),
        queries.invalidateQueries({ queryKey: ['matrix-signals', ref.org, ref.project] }),
        queries.invalidateQueries({ queryKey: ['matrix-pending', ref.org, ref.project] }),
        ...result.environments.flatMap((published) => {
          const env = { ...ref, environment: published.environment_id };
          return [
            queries.invalidateQueries({ queryKey: revisionsKey(env) }),
            queries.invalidateQueries({ queryKey: pinsKey(env) }),
          ];
        }),
      ]);
    },
  });
}

/** Config-only copy: secret copy stays on Values with its disclosure ceremony. */
export function useCopyMatrixConfig(ref: MatrixRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (input: {
      readonly sourceEnvironment: string;
      readonly key: string;
      readonly destinationEnvironments: readonly string[];
      readonly confirmProtected: boolean;
    }) =>
      parsed(copyValuesOp, {
          path: ref,
          body: {
            source_environment_id: input.sourceEnvironment,
            keys: [input.key],
            destination_environment_ids: [...input.destinationEnvironments],
            confirm_protected: input.confirmProtected,
          },
          ...transport,
        }),
    onSuccess: (result, input) =>
      invalidateAfterCopy(queries, ref, [
        ...new Set([
          ...input.destinationEnvironments,
          ...result.copied.map((copied) => copied.destination_environment_id),
        ]),
      ]),
    onSettled: (_result, _error, input) =>
      queries.invalidateQueries({
        queryKey: windowKey({ ...ref, environment: input.sourceEnvironment }),
      }),
  });
}

/**
 * matrixMutationError turns a refusal into something the human can act on.
 *
 * The server's caller-safe detail is quoted VERBATIM whenever there is one.
 * Every refusal that names a key — a presence veto, a value that fails the
 * current schema, a stale or missing restore preview token — carries it, and
 * mvp-boundary C5 requires a schema-failing restore to block loud naming the
 * keys. Paraphrasing would put a second vocabulary in front of the one the CLI
 * and the audit trail use, and dropping it leaves a 400 with nothing to fix.
 */
export function matrixMutationError(
  error: Error,
  action: 'stage' | 'clear' | 'copy' | 'publish',
  restorePreviewAttached = false,
): string {
  if (error instanceof RestorePreviewSelectionError) {
    return error.message;
  }
  if (action === 'publish' && restorePreviewAttached && error instanceof ApiError && error.status === 409) {
    return 'Publish refused: the restore preview is stale or missing — stage the restore again from the history drawer.';
  }
  if (error instanceof ApiError) {
    const detailed = callerSafeRefusal(error, action === 'publish' ? 'Publish refused' : 'Refused');
    if (detailed !== null) {
      return action === 'publish'
        ? `${detailed} Fix the named key in the matrix row editor, then publish again.`
        : detailed;
    }
    if (error.status === 403) {
      return action === 'publish'
        ? 'You do not have permission to publish the selected drafts.'
        : `You do not have permission to ${action} this value.`;
    }
    if (error.status === 409) {
      return action === 'publish'
        ? 'Publish was refused. Fix the named matrix problems, then retry.'
        : `The server refused this ${action}; reload the matrix and retry.`;
    }
    return action === 'publish'
      ? `The server could not publish the selected drafts (error ${String(error.status)}).`
      : `The server could not ${action} this value (error ${String(error.status)}).`;
  }
  return action === 'publish'
    ? 'The server could not publish the selected drafts.'
    : `The server could not ${action} this value.`;
}
