import {
  clearValue,
  copyValues,
  getEnvironmentSettings,
  getEnvironmentSignals,
  listKeyGroups,
  listKeys,
  listPendingDrafts,
  listProjects,
  listValues,
  publishPendingChanges,
  setValue,
} from '@hikyo/client';
import {
  zEnvironmentSignals,
  zCopyValuesResult,
  zEnvironmentSettings,
  zKeyGroupList,
  zKeyList,
  zPendingChange,
  zPendingDraftList,
  zProjectList,
  zPublishResult,
  zValueList,
} from '@hikyo/zod';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';

import { ApiError, parsed } from './client.ts';
import { callerSafeRefusal, pinsKey, revisionsKey } from './history.ts';
import { useEnvironments, valuesKey, type EnvRef } from './values.ts';

/**
 * Whole-project matrix API boundary.
 *
 * The matrix reads one project catalogue and then fans out over the project's
 * environments. Every body crosses the generated Zod schema at this boundary;
 * the component receives only parsed domain records. Signals poll because the
 * API documents this endpoint as the fallback when the advisory SSE stream is
 * unavailable, and this surface does not need a second live-update protocol.
 */

export type MatrixRef = { readonly org: string; readonly project: string };
export type MatrixKeyList = z.infer<typeof zKeyList>;
export type MatrixEnvironmentSignals = z.infer<typeof zEnvironmentSignals>;
export type MatrixSignalCell = MatrixEnvironmentSignals['cells'][number];

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

const matrixKeysKey = (ref: MatrixRef): readonly [string, string, string] =>
  ['matrix-keys', ref.org, ref.project];
const matrixGroupsKey = (ref: MatrixRef): readonly [string, string, string] =>
  ['matrix-groups', ref.org, ref.project];
const signalsKey = (
  ref: MatrixRef,
  environment: string,
): readonly [string, string, string, string] =>
  ['matrix-signals', ref.org, ref.project, environment];
const settingsKey = (
  ref: MatrixRef,
  environment: string,
): readonly [string, string, string, string] =>
  ['matrix-settings', ref.org, ref.project, environment];
const pendingDraftsKey = (
  ref: MatrixRef,
  environment: string,
): readonly [string, string, string, string] =>
  ['matrix-pending', ref.org, ref.project, environment];

export function useProjects(org: string) {
  return useQuery({
    queryKey: ['projects', org],
    queryFn: () => parsed(listProjects({ path: { org } }), zProjectList),
    enabled: org !== '',
    retry: false,
  });
}

export function useMatrixProject(ref: MatrixRef) {
  const queries = useQueryClient();
  const environmentRef: EnvRef = { ...ref, environment: '' };
  const environments = useEnvironments(environmentRef);
  const keys = useQuery({
    queryKey: matrixKeysKey(ref),
    queryFn: () => parsed(listKeys({ path: ref }), zKeyList),
    enabled: ref.org !== '' && ref.project !== '',
    retry: false,
  });
  const groups = useQuery({
    queryKey: matrixGroupsKey(ref),
    queryFn: () => parsed(listKeyGroups({ path: ref }), zKeyGroupList),
    enabled: ref.org !== '' && ref.project !== '',
    retry: false,
  });
  const environmentItems = environments.data?.items ?? [];
  const values = useQueries({
    queries: environmentItems.map((environment) => ({
      queryKey: valuesKey({ ...ref, environment: environment.id }),
      queryFn: () =>
        parsed(
          listValues({ path: { ...ref, environment: environment.id } }),
          zValueList,
        ),
      retry: false,
    })),
  });
  const settings = useQueries({
    queries: environmentItems.map((environment) => ({
      queryKey: settingsKey(ref, environment.id),
      queryFn: () =>
        parsed(
          getEnvironmentSettings({
            path: { ...ref, environment: environment.id },
          }),
          zEnvironmentSettings,
        ),
      retry: false,
    })),
  });
  const signals = useQueries({
    queries: environmentItems.map((environment) => ({
      queryKey: signalsKey(ref, environment.id),
      queryFn: async () => {
        const key = signalsKey(ref, environment.id);
        const previous = queries.getQueryData<MatrixEnvironmentSignals>(key);
        const next = await parsed(
          getEnvironmentSignals({
            path: { ...ref, environment: environment.id },
          }),
          zMatrixEnvironmentSignals,
        );
        if (signalsRequireValuesRefresh(previous?.revision, next.revision)) {
          await queries.invalidateQueries({
            queryKey: valuesKey({ ...ref, environment: environment.id }),
          });
        }
        return next;
      },
      refetchInterval: 2_000,
      retry: false,
    })),
  });
  const pendingDrafts = useQueries({
    queries: environmentItems.map((environment) => ({
      queryKey: pendingDraftsKey(ref, environment.id),
      queryFn: () =>
        parsed(
          listPendingDrafts({ path: { ...ref, environment: environment.id } }),
          zMatrixPendingDraftList,
        ),
      retry: false,
    })),
  });

  return { environments, keys, groups, values, signals, settings, pendingDrafts };
}

export function useStageMatrixValue(ref: MatrixRef) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { readonly environment: string; readonly key: string; readonly value: string }) =>
      parsed(
        setValue({
          path: { ...ref, environment: input.environment, key: input.key },
          body: { value: input.value },
        }),
        zPendingChange,
      ),
    onSuccess: (_result, input) =>
      Promise.all([
        queries.invalidateQueries({ queryKey: valuesKey({ ...ref, environment: input.environment }) }),
        queries.invalidateQueries({ queryKey: signalsKey(ref, input.environment) }),
        queries.invalidateQueries({ queryKey: pendingDraftsKey(ref, input.environment) }),
      ]),
  });
}

export function useClearMatrixValue(ref: MatrixRef) {
  const queries = useQueryClient();
  return useMutation({
    mutationFn: (input: { readonly environment: string; readonly key: string }) =>
      parsed(
        clearValue({ path: { ...ref, environment: input.environment, key: input.key } }),
        zPendingChange,
      ),
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
        result = await parsed(
          publishPendingChanges({
            path: { ...ref, environment: input.addressedEnvironment },
            body: {
              version_ids: [...input.versionIds],
              ...(previewToken === undefined ? {} : { preview_token: previewToken }),
            },
          }),
          zPublishResult,
        );
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
  return useMutation({
    mutationFn: (input: {
      readonly sourceEnvironment: string;
      readonly key: string;
      readonly destinationEnvironments: readonly string[];
      readonly confirmProtected: boolean;
    }) =>
      parsed(
        copyValues({
          path: ref,
          body: {
            source_environment_id: input.sourceEnvironment,
            keys: [input.key],
            destination_environment_ids: [...input.destinationEnvironments],
            confirm_protected: input.confirmProtected,
          },
        }),
        zCopyValuesResult,
      ),
    onSuccess: () =>
      Promise.all([
        queries.invalidateQueries({ queryKey: ['values', ref.org, ref.project] }),
        queries.invalidateQueries({ queryKey: ['matrix-signals', ref.org, ref.project] }),
        queries.invalidateQueries({ queryKey: ['matrix-pending', ref.org, ref.project] }),
      ]),
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
