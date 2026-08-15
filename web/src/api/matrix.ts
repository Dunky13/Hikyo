import {
  clearValue,
  copyValues,
  getEnvironmentSettings,
  getEnvironmentSignals,
  listKeyGroups,
  listKeys,
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
  zProjectList,
  zPublishResult,
  zValueList,
} from '@hikyo/zod';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';

import { ApiError, parsed } from './client.ts';
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

type PreviewStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function matrixDraftPreviewKey(ref: MatrixRef, versionId: string): string {
  return `hikyo:matrix-draft:${ref.org}:${ref.project}:${versionId}`;
}

export function writeMatrixDraftPreview(
  storage: PreviewStorage,
  ref: MatrixRef,
  versionId: string,
  value: string,
): void {
  storage.setItem(matrixDraftPreviewKey(ref, versionId), value);
}

export function readMatrixDraftPreview(
  storage: PreviewStorage,
  ref: MatrixRef,
  versionId: string,
): string | undefined {
  return storage.getItem(matrixDraftPreviewKey(ref, versionId)) ?? undefined;
}

export function removeMatrixDraftPreview(
  storage: PreviewStorage,
  ref: MatrixRef,
  versionId: string,
): void {
  storage.removeItem(matrixDraftPreviewKey(ref, versionId));
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
        if (revisionAdvanced(previous?.revision, next.revision)) {
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

  return { environments, keys, groups, values, signals, settings };
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
      const result = await parsed(
        publishPendingChanges({
          path: { ...ref, environment: input.addressedEnvironment },
          body: { version_ids: [...input.versionIds] },
        }),
        zPublishResult,
      );
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
    onSuccess: () =>
      Promise.all([
        queries.invalidateQueries({ queryKey: ['values', ref.org, ref.project] }),
        queries.invalidateQueries({ queryKey: ['matrix-signals', ref.org, ref.project] }),
      ]),
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
      ]),
  });
}

export function matrixMutationError(
  error: Error,
  action: 'stage' | 'clear' | 'copy' | 'publish',
): string {
  if (error instanceof ApiError) {
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
