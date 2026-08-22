import {
  createRevisionPinOp,
  getProjectRetentionOp,
  getRevisionOp,
  listRevisionPinsOp,
  listRevisionsOp,
  releaseRevisionPinOp,
  rollbackRevisionOp,
} from '@hikyo/operations';
import {
  zProjectRetentionPolicy,
  zRevisionDetail,
  zRevisionList,
  zRevisionPinList,
  zRollbackResult,
} from '@hikyo/zod';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import { z } from 'zod';

import { ApiError, ok, parsed } from './client.ts';
import {
  pinsKey,
  projectRetentionKey,
  revisionDetailKey,
  revisionsKey,
  valuesKey,
  type EnvRef,
  type MatrixRef,
} from './keys.ts';
import { useTransport } from './transport.tsx';

export {
  pinsKey,
  projectRetentionKey,
  revisionDetailKey,
  revisionsKey,
} from './keys.ts';

/**
 * The revision-history API boundary (#59).
 *
 * Everything the drawer reads crosses the generated Zod at this seam, and two
 * contract invariants are re-stated as refinements because they are the ones
 * whose violation would be a DISCLOSURE rather than a rendering bug:
 *
 *  1. A collected revision names the policy that collected it, and a live one
 *     names none. That pairing is what makes the drawer's refusal quotable.
 *  2. An impact row for a `secret` key carries no material on either side —
 *     not a plaintext, not a length, not a comparison status beyond
 *     write-presence — and a `unset` row carries no `after` at all.
 */

export type HistoryRevisionList = z.infer<typeof zRevisionList>;
export type HistoryRevisionItem = HistoryRevisionList['items'][number];
export type HistoryRevisionDetail = z.infer<typeof zRevisionDetail>;
export type RevisionPinList = z.infer<typeof zRevisionPinList>;
export type RevisionPinItem = RevisionPinList['items'][number];
export type RestoreResult = z.infer<typeof zRollbackResult>;
export type ProjectRetention = z.infer<typeof zProjectRetentionPolicy>;

function refineCollectionBit(
  entry: { readonly payload_present: boolean; readonly collected_policy?: string | undefined },
  context: z.RefinementCtx,
  path: readonly (string | number)[],
): void {
  if (!entry.payload_present && (entry.collected_policy ?? '') === '') {
    context.addIssue({
      code: 'custom',
      path: [...path, 'collected_policy'],
      message: 'a collected revision must name the policy that collected it',
    });
  }
  if (entry.payload_present && entry.collected_policy !== undefined) {
    context.addIssue({
      code: 'custom',
      path: [...path, 'collected_policy'],
      message: 'only a collected revision carries a collection policy',
    });
  }
}

export const zHistoryRevisionList = zRevisionList.superRefine((list, context) => {
  list.items.forEach((item, index) => {
    refineCollectionBit(item, context, ['items', index]);
  });
});

export const zHistoryRevisionDetail = zRevisionDetail;

export const zHistoryRollbackResult = zRollbackResult.superRefine((result, context) => {
  result.preview.environments.forEach((environment, environmentIndex) => {
    environment.changes.forEach((change, changeIndex) => {
      const path = ['preview', 'environments', environmentIndex, 'changes', changeIndex] as const;
      if (change.classification === 'secret' && (change.before !== undefined || change.after !== undefined)) {
        context.addIssue({
          code: 'custom',
          path: [...path],
          message: 'secret impact rows are status-only and must carry no material',
        });
      }
      if (change.operation === 'unset' && change.after !== undefined) {
        context.addIssue({
          code: 'custom',
          path: [...path, 'after'],
          message: 'a clear has no after value',
        });
      }
    });
  });
});

/**
 * revisionNumber narrows a parsed revision back to the wire's request shape.
 *
 * Responses parse `int64` to `bigint` (no precision loss); the generated
 * REQUEST types are plain `number`, which is the generator's shape and not
 * something this file gets to change. The conversion is therefore explicit and
 * fails loud past `Number.MAX_SAFE_INTEGER` rather than silently addressing a
 * revision nobody asked for — a rounded revision number in a restore or a pin
 * is the wrong snapshot, delivered confidently.
 */
export function revisionNumber(revision: bigint): number {
  if (revision > BigInt(Number.MAX_SAFE_INTEGER) || revision < 1n) {
    throw new Error(`revision ${String(revision)} is outside the range this client can address`);
  }
  return Number(revision);
}

export function historyHref(input: {
  readonly org: string;
  readonly project: string;
  readonly env?: string;
  readonly keyId?: string;
  readonly rev?: bigint;
}): string {
  const query = [
    input.env === undefined ? null : `env=${encodeURIComponent(input.env)}`,
    input.keyId === undefined ? null : `key=${encodeURIComponent(input.keyId)}`,
    input.rev === undefined ? null : `rev=${encodeURIComponent(String(input.rev))}`,
  ].filter((part) => part !== null);
  const path =
    `/orgs/${encodeURIComponent(input.org)}/projects/${encodeURIComponent(input.project)}` +
    '/matrix/history';
  return query.length === 0 ? path : `${path}?${query.join('&')}`;
}

const enabledEnv = (env: EnvRef): boolean =>
  env.org !== '' && env.project !== '' && env.environment !== '';

export function useRevisionHistory(env: EnvRef): UseQueryResult<HistoryRevisionList> {
  const transport = useTransport();
  return useQuery({
    queryKey: revisionsKey(env),
    queryFn: async () =>
      zHistoryRevisionList.parse(
        await parsed(listRevisionsOp, { path: { ...env }, ...transport }),
      ),
    enabled: enabledEnv(env),
    retry: false,
  });
}

/**
 * useRevisionDetail reads ONE revision's delivered key set.
 *
 * It is deliberately gated on the lineage row's collection bit rather than
 * fetched optimistically: `getRevision` derives a change token over the
 * snapshot's manifest, so it refuses a collected revision with a 409. Asking
 * anyway would turn "this payload was collected, here is the policy" — a fact
 * the history row already carries — into an error state the drawer would have
 * to un-explain.
 */
export function useRevisionDetail(
  env: EnvRef,
  revision: bigint | null,
  payloadPresent: boolean,
): UseQueryResult<HistoryRevisionDetail> {
  const label = revision === null ? '' : String(revision);
  const transport = useTransport();
  return useQuery({
    queryKey: revisionDetailKey(env, label),
    queryFn: () =>
      parsed(getRevisionOp, { path: { ...env, revision: label }, ...transport }),
    enabled: enabledEnv(env) && revision !== null && payloadPresent,
    retry: false,
  });
}

export function useRevisionPins(env: EnvRef): UseQueryResult<RevisionPinList> {
  const transport = useTransport();
  return useQuery({
    queryKey: pinsKey(env),
    queryFn: () => parsed(listRevisionPinsOp, { path: { ...env }, ...transport }),
    enabled: enabledEnv(env),
    retry: false,
  });
}

/**
 * useProjectRetention is the drawer head's read-only line.
 *
 * The project endpoint answers with the EFFECTIVE policy and whether it is
 * inherited, which is the whole line — so the org read is not fetched here. A
 * second request to render a badge the first response already determines is a
 * second thing that can fail.
 */
export function useProjectRetention(ref: MatrixRef): UseQueryResult<ProjectRetention> {
  const transport = useTransport();
  return useQuery({
    queryKey: projectRetentionKey(ref),
    queryFn: () => parsed(getProjectRetentionOp, { path: { ...ref }, ...transport }),
    enabled: ref.org !== '' && ref.project !== '',
    retry: false,
  });
}

/**
 * useRestoreRevision stages the two-way diff as ordinary drafts.
 *
 * Nothing is published here. The returned preview token is what publish must
 * carry: restore-authored drafts are refused without it, and it binds the exact
 * versions, base revision, schema revision and grant generation the preview was
 * computed against.
 */
export function useRestoreRevision(env: EnvRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: async (input: { readonly revision: bigint; readonly key?: string }) =>
      zHistoryRollbackResult.parse(
        await parsed(rollbackRevisionOp, {
          path: { ...env, revision: revisionNumber(input.revision) },
          body: input.key === undefined ? {} : { key: input.key },
          ...transport,
        }),
      ),
    onSuccess: () =>
      Promise.all([
        queries.invalidateQueries({ queryKey: valuesKey(env) }),
        queries.invalidateQueries({ queryKey: ['matrix-signals', env.org, env.project] }),
        queries.invalidateQueries({ queryKey: ['matrix-pending', env.org, env.project] }),
      ]),
  });
}

export function useSetRevisionPin(env: EnvRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (input: {
      readonly workloadPrincipalID: string;
      readonly revision: bigint;
      readonly expiresAt: string;
      readonly overrideSchema: boolean;
    }) =>
      parsed(createRevisionPinOp, {
          path: { ...env },
          body: {
            workload_principal_id: input.workloadPrincipalID,
            revision: revisionNumber(input.revision),
            expires_at: input.expiresAt,
            override_schema: input.overrideSchema,
          },
          ...transport,
        }),
    onSuccess: () => queries.invalidateQueries({ queryKey: pinsKey(env) }),
  });
}

export function useReleaseRevisionPin(env: EnvRef) {
  const queries = useQueryClient();
  const transport = useTransport();
  return useMutation({
    mutationFn: (workloadPrincipalID: string) =>
      ok(releaseRevisionPinOp, { path: { ...env, workloadPrincipal: workloadPrincipalID }, ...transport }),
    onSuccess: () =>
      Promise.all([
        queries.invalidateQueries({ queryKey: pinsKey(env) }),
        queries.invalidateQueries({ queryKey: revisionsKey(env) }),
      ]),
  });
}

export type HistoryAction = 'restore' | 'pin' | 'release';

/** Quotes a caller-safe API detail without rewording it. */
export function callerSafeRefusal(error: unknown, prefix: string): string | null {
  if (error instanceof ApiError && error.detail !== undefined && error.detail !== '') {
    return `${prefix}: ${error.detail}`;
  }
  return null;
}

/**
 * historyRefusalText surfaces a refusal by name.
 *
 * The server's caller-safe detail is quoted verbatim wherever there is one:
 * every refusal on this surface — collected payload, schema failure, expiry
 * bound, quota, missing reveal-history — is named by the service, and
 * paraphrasing it here would put a second, drifting vocabulary in front of the
 * one the CLI and the audit trail use. Only a refusal with no detail gets a
 * sentence of our own, and it says which status it was.
 */
export function historyRefusalText(error: unknown, action: HistoryAction): string {
  const verb = {
    restore: 'stage this restore',
    pin: 'pin this revision',
    release: 'release this pin',
  }[action];
  const detailed = callerSafeRefusal(error, 'Refused');
  if (detailed !== null) {
    return detailed;
  }
  if (error instanceof ApiError) {
    if (error.status === 403) {
      return (
        `You may not ${verb} here. A historical secret needs reveal-history, and a ` +
        'protected environment needs a fresh passkey ceremony for exactly these keys.'
      );
    }
    if (error.status === 404) {
      return `The server does not have that revision any more, so it could not ${verb}.`;
    }
    return `The server could not ${verb} (error ${String(error.status)}).`;
  }
  return `The server could not ${verb}.`;
}
