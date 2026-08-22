import {
  getRetentionHealthOp,
} from '@hikyo/operations';
import { zRetentionHealth } from '@hikyo/zod';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import type { z } from 'zod';

import { ApiError, parsed } from './client.ts';

export type RetentionHealth = z.infer<typeof zRetentionHealth>;

export const retentionHealthKey = ['retention-health'] as const;
// The health read is audited. Match the hourly scheduler cadence so long-lived
// tabs notice stale/recovered state without turning the instance trail into a
// per-tab heartbeat log.
export const retentionHealthPollMs = 60 * 60 * 1_000;

export function retentionHealthRefetchInterval(health: RetentionHealth | null | undefined) {
  return health === null ? false : retentionHealthPollMs;
}

/**
 * The chrome is shared by ordinary tenant members and instance operators.
 * A uniform 403/404 means this principal has no visible health surface, so it
 * is absence here rather than a noisy global error. Every visible answer is
 * still parsed against the generated contract before the banner sees it.
 */
export function useRetentionHealth(enabled: boolean): UseQueryResult<RetentionHealth | null> {
  return useQuery({
    queryKey: retentionHealthKey,
    queryFn: async () => {
      try {
        return await parsed(getRetentionHealthOp, {});
      } catch (error) {
        if (error instanceof ApiError && (error.status === 403 || error.status === 404)) {
          return null;
        }
        throw error;
      }
    },
    enabled,
    refetchInterval: (query) => retentionHealthRefetchInterval(query.state.data),
    retry: false,
  });
}

export function retentionBanner(health: RetentionHealth | null | undefined, isError = false) {
  if (health?.stale === true) {
    return { kind: 'stale', lastPruneSuccess: health.last_prune_success } as const;
  }
  return isError ? ({ kind: 'error' } as const) : null;
}

/**
 * The per-project storage high-water warn: a project has reached the 1 GiB warn
 * threshold and is heading for the 4 GiB publish refusal. Absent (null) unless
 * the server sets storage_warn, so the banner is silent below the water.
 */
export function storageBanner(health: RetentionHealth | null | undefined) {
  if (health?.storage_warn === true) {
    return { kind: 'storage', peakProjectBytes: health.peak_project_bytes } as const;
  }
  return null;
}
