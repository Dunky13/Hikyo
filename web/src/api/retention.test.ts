import { describe, expect, it } from 'vitest';

import {
  retentionBanner,
  retentionHealthPollMs,
  retentionHealthRefetchInterval,
} from './retention.ts';

describe('retentionBanner', () => {
  it('transitions from fresh to stale when the server response changes', () => {
    expect(
      retentionBanner({
        last_prune_success: '2026-08-15T10:00:00Z',
        stale: false,
        stale_after_seconds: 86400,
      }),
    ).toBeNull();
    expect(
      retentionBanner({
        last_prune_success: '2026-08-14T10:00:00Z',
        stale: true,
        stale_after_seconds: 86400,
      }),
    ).toEqual({ kind: 'stale', lastPruneSuccess: '2026-08-14T10:00:00Z' });
  });

  it('shows stale never-recorded health', () => {
    expect(
      retentionBanner({ last_prune_success: null, stale: true, stale_after_seconds: 86400 }),
    ).toEqual({ kind: 'stale', lastPruneSuccess: null });
  });

  it('stays absent for fresh, forbidden, and not-found results', () => {
    expect(
      retentionBanner({
        last_prune_success: '2026-08-15T10:00:00Z',
        stale: false,
        stale_after_seconds: 86400,
      }),
    ).toBeNull();
    expect(retentionBanner(null)).toBeNull();
    expect(retentionBanner(undefined)).toBeNull();
  });

  it('fails loud for non-authorization health errors', () => {
    expect(retentionBanner(undefined, true)).toEqual({ kind: 'error' });
  });

  it('keeps a known-stale warning visible through a refetch error', () => {
    expect(
      retentionBanner(
        {
          last_prune_success: '2026-08-14T10:00:00Z',
          stale: true,
          stale_after_seconds: 86400,
        },
        true,
      ),
    ).toEqual({ kind: 'stale', lastPruneSuccess: '2026-08-14T10:00:00Z' });
  });

  it('polls permitted health hourly and stops after a hidden 403/404 result', () => {
    expect(retentionHealthRefetchInterval(undefined)).toBe(retentionHealthPollMs);
    expect(retentionHealthRefetchInterval(null)).toBe(false);
    expect(
      retentionHealthRefetchInterval({
        last_prune_success: '2026-08-15T10:00:00Z',
        stale: false,
        stale_after_seconds: 86400,
      }),
    ).toBe(60 * 60 * 1_000);
  });
});
