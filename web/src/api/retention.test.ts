import { describe, expect, it } from 'vitest';

import {
  retentionBanner,
  retentionHealthPollMs,
  retentionHealthRefetchInterval,
  storageBanner,
  type RetentionHealth,
} from './retention.ts';

// health builds a full RetentionHealth from partial overrides so each case
// states only the fields it cares about; storage defaults sit below the warn.
function health(over: Partial<RetentionHealth>): RetentionHealth {
  return {
    last_prune_success: '2026-08-15T10:00:00Z',
    stale: false,
    stale_after_seconds: 86400,
    peak_project_bytes: 0,
    storage_warn: false,
    ...over,
  };
}

describe('retentionBanner', () => {
  it('transitions from fresh to stale when the server response changes', () => {
    expect(retentionBanner(health({ stale: false }))).toBeNull();
    expect(
      retentionBanner(health({ last_prune_success: '2026-08-14T10:00:00Z', stale: true })),
    ).toEqual({ kind: 'stale', lastPruneSuccess: '2026-08-14T10:00:00Z' });
  });

  it('shows stale never-recorded health', () => {
    expect(retentionBanner(health({ last_prune_success: null, stale: true }))).toEqual({
      kind: 'stale',
      lastPruneSuccess: null,
    });
  });

  it('stays absent for fresh, forbidden, and not-found results', () => {
    expect(retentionBanner(health({ stale: false }))).toBeNull();
    expect(retentionBanner(null)).toBeNull();
    expect(retentionBanner(undefined)).toBeNull();
  });

  it('fails loud for non-authorization health errors', () => {
    expect(retentionBanner(undefined, true)).toEqual({ kind: 'error' });
  });

  it('keeps a known-stale warning visible through a refetch error', () => {
    expect(
      retentionBanner(health({ last_prune_success: '2026-08-14T10:00:00Z', stale: true }), true),
    ).toEqual({ kind: 'stale', lastPruneSuccess: '2026-08-14T10:00:00Z' });
  });

  it('polls permitted health hourly and stops after a hidden 403/404 result', () => {
    expect(retentionHealthRefetchInterval(undefined)).toBe(retentionHealthPollMs);
    expect(retentionHealthRefetchInterval(null)).toBe(false);
    expect(retentionHealthRefetchInterval(health({ stale: false }))).toBe(60 * 60 * 1_000);
  });
});

describe('storageBanner', () => {
  it('is absent below the warn threshold', () => {
    expect(storageBanner(health({ storage_warn: false, peak_project_bytes: 512 * 1024 * 1024 }))).toBeNull();
    expect(storageBanner(null)).toBeNull();
    expect(storageBanner(undefined)).toBeNull();
  });

  it('surfaces the peak project bytes once the server flags the warn', () => {
    expect(
      storageBanner(health({ storage_warn: true, peak_project_bytes: 1_500_000_000 })),
    ).toEqual({ kind: 'storage', peakProjectBytes: 1_500_000_000 });
  });
});
