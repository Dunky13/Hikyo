import { describe, expect, it } from 'vitest';

import {
  historyHref,
  revisionNumber,
  zHistoryRevisionList,
  zHistoryRollbackResult,
} from './history.ts';

const lineage = {
  revision: 3,
  schema_revision: 7,
  published_by: 'usr_0198aaaa-bbbb-7ccc-8ddd-eeeeffff0001',
  published_at: '2026-08-01T10:00:00Z',
  changed_keys: [{ key_id: 'key_0198aaaa-bbbb-7ccc-8ddd-eeeeffff0002', name: 'LOG_LEVEL', change: 'edited' }],
  payload_present: true,
};

describe('history revision boundary', () => {
  it('accepts a live revision that names no collection policy', () => {
    const parsed = zHistoryRevisionList.parse({ items: [lineage], count: 1 });
    expect(parsed.items[0]?.payload_present).toBe(true);
    expect(parsed.items[0]?.revision).toBe(3n);
  });

  it('accepts a collected revision that names the policy that collected it', () => {
    const parsed = zHistoryRevisionList.parse({
      items: [{ ...lineage, payload_present: false, collected_policy: 'keep-if-either(x)' }],
      count: 1,
    });
    expect(parsed.items[0]?.collected_policy).toBe('keep-if-either(x)');
  });

  it('refuses a collected revision with no policy — the refusal has to name one', () => {
    expect(() => zHistoryRevisionList.parse({ items: [{ ...lineage, payload_present: false }], count: 1 }))
      .toThrow(/collected revision must name the policy/);
  });

  it('refuses a live revision carrying a collection policy', () => {
    expect(() =>
      zHistoryRevisionList.parse({
        items: [{ ...lineage, collected_policy: 'keep-if-either(x)' }],
        count: 1,
      }),
    ).toThrow(/only a collected revision carries/);
  });
});

describe('restore result boundary', () => {
  const preview = (change: Record<string, unknown>) => ({
    revision: 3,
    changes: [],
    preview: {
      token: 'tok',
      environments: [
        {
          environment_id: 'env_0198aaaa-bbbb-7ccc-8ddd-eeeeffff0003',
          base_revision: 5,
          schema_revision: 7,
          protected: false,
          changes: [change],
        },
      ],
    },
  });

  const configSet = {
    version_id: 'pcv_0198aaaa-bbbb-7ccc-8ddd-eeeeffff0004',
    key_id: 'key_0198aaaa-bbbb-7ccc-8ddd-eeeeffff0002',
    name: 'LOG_LEVEL',
    classification: 'config',
    operation: 'set',
    status: 'edited',
    before: 'warn',
    after: 'debug',
  };

  it('keeps config plaintext, which is what the impact preview is for', () => {
    const parsed = zHistoryRollbackResult.parse(preview(configSet));
    expect(parsed.preview.environments[0]?.changes[0]?.after).toBe('debug');
  });

  it('refuses a secret row carrying material on either side', () => {
    expect(() => zHistoryRollbackResult.parse(preview({ ...configSet, classification: 'secret' })))
      .toThrow(/secret impact rows are status-only/);
  });

  it('refuses a clear that claims an after value', () => {
    expect(() =>
      zHistoryRollbackResult.parse(preview({ ...configSet, operation: 'unset', status: 'removed' })),
    ).toThrow(/a clear has no after value/);
  });
});

describe('historyHref', () => {
  it('encodes path and query parameters while keeping key as the immutable id', () => {
    expect(historyHref({
      org: 'team/one',
      project: 'app name',
      env: 'env?prod',
      keyId: 'key/id',
      rev: 42n,
    })).toBe('/orgs/team%2Fone/projects/app%20name/matrix/history?env=env%3Fprod&key=key%2Fid&rev=42');
  });
});

describe('revisionNumber', () => {
  it('narrows a parsed revision to the request shape', () => {
    expect(revisionNumber(42n)).toBe(42);
  });

  it('fails loud rather than rounding a revision it cannot address exactly', () => {
    expect(() => revisionNumber(BigInt(Number.MAX_SAFE_INTEGER) + 1n)).toThrow(/outside the range/);
    expect(() => revisionNumber(0n)).toThrow(/outside the range/);
  });
});
