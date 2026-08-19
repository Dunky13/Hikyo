import { afterAll, describe, expect, it } from 'vitest';

import {
  pinAction,
  pinExpiry,
  pinExpiryInstant,
  pinComparedToLatest,
  revisionActionGate,
  revisionsForKeyFilter,
  defaultPinExpiry,
  historyKeyDisplay,
  pinCeremonyUnit,
  pinSchemaOverrideOffered,
  relativeAge,
  restoreKeyName,
  restoreCeremonyUnit,
  restorePreviewSummary,
  retentionLine,
  SOLE_KEEPER_RELEASE_BUTTON,
  SOLE_KEEPER_RELEASE_TITLE,
  soleKeeperReleaseConsequences,
  soleKeeperPinIds,
  toHistoryRetention,
  workloadLabel,
  type HistoryPin,
  type PinLatestValue,
  type HistoryRetention,
  type HistoryRevision,
  type HistorySnapshotKey,
} from './history-state.ts';

const previousTZ = process.env.TZ;
process.env.TZ = 'America/New_York';
afterAll(() => {
  process.env.TZ = previousTZ;
});

const collectedPolicy = 'keep-if-either(max_age=2160h0m0s,last_revisions=10)';

type LiveRevision = Extract<HistoryRevision, { readonly payloadPresent: true }>;

function revision(overrides: Partial<Omit<LiveRevision, 'payloadPresent'>> = {}): LiveRevision {
  return {
    revision: 3n,
    schemaRevision: 7n,
    publishedBy: 'usr_0198aaaa',
    publishedAt: '2026-08-01T10:00:00Z',
    payloadPresent: true,
    changedKeys: [{ keyId: 'key_log', name: 'LOG_LEVEL', change: 'edited' }],
    ...overrides,
  };
}

describe('revisionActionGate', () => {
  it('allows restore and pin on a retained, non-current revision', () => {
    const gate = revisionActionGate(revision(), 5n);
    expect(gate).toEqual({ restore: true, pin: true, reason: null });
  });

  it('refuses restore on the current revision because it would stage nothing', () => {
    const gate = revisionActionGate(revision({ revision: 5n }), 5n);
    expect(gate.restore).toBe(false);
    expect(gate.pin).toBe(true);
    expect(gate.reason).toBe('r5 is already the current revision — a restore would stage nothing.');
  });

  it('refuses both and names the stamped policy when the payload was collected', () => {
    const gate = revisionActionGate(
      collectedRevision(),
      5n,
    );
    expect(gate).toEqual({
      restore: false,
      pin: false,
      reason: `r3's payload was collected by retention policy ${collectedPolicy} — restore and pin are refused; the lineage stays.`,
    });
  });
});

function collectedRevision(
  overrides: Partial<Omit<Extract<HistoryRevision, { readonly payloadPresent: false }>, 'payloadPresent' | 'collectedPolicy'>> = {},
): Extract<HistoryRevision, { readonly payloadPresent: false }> {
  return {
    revision: 3n,
    schemaRevision: 7n,
    publishedBy: 'usr_0198aaaa',
    publishedAt: '2026-08-01T10:00:00Z',
    payloadPresent: false,
    collectedPolicy,
    changedKeys: [{ keyId: 'key_log', name: 'LOG_LEVEL', change: 'edited' }],
    ...overrides,
  };
}

describe('revisionsForKeyFilter', () => {
  const logRevision = revision({
    revision: 2n,
    changedKeys: [
      { keyId: 'key_log', name: 'LOG_LEVEL', change: 'edited' },
      { keyId: 'key_db', name: 'DB_PASSWORD', change: 'added' },
    ],
  });
  const history: readonly HistoryRevision[] = [
    revision({ revision: 3n, changedKeys: [{ keyId: 'key_db', name: 'DB_PASSWORD', change: 'edited' }] }),
    logRevision,
    revision({ revision: 1n, changedKeys: [{ keyId: 'key_log', name: 'LOG_LEVEL', change: 'added' }] }),
  ];

  it('returns the whole history when no key is filtered', () => {
    expect(revisionsForKeyFilter(history, null).map((r) => r.revision)).toEqual([3n, 2n, 1n]);
  });

  it('keeps only revisions for the immutable key id across a rename', () => {
    const renamed = [
      revision({ revision: 3n, changedKeys: [{ keyId: 'key_log', name: 'APP_LOG_LEVEL', change: 'edited' }] }),
      ...history,
    ];
    expect(revisionsForKeyFilter(renamed, 'key_log').map((r) => r.revision)).toEqual([3n, 2n, 1n]);
  });

  it('does not merge a deleted key with a replacement that reused its name', () => {
    const reusedName = [
      revision({ revision: 4n, changedKeys: [{ keyId: 'key_new', name: 'LOG_LEVEL', change: 'added' }] }),
      ...history,
    ];
    expect(revisionsForKeyFilter(reusedName, 'key_log').map((r) => r.revision)).toEqual([2n, 1n]);
  });

  it('labels the current catalogue name, or the historical name when the key is gone', () => {
    expect(historyKeyDisplay('key_log', [{ id: 'key_log', name: 'APP_LOG_LEVEL' }], logRevision)).toEqual({
      name: 'APP_LOG_LEVEL',
      label: 'APP_LOG_LEVEL (current name)',
      current: true,
    });
    expect(historyKeyDisplay('key_log', [], logRevision)).toEqual({
      name: 'LOG_LEVEL',
      label: 'LOG_LEVEL (historical name; key no longer exists)',
      current: false,
    });
  });

  it('uses the current name for a per-key restore and refuses a deleted key loud', () => {
    expect(restoreKeyName('key_log', [{ id: 'key_log', name: 'APP_LOG_LEVEL' }], logRevision)).toBe('APP_LOG_LEVEL');
    expect(() => restoreKeyName('key_log', [], logRevision)).toThrow(
      'Cannot restore LOG_LEVEL: key key_log no longer exists in the current catalogue.',
    );
  });
});

describe('pinAction', () => {
  it('is a plain pin when the workload follows latest', () => {
    expect(pinAction(undefined, 3n)).toEqual({
      kind: 'pin',
      label: 'Create pin',
    });
  });

  it('is a renew when the workload is already pinned to the same revision', () => {
    expect(pinAction(4n, 4n)).toEqual({
      kind: 'renew',
      label: 'Renew pin on r4',
    });
  });

  it('is a move when the workload is pinned elsewhere', () => {
    expect(pinAction(2n, 4n)).toEqual({
      kind: 'move',
      label: 'Move pin from r2 to r4',
    });
  });
});

describe('pinExpiry', () => {
  const now = new Date('2026-08-19T12:00:00Z');

  it('reports a comfortable pin with no warning', () => {
    expect(pinExpiry('2026-12-19T12:00:00Z', now)).toEqual({
      days: 122,
      tier: 'ok',
      text: 'expires in 122 d',
    });
  });

  it('uses raw-millisecond warning boundaries and separate display rounding', () => {
    expect(pinExpiry('2026-09-18T12:00:00.001Z', now).tier).toBe('ok');
    expect(pinExpiry('2026-09-18T12:00:00Z', now)).toEqual({
      days: 30,
      tier: 'month',
      text: '! expires in 30 d',
    });
    expect(pinExpiry('2026-08-26T12:00:00Z', now)).toEqual({
      days: 7,
      tier: 'week',
      text: '!! expires in 7 d',
    });
    expect(pinExpiry('2026-08-20T12:00:00Z', now)).toEqual({
      days: 1,
      tier: 'day',
      text: '!!! expires in 1 d',
    });
    expect(pinExpiry('2026-08-19T12:00:00.001Z', now)).toEqual({
      days: 1,
      tier: 'day',
      text: '!!! expires today',
    });
    expect(pinExpiry('2026-08-19T12:00:00Z', now)).toEqual({
      days: 0,
      tier: 'expired',
      text: 'expired — still delivering until its payload is collected',
    });
    expect(pinExpiry('2026-08-19T11:59:59.999Z', now)).toEqual({
      days: -1,
      tier: 'expired',
      text: 'expired — still delivering until its payload is collected',
    });
  });
});

describe('soleKeeperPinIds', () => {
  const now = new Date('2026-08-19T12:00:00Z');
  const keepIfEither: HistoryRetention = {
    mode: 'keep-if-either',
    maxAgeSeconds: 90 * 24 * 60 * 60,
    lastRevisions: 2,
  };
  // r5 newest → rank 1, r4 → 2, r3 → 3 (past the last-2 window), and r3 is
  // also older than the 90-day age window, so only a pin holds it.
  const history: readonly HistoryRevision[] = [
    revision({ revision: 5n, publishedAt: '2026-08-18T12:00:00Z' }),
    revision({ revision: 4n, publishedAt: '2026-08-17T12:00:00Z' }),
    revision({ revision: 3n, publishedAt: '2026-01-01T12:00:00Z' }),
  ];

  function pin(overrides: Partial<HistoryPin> = {}): HistoryPin {
    return {
      id: 'pin_a',
      workloadPrincipalId: 'prn_workload_a',
      revision: 3n,
      expiresAt: '2026-11-19T12:00:00Z',
      expired: false,
      schemaOverride: false,
      ...overrides,
    };
  }

  it('finds the pin that is the only thing keeping a past-retention payload', () => {
    expect([...soleKeeperPinIds({ pins: [pin()], revisions: history, policy: keepIfEither, now })])
      .toEqual(['pin_a']);
  });

  it('holds nobody sole when a second live pin keeps the same revision', () => {
    const pins = [pin(), pin({ id: 'pin_b', workloadPrincipalId: 'prn_workload_b' })];
    expect(soleKeeperPinIds({ pins, revisions: history, policy: keepIfEither, now }).size).toBe(0);
  });

  it('exempts a revision still inside the last-N window', () => {
    const pins = [pin({ revision: 4n })];
    expect(soleKeeperPinIds({ pins, revisions: history, policy: keepIfEither, now }).size).toBe(0);
  });

  it('exempts a revision still inside the age window even when it is past last-N', () => {
    const young: readonly HistoryRevision[] = [
      revision({ revision: 5n, publishedAt: '2026-08-18T12:00:00Z' }),
      revision({ revision: 4n, publishedAt: '2026-08-17T12:00:00Z' }),
      revision({ revision: 3n, publishedAt: '2026-08-16T12:00:00Z' }),
    ];
    expect(soleKeeperPinIds({ pins: [pin()], revisions: young, policy: keepIfEither, now }).size).toBe(0);
  });

  it('holds nobody sole under an unlimited policy, where no payload is ever collected', () => {
    const unlimited: HistoryRetention = {
      mode: 'unlimited',
      maxAgeSeconds: null,
      lastRevisions: null,
    };
    expect(soleKeeperPinIds({ pins: [pin()], revisions: history, policy: unlimited, now }).size).toBe(0);
  });

  it('does not call an EXPIRED pin a sole keeper — it no longer holds the payload back', () => {
    const pins = [pin({ expired: true, expiresAt: '2026-08-01T12:00:00Z' })];
    expect(soleKeeperPinIds({ pins, revisions: history, policy: keepIfEither, now }).size).toBe(0);
  });

  it('uses expiresAt rather than the fetch-time expired display flag', () => {
    expect([...soleKeeperPinIds({ pins: [pin({ expired: true })], revisions: history, policy: keepIfEither, now })])
      .toEqual(['pin_a']);
    expect(soleKeeperPinIds({
      pins: [pin({ expired: false, expiresAt: '2026-08-19T11:59:59.999Z' })],
      revisions: history,
      policy: keepIfEither,
      now,
    }).size).toBe(0);
  });

  it('does not call a pin on an ALREADY collected revision a sole keeper', () => {
    const collected: readonly HistoryRevision[] = [
      revision({ revision: 5n, publishedAt: '2026-08-18T12:00:00Z' }),
      revision({ revision: 4n, publishedAt: '2026-08-17T12:00:00Z' }),
      collectedRevision({ revision: 3n, publishedAt: '2026-01-01T12:00:00Z' }),
    ];
    expect(soleKeeperPinIds({ pins: [pin()], revisions: collected, policy: keepIfEither, now }).size).toBe(0);
  });
});

describe('restorePreviewSummary', () => {
  it('counts the two staged operations separately', () => {
    const summary = restorePreviewSummary([
      { keyId: 'k1', name: 'A', classification: 'config', operation: 'set', status: 'edited' },
      { keyId: 'k2', name: 'B', classification: 'secret', operation: 'set', status: 'edited' },
      { keyId: 'k3', name: 'C', classification: 'config', operation: 'unset', status: 'removed' },
    ]);
    expect(summary).toEqual({ set: 2, clear: 1, total: 3, chips: ['2 set', '1 clear'] });
  });

  it('says so when the environment already matches the revision', () => {
    expect(restorePreviewSummary([])).toEqual({
      set: 0,
      clear: 0,
      total: 0,
      chips: ['already matches — nothing to stage'],
    });
  });
});

describe('restoreCeremonyUnit', () => {
  const revisionKeys: readonly HistorySnapshotKey[] = [
    { keyId: 'k_secret', name: 'DB_PASSWORD', classification: 'secret' },
    { keyId: 'k_config', name: 'LOG_LEVEL', classification: 'config' },
    { keyId: 'k_declassified', name: 'PAYMENT_PIN', classification: 'config' },
  ];

  it('enumerates the historical secrets the staging will open', () => {
    expect(
      restoreCeremonyUnit({ revisionKeys, currentCells: [], keyId: null }),
    ).toEqual([{ id: 'k_secret', name: 'DB_PASSWORD' }]);
  });

  it('adds a key whose CURRENT value is a set secret, because the comparison opens it', () => {
    expect(
      restoreCeremonyUnit({
        revisionKeys,
        currentCells: [{ keyId: 'k_config', classification: 'secret', set: true }],
        keyId: null,
      }).map((entry) => entry.id),
    ).toEqual(['k_secret', 'k_config']);
  });

  it('ignores a current secret that is ABSENT, because nothing is compared', () => {
    expect(
      restoreCeremonyUnit({
        revisionKeys,
        currentCells: [{ keyId: 'k_config', classification: 'secret', set: false }],
        keyId: null,
      }).map((entry) => entry.id),
    ).toEqual(['k_secret']);
  });

  it('narrows to one key for a per-key restore', () => {
    expect(restoreCeremonyUnit({ revisionKeys, currentCells: [], keyId: 'k_config' })).toEqual([]);
    expect(
      restoreCeremonyUnit({ revisionKeys, currentCells: [], keyId: 'k_secret' }),
    ).toEqual([{ id: 'k_secret', name: 'DB_PASSWORD' }]);
  });

  it('narrows a renamed secret by immutable key id', () => {
    expect(
      restoreCeremonyUnit({
        revisionKeys: [{ keyId: 'K', name: 'OLD_NAME', classification: 'secret' }],
        currentCells: [{ keyId: 'K', classification: 'secret', set: true }],
        keyId: 'K',
      }),
    ).toEqual([{ id: 'K', name: 'OLD_NAME' }]);
  });
});

describe('pinCeremonyUnit', () => {
  it('unions snapshot-time and current secret classification in both directions', () => {
    expect(
      pinCeremonyUnit(
        [
          { keyId: 'k_secret_then_config', name: 'OLD_SECRET', classification: 'secret' },
          { keyId: 'k_config_then_secret', name: 'NEW_SECRET', classification: 'config' },
          { keyId: 'k_config', name: 'CONFIG', classification: 'config' },
        ],
        [
          { keyId: 'k_secret_then_config', classification: 'config', set: true },
          { keyId: 'k_config_then_secret', classification: 'secret', set: true },
          { keyId: 'k_config', classification: 'config', set: true },
        ],
      ),
    ).toEqual([
      { id: 'k_secret_then_config', name: 'OLD_SECRET' },
      { id: 'k_config_then_secret', name: 'NEW_SECRET' },
    ]);
  });
});

describe('retentionLine', () => {
  it('reads the effective keep-if-either window and marks it inherited', () => {
    expect(
      retentionLine({
        inherited: true,
        mode: 'keep-if-either',
        maxAgeSeconds: 90 * 24 * 60 * 60,
        lastRevisions: 10,
      }),
    ).toEqual({
      window: 'values kept: 90 d or the last 10 revisions, whichever is longer, plus pinned',
      badge: 'inherits org',
      badgeTitle:
        'this project has no retention of its own — it follows the org default and moves when the org value moves',
    });
  });

  it('marks a project override as custom', () => {
    expect(
      retentionLine({
        inherited: false,
        mode: 'keep-if-either',
        maxAgeSeconds: 7 * 24 * 60 * 60,
        lastRevisions: 3,
      }).badge,
    ).toBe('custom');
  });

  it('states an unlimited policy without inventing a window', () => {
    expect(
      retentionLine({ inherited: true, mode: 'unlimited', maxAgeSeconds: null, lastRevisions: null })
        .window,
    ).toBe('values kept: unlimited — no payload is ever collected');
  });
});

describe('pinSchemaOverrideOffered', () => {
  it('does not offer an override for the expiry bound — an override would not fix it', () => {
    expect(pinSchemaOverrideOffered('pin expiry exceeds the maximum 365 days')).toBe(false);
    expect(pinSchemaOverrideOffered('pin expiry must be in the future')).toBe(false);
  });

  it('does not offer an override for the project quota', () => {
    expect(pinSchemaOverrideOffered('pin quota 100 per project is exhausted')).toBe(false);
  });

  it('does not offer an override for unrelated collected, authorization, workload, revision, or expiry refusals', () => {
    for (const refusal of [
      'revision 3 payload was collected by retention policy keep-if-either',
      'reveal-history authorization is required',
      'pin workload principal is required',
      'pin revision must be positive',
      'pin expiry must be in the future',
    ]) {
      expect(pinSchemaOverrideOffered(refusal)).toBe(false);
    }
  });

  it('offers the recorded override for every current-schema refusal validateResolved can raise', () => {
    for (const refusal of [
      'key "DB_POOL_SIZE" is `required_in` environment env_prod and resolves to absent: publish is vetoed',
      'key "DEBUG" is `forbidden_in` environment env_prod and resolves to set: publish is vetoed',
      'value for "WORKERS" is invalid (max: value is above the declared `max` of 8)',
      "key group db resolves partially in environment env_prod: set [DB_HOST], absent [DB_PORT]: a group's presence is all-or-none",
    ]) {
      expect(pinSchemaOverrideOffered(refusal), refusal).toBe(true);
    }
  });

  it('offers nothing when the server named no reason at all', () => {
    expect(pinSchemaOverrideOffered(undefined)).toBe(false);
  });

  it('does not offer an override for an incomplete value refusal prefix', () => {
    expect(pinSchemaOverrideOffered('value for "WORKERS"')).toBe(false);
  });
});

describe('defaultPinExpiry', () => {
  it('adds 180 local calendar days and submits the end of the chosen local day', () => {
    expect(defaultPinExpiry(new Date('2026-03-07T15:00:00Z'))).toBe('2026-09-03');
    expect(pinExpiryInstant('2026-03-08')).toBe('2026-03-09T03:59:59.999Z');
  });

  it('refuses an impossible date input loudly', () => {
    expect(() => pinExpiryInstant('2026-02-30')).toThrow('Invalid pin expiry date: 2026-02-30');
  });
});

describe('sole-keeper release copy', () => {
  it('states collection eligibility rather than immediate deletion', () => {
    expect(SOLE_KEEPER_RELEASE_TITLE).toBe('Release sole-keeper pin');
    expect(SOLE_KEEPER_RELEASE_BUTTON).toBe('Release pin — values become eligible for collection');
    expect(soleKeeperReleaseConsequences(3n)).toBe(
      "Releasing makes r3's values eligible for collection at the next retention sweep — they will then be deleted permanently.",
    );
  });
});

describe('shared history display mappers', () => {
  it('maps the API retention shape once', () => {
    expect(toHistoryRetention({
      mode: 'keep-if-either',
      max_age_seconds: 60,
      last_revisions: 2,
    })).toEqual({ mode: 'keep-if-either', maxAgeSeconds: 60, lastRevisions: 2 });
  });

  it('labels a workload by name with a stable shortened-id fallback', () => {
    const names = new Map([['prn_known', 'deploy']]);
    expect(workloadLabel('prn_known', names)).toBe('deploy');
    expect(workloadLabel('prn_0198aaaabbbb', names)).toBe('prn_0198aaaa…');
  });
});

describe('pinComparedToLatest', () => {
  const revisionKeys: readonly HistorySnapshotKey[] = [
    { keyId: 'k_same', name: 'SAME', classification: 'config' },
    { keyId: 'k_changed', name: 'CHANGED', classification: 'config' },
    { keyId: 'k_removed', name: 'REMOVED', classification: 'config' },
    { keyId: 'k_secret', name: 'SECRET', classification: 'secret' },
  ];

  it('phrases config presence and value changes from the pinned workload view', () => {
    expect(pinComparedToLatest({
      revision: 3n,
      revisionKeys,
      historical: [
        { name: 'SAME', classification: 'config', revealed: true, value: 'same' },
        { name: 'CHANGED', classification: 'config', revealed: true, value: 'old' },
        { name: 'REMOVED', classification: 'config', revealed: true, value: 'kept' },
        { name: 'SECRET', classification: 'secret', revealed: false },
      ],
      latest: [
        { keyId: 'k_same', name: 'SAME', classification: 'config', set: true, revealed: true, value: 'same' },
        { keyId: 'k_changed', name: 'CHANGED', classification: 'config', set: true, revealed: true, value: 'new' },
        { keyId: 'k_removed', name: 'REMOVED', classification: 'config', set: false, revealed: false },
        { keyId: 'k_secret', name: 'SECRET', classification: 'secret', set: true, revealed: false },
        { keyId: 'k_added', name: 'ADDED', classification: 'config', set: true, revealed: true, value: 'latest' },
      ],
      laterRevisions: [revision({ revision: 4n, changedKeys: [{ keyId: 'k_secret', name: 'SECRET', change: 'edited' }] })],
    })).toEqual({
      lines: [
        'CHANGED stays at old — latest: new',
        'keeps REMOVED',
        'SECRET written again since r3 (r4)',
        "won't have ADDED",
      ],
      unchangedConfigKeys: 1,
    });
  });

  it('uses lineage alone for an unchanged secret and refuses secret material', () => {
    const secretRevisionKeys: readonly HistorySnapshotKey[] = [
      { keyId: 'k_secret', name: 'SECRET', classification: 'secret' },
    ];
    const latest: readonly PinLatestValue[] = [
      {
        keyId: 'k_secret',
        name: 'SECRET',
        classification: 'secret',
        set: true,
        revealed: false,
      },
    ];
    const laterRevisions: readonly HistoryRevision[] = [];
    const base = {
      revision: 3n,
      revisionKeys: secretRevisionKeys,
      latest,
      laterRevisions,
    };
    expect(pinComparedToLatest({
      ...base,
      historical: [{ name: 'SECRET', classification: 'secret', revealed: false }],
    }).lines).toEqual(['SECRET not written since r3']);
    expect(() => pinComparedToLatest({
      ...base,
      historical: [{ name: 'SECRET', classification: 'secret', revealed: true, value: 'forbidden' }],
    })).toThrow('historical secret SECRET exposed material in a pin comparison.');
  });
});

describe('relativeAge', () => {
  const now = new Date('2026-08-19T12:00:00Z');

  it('reads in minutes, hours and days as the gap grows', () => {
    expect(relativeAge('2026-08-19T11:40:00Z', now)).toBe('20 minutes ago');
    expect(relativeAge('2026-08-19T04:00:00Z', now)).toBe('8 hours ago');
    expect(relativeAge('2026-08-05T12:00:00Z', now)).toBe('14 days ago');
  });

  it('says "just now" rather than "0 minutes ago"', () => {
    expect(relativeAge('2026-08-19T11:59:50Z', now)).toBe('now');
  });
});
