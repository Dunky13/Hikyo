import { beforeEach, describe, expect, it } from 'vitest';

import { ApiError } from './client.ts';
import {
  matrixPublishValidation,
  matrixMutationError,
  forgetRestorePreviews,
  parseMatrixEnvironmentSignals,
  parseMatrixPendingDrafts,
  pendingConfigPreview,
  rememberRestorePreview,
  restorePreviewFor,
  revisionAdvanced,
  signalsRequireValuesRefresh,
} from './matrix.ts';

const envDev = 'env_01989abc-def0-7123-8123-123456789abc';
const keyLog = 'key_01989abc-def0-7123-8123-123456789abc';
const keyOther = 'key_01989abc-def0-7123-8123-123456789abd';
const version = 'ver_01989abc-def0-7123-8123-123456789abc';
const ref = { org: 'org', project: 'project' };

beforeEach(() => {
  forgetRestorePreviews(ref, [version, 'ver_second', 'ver_other']);
});

describe('restore preview lifecycle', () => {
  it('matches exact sorted version sets without overwriting another restore', () => {
    rememberRestorePreview(ref, [version, 'ver_second'], 'token-one');
    rememberRestorePreview(ref, ['ver_other'], 'token-two');
    expect(restorePreviewFor(ref, ['ver_second', version])).toEqual({ token: 'token-one' });
    expect(restorePreviewFor(ref, ['ver_other'])).toEqual({ token: 'token-two' });
  });

  it('returns overlapping version ids for a partial selection and null for no overlap', () => {
    rememberRestorePreview(ref, [version, 'ver_second'], 'token-one');
    expect(restorePreviewFor(ref, [version, 'ver_other'])).toEqual({ conflict: [version] });
    expect(restorePreviewFor(ref, ['ver_other'])).toBeNull();
  });

  it('keeps the client-side exact-selection refusal actionable', () => {
    rememberRestorePreview(ref, [version, 'ver_second'], 'token-one');
    const preview = restorePreviewFor(ref, [version, 'ver_other']);
    expect(preview).toEqual({ conflict: [version] });
  });

  it('forgets a preview after its versions publish', () => {
    rememberRestorePreview(ref, [version], 'token-one');
    forgetRestorePreviews(ref, [version]);
    expect(restorePreviewFor(ref, [version])).toBeNull();
  });

  it('names a detail-less 409 as stale only when a preview token was attached', () => {
    const conflict = new ApiError(409, 'request failed with 409');
    expect(matrixMutationError(conflict, 'publish', true)).toBe(
      'Publish refused: the restore preview is stale or missing — stage the restore again from the history drawer.',
    );
    expect(matrixMutationError(conflict, 'publish', false)).toBe(
      'Publish was refused. Fix the named matrix problems, then retry.',
    );
  });
});

describe('matrix signal boundary', () => {
  it('refuses a pending version without its operation', () => {
    expect(() =>
      parseMatrixEnvironmentSignals({
        environment_id: envDev,
        revision: 2,
        cells: [
          {
            key_id: keyLog,
            name: 'LOG_LEVEL',
            classification: 'config',
            pending_version_id: version,
            pending_by_others: false,
          },
        ],
      }),
    ).toThrow(/pending_version_id and pending_operation/);
  });

  it('accepts complete pending and absent-pending cells', () => {
    expect(
      parseMatrixEnvironmentSignals({
        environment_id: envDev,
        revision: 2,
        cells: [
          {
            key_id: keyLog,
            name: 'LOG_LEVEL',
            classification: 'config',
            pending_version_id: version,
            pending_operation: 'set',
            pending_by_others: false,
          },
          {
            key_id: keyOther,
            name: 'OTHER',
            classification: 'config',
            pending_by_others: false,
          },
        ],
      }).cells,
    ).toHaveLength(2);
  });
});

describe('matrix cache coherence', () => {
  it('establishes initial ordering, then refreshes only when the signal advances', () => {
    expect(revisionAdvanced(undefined, 2n)).toBe(false);
    expect(revisionAdvanced(2n, 2n)).toBe(false);
    expect(revisionAdvanced(2n, 3n)).toBe(true);
    expect(signalsRequireValuesRefresh(undefined, 2n)).toBe(true);
    expect(signalsRequireValuesRefresh(2n, 2n)).toBe(false);
    expect(signalsRequireValuesRefresh(2n, 3n)).toBe(true);
  });
});

describe('publish validation mapping', () => {
  it('maps a safe named cell refusal to exactly one matrix cell', () => {
    const error = new ApiError(
      400,
      'request failed with 400',
      'key "LOG_LEVEL" is `required_in` environment env_prod and resolves to absent: publish is vetoed',
    );

    expect(
      matrixPublishValidation(error, [{ id: 'key_log', name: 'LOG_LEVEL' }], ['env_dev', 'env_prod']),
    ).toEqual({
      keyId: 'key_log',
      environmentId: 'env_prod',
      message: error.detail,
    });
  });

  it('keeps authorization, conflict, network, and unparsed refusals mutation-level', () => {
    const keys = [{ id: 'key_log', name: 'LOG_LEVEL' }];
    expect(matrixPublishValidation(new ApiError(403, 'forbidden'), keys, ['env_prod'])).toBeNull();
    expect(matrixPublishValidation(new ApiError(409, 'stale'), keys, ['env_prod'])).toBeNull();
    expect(matrixPublishValidation(new Error('offline'), keys, ['env_prod'])).toBeNull();
    expect(matrixPublishValidation(new ApiError(400, 'bad request'), keys, ['env_prod'])).toBeNull();
  });
});

describe('pending draft preview boundary', () => {
  const draft = {
    version_id: version,
    key_id: keyLog,
    name: 'LOG_LEVEL',
    classification: 'config',
    operation: 'set',
    staged_from_revision: 1,
    created_at: '2026-08-15T10:00:00Z',
  };

  it('accepts a revealed config preview and binds it to the signal by version id', () => {
    const drafts = parseMatrixPendingDrafts({
      items: [{ ...draft, revealed: true, value: 'debug' }],
      count: 1,
    });
    const byVersion = new Map(drafts.items.map((item) => [item.version_id, item]));
    const signal: Parameters<typeof pendingConfigPreview>[0] = {
      key_id: keyLog,
      name: 'LOG_LEVEL',
      classification: 'config',
      pending_by_others: false,
      pending_version_id: version,
      pending_operation: 'set',
    };
    expect(pendingConfigPreview(signal, byVersion)).toBe('debug');
    expect(pendingConfigPreview({ ...signal, pending_version_id: 'ver_other' }, byVersion)).toBeUndefined();
    expect(() => pendingConfigPreview({ ...signal, key_id: keyOther }, byVersion)).toThrow(
      'bound to the wrong key',
    );
  });

  it('accepts a hidden config set whose material originated as secret', () => {
    expect(
      parseMatrixPendingDrafts({ items: [{ ...draft, revealed: false }], count: 1 }).items[0],
    ).toMatchObject({ classification: 'config', operation: 'set', revealed: false });
  });

  it('rejects a revealed draft without a value', () => {
    expect(() =>
      parseMatrixPendingDrafts({ items: [{ ...draft, revealed: true }], count: 1 }),
    ).toThrow('pending draft value must appear if and only if revealed is true');
  });

  it('rejects secret material on the preview seam', () => {
    expect(() =>
      parseMatrixPendingDrafts({
        items: [{ ...draft, classification: 'secret', revealed: true, value: 'secret' }],
        count: 1,
      }),
    ).toThrow('secret pending drafts must remain unrevealed');
  });
});
