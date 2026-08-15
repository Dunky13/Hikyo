import { describe, expect, it } from 'vitest';

import { ApiError } from './client.ts';
import {
  matrixPublishValidation,
  parseMatrixEnvironmentSignals,
  readMatrixDraftPreview,
  revisionAdvanced,
  signalsRequireValuesRefresh,
  writeMatrixDraftPreview,
  type MatrixRef,
} from './matrix.ts';

const ref: MatrixRef = { org: 'org_a', project: 'prj_a' };
const envDev = 'env_01989abc-def0-7123-8123-123456789abc';
const keyLog = 'key_01989abc-def0-7123-8123-123456789abc';
const keyOther = 'key_01989abc-def0-7123-8123-123456789abd';
const version = 'ver_01989abc-def0-7123-8123-123456789abc';

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

describe('config draft preview persistence', () => {
  it('survives reload storage and is bound to the immutable version id', () => {
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    };

    writeMatrixDraftPreview(storage, ref, 'ver_1', 'debug');

    expect(readMatrixDraftPreview(storage, ref, 'ver_1')).toBe('debug');
    expect(readMatrixDraftPreview(storage, ref, 'ver_2')).toBeUndefined();
  });
});
