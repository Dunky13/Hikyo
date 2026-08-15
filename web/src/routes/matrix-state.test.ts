import { describe, expect, it } from 'vitest';

import {
  copyRequiresProtectedConfirmation,
  computeMatrixProblems,
  groupProblemCounts,
  keysForMatrixFilter,
  blockedPublishEnvironmentIds,
  canClearMatrixCell,
  draftValueForMatrixCell,
  requiredInEnvironment,
  toggleVisibleEnvironment,
  validateMatrixDraft,
  type MatrixStateKey,
  type MatrixStateValue,
} from './matrix-state.ts';

const environments: readonly string[] = ['env_dev', 'env_prod'];

const keys: readonly MatrixStateKey[] = [
  {
    id: 'key_required',
    name: 'REQUIRED_KEY',
    groupId: 'group_app',
    requiredIn: { mode: 'all' },
  },
  {
    id: 'key_optional',
    name: 'OPTIONAL_KEY',
    groupId: 'group_ops',
    requiredIn: { mode: 'none' },
  },
];

const values: readonly MatrixStateValue[] = [
  { keyId: 'key_required', environmentId: 'env_dev', set: true },
  {
    keyId: 'key_required',
    environmentId: 'env_prod',
    set: true,
    pendingOperation: 'unset',
  },
  { keyId: 'key_optional', environmentId: 'env_dev', set: true },
  { keyId: 'key_optional', environmentId: 'env_prod', set: true },
];

describe('requiredInEnvironment', () => {
  it('keeps symbolic all and explicit environment membership distinct', () => {
    expect(requiredInEnvironment({ mode: 'all' }, 'future_env')).toBe(true);
    expect(
      requiredInEnvironment(
        { mode: 'explicit', environmentIds: ['env_prod'] },
        'env_prod',
      ),
    ).toBe(true);
    expect(
      requiredInEnvironment(
        { mode: 'explicit', environmentIds: ['env_prod'] },
        'env_dev',
      ),
    ).toBe(false);
    expect(requiredInEnvironment({ mode: 'none' }, 'env_prod')).toBe(false);
  });
});

describe('computeMatrixProblems', () => {
  it('reports required absent cells and server validation errors without inventing drift', () => {
    const problems = computeMatrixProblems({
      keys,
      environmentIds: environments,
      values,
      validationErrors: [
        {
          keyId: 'key_optional',
          environmentId: 'env_dev',
          message: 'Server refused the staged value.',
        },
      ],
    });

    expect(problems).toEqual([
      {
        keyId: 'key_required',
        keyName: 'REQUIRED_KEY',
        groupId: 'group_app',
        environmentId: 'env_prod',
        kind: 'required-absent',
        message: 'REQUIRED_KEY is required in env_prod but is absent.',
      },
      {
        keyId: 'key_optional',
        keyName: 'OPTIONAL_KEY',
        groupId: 'group_ops',
        environmentId: 'env_dev',
        kind: 'validation',
        message: 'Server refused the staged value.',
      },
    ]);
  });

  it('counts problem cells per group and filters keys while retaining declaration order', () => {
    const problems = computeMatrixProblems({
      keys,
      environmentIds: environments,
      values,
      validationErrors: [],
    });

    expect(groupProblemCounts(problems)).toEqual(new Map([['group_app', 1]]));
    expect(keysForMatrixFilter(keys, problems, 'problems').map((key) => key.name)).toEqual([
      'REQUIRED_KEY',
    ]);
    expect(keysForMatrixFilter(keys, problems, 'all')).toEqual(keys);
  });
});

describe('toggleVisibleEnvironment', () => {
  it('never hides the final visible environment', () => {
    expect(toggleVisibleEnvironment(['env_dev'], 'env_dev', environments)).toEqual(['env_dev']);
  });

  it('can hide and restore an environment in project order', () => {
    expect(toggleVisibleEnvironment([...environments], 'env_prod', environments)).toEqual([
      'env_dev',
    ]);
    expect(toggleVisibleEnvironment(['env_dev'], 'env_prod', environments)).toEqual([
      'env_dev',
      'env_prod',
    ]);
  });
});

describe('publish and copy guards', () => {
  it('blocks only unsafe environments while clean environments remain selectable', () => {
    const problems = computeMatrixProblems({
      keys,
      environmentIds: environments,
      values,
      validationErrors: [],
    });

    expect(blockedPublishEnvironmentIds(problems, ['env_dev'])).toEqual(new Set());
    expect(blockedPublishEnvironmentIds(problems, ['env_dev', 'env_prod'])).toEqual(
      new Set(['env_prod']),
    );
  });

  it('requires an explicit confirmation only when a protected destination is selected', () => {
    expect(copyRequiresProtectedConfirmation(['env_dev'], ['env_prod'])).toBe(false);
    expect(copyRequiresProtectedConfirmation(['env_dev', 'env_prod'], ['env_prod'])).toBe(true);
  });
});

describe('row editor state', () => {
  it('reopens config from its exact staged preview and keeps secrets write-only', () => {
    expect(draftValueForMatrixCell('config', 'published', 'set', 'staged')).toBe('staged');
    expect(draftValueForMatrixCell('config', 'published', undefined, undefined)).toBe('published');
    expect(draftValueForMatrixCell('secret', 'never expose', 'set', 'also hidden')).toBe('');
  });

  it('allows a pending set over an absent cell to return to absent', () => {
    expect(canClearMatrixCell(false, 'set')).toBe(true);
    expect(canClearMatrixCell(false, undefined)).toBe(false);
    expect(canClearMatrixCell(true, undefined)).toBe(true);
  });

  it('validates common declared types while typing', () => {
    expect(validateMatrixDraft({ type: 'boolean' }, 'truthy')).toMatch(/true or false/);
    expect(validateMatrixDraft({ type: 'integer', min: 2n }, '1')).toMatch(/at least 2/);
    expect(validateMatrixDraft({ type: 'enum', members: ['debug', 'info'] }, 'warn')).toMatch(
      /debug, info/,
    );
    expect(validateMatrixDraft({ type: 'json' }, '{')).toMatch(/valid JSON/);
    expect(validateMatrixDraft({ type: 'url', schemes: ['https'] }, 'http://example.test')).toMatch(
      /https/,
    );
    expect(validateMatrixDraft({ type: 'string', min_length: 2 }, 'ok')).toBeNull();
  });
});
