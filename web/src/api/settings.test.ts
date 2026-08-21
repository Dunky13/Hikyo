import { describe, expect, it } from 'vitest';

import { ApiError } from './client.ts';
import {
  createEnvironmentRefusalText,
  createProjectRefusalText,
  DAY_SECONDS,
  environmentSettingsReadState,
  formatRetentionAge,
  orgTopologyReadiness,
  projectRetentionInherited,
  retentionBoundsPayload,
  retentionDayState,
  retentionSentence,
  settingsFailureText,
  settingsOperationFailure,
  validatePositiveInteger,
} from './settings.ts';

const ORG_CAP = {
  mode: 'keep-if-either' as const,
  max_age_seconds: 90 * DAY_SECONDS,
  last_revisions: 10,
};

describe('environment settings reads', () => {
  it('keeps pending distinct from an unreadable uniform 404', () => {
    expect(
      environmentSettingsReadState({
        isPending: true,
        isError: false,
        data: undefined,
        error: null,
      }),
    ).toEqual({ status: 'pending' });
    expect(
      environmentSettingsReadState({
        isPending: false,
        isError: true,
        data: undefined,
        error: new ApiError(404, 'not found'),
      }),
    ).toEqual({ status: 'unreadable' });
  });

  it('keeps forbidden and unexpected failures distinct from unreadable', () => {
    expect(
      environmentSettingsReadState({
        isPending: false,
        isError: true,
        data: undefined,
        error: new ApiError(403, 'forbidden'),
      }),
    ).toEqual({ status: 'forbidden' });
    const failure = new ApiError(500, 'fault');
    expect(
      environmentSettingsReadState({
        isPending: false,
        isError: true,
        data: undefined,
        error: failure,
      }),
    ).toEqual({ status: 'error', error: failure });
  });

  it('keeps the complete parsed policy in the ready state', () => {
    expect(
      environmentSettingsReadState({
        isPending: false,
        isError: false,
        data: { protected: false, reauth_window_seconds: 300 },
        error: null,
      }),
    ).toEqual({ status: 'ready', protected: false, reauth_window_seconds: 300 });
  });
});

describe('organisation topology readiness', () => {
  it('waits for every settings read before exposing an action-ready topology', () => {
    expect(
      orgTopologyReadiness(
        'org_1',
        { isPending: false, isError: false },
        [{ isPending: false, isError: false }],
        [{ status: 'pending' }],
      ),
    ).toEqual({ isPending: true, isError: false, ready: false });
  });

  it('treats only unreadable 404 settings as a settled non-error state', () => {
    expect(
      orgTopologyReadiness(
        'org_1',
        { isPending: false, isError: false },
        [{ isPending: false, isError: false }],
        [{ status: 'unreadable' }],
      ),
    ).toEqual({ isPending: false, isError: false, ready: true });
    expect(
      orgTopologyReadiness(
        'org_1',
        { isPending: false, isError: false },
        [{ isPending: false, isError: false }],
        [{ status: 'forbidden' }],
      ),
    ).toEqual({ isPending: false, isError: true, ready: false });
  });
});

describe('retention values', () => {
  it('formats day-aligned values as days and preserves exact smaller units', () => {
    expect(formatRetentionAge(3 * DAY_SECONDS)).toBe('3 days');
    expect(formatRetentionAge(60)).toBe('1 minute');
    expect(formatRetentionAge(90)).toBe('90 seconds');
  });

  it('keeps day-aligned, exact, and absent ages as distinct editor states', () => {
    expect(retentionDayState(3 * DAY_SECONDS)).toEqual({ kind: 'days', days: '3' });
    expect(retentionDayState(60)).toEqual({ kind: 'exact', seconds: 60 });
    expect(retentionDayState(null)).toEqual({ kind: 'absent' });
  });

  it('assembles both retention bounds once with exact day conversion', () => {
    expect(retentionBoundsPayload('30', '5')).toEqual({
      ok: true,
      maxAgeSeconds: 30 * DAY_SECONDS,
      lastRevisions: 5,
    });
    expect(retentionBoundsPayload('', '5')).toEqual({
      ok: false,
      message: 'Maximum age in days must be a whole number of at least 1.',
    });
    expect(retentionBoundsPayload('30', '0')).toEqual({
      ok: false,
      message: 'Revision count must be a whole number of at least 1.',
    });
  });

  it('validates positive integer input without coercing invalid values', () => {
    expect(validatePositiveInteger('12', 'Revision count')).toEqual({ ok: true, value: 12 });
    for (const value of ['', '0', '-1', '1.5', 'not-a-number', 'Infinity']) {
      expect(validatePositiveInteger(value, 'Revision count')).toEqual({
        ok: false,
        message: 'Revision count must be a whole number of at least 1.',
      });
    }
  });

  it('refuses an unknown project retention selector value', () => {
    expect(projectRetentionInherited('inherit')).toBe(true);
    expect(projectRetentionInherited('override')).toBe(false);
    expect(() => projectRetentionInherited('surprise')).toThrow(
      'unknown project retention mode surprise',
    );
  });
});

describe('the retention sentence', () => {
  it('states the OR, because keep-if-either keeps a payload that satisfies either bound', () => {
    expect(retentionSentence(ORG_CAP)).toBe(
      'Keep a payload while it is younger than 90 days OR among the last 10 revisions of its environment.',
    );
  });

  it('does not round a persisted sub-day policy', () => {
    expect(
      retentionSentence({
        mode: 'keep-if-either',
        max_age_seconds: 60,
        last_revisions: 2,
      }),
    ).toContain('1 minute');
  });

  it('states unlimited as the explicit policy it is', () => {
    expect(
      retentionSentence({ mode: 'unlimited', max_age_seconds: null, last_revisions: null }),
    ).toContain('never collected');
  });

  it('calls a bounded policy with no bounds a server fault rather than inventing one', () => {
    expect(
      retentionSentence({ mode: 'keep-if-either', max_age_seconds: null, last_revisions: null }),
    ).toContain('server fault');
  });
});

describe('settings refusals', () => {
  it('carries the operation through the shared feedback callback', () => {
    expect(
      settingsFailureText(
        settingsOperationFailure('delete-project', new ApiError(409, 'conflict')),
      ),
    ).toContain('still holds environments or folders');
  });

  it('maps create, rename, and delete lifecycle statuses to their own operation', () => {
    expect(settingsFailureText(new ApiError(409, 'x'), 'create-org')).toContain(
      'organisation name is already in use',
    );
    expect(settingsFailureText(new ApiError(400, 'x'), 'rename-project')).toContain(
      'project name',
    );
    expect(settingsFailureText(new ApiError(404, 'x'), 'rename-org')).toContain(
      'organisation is unavailable or does not exist',
    );
    expect(settingsFailureText(new ApiError(409, 'x'), 'delete-project')).toContain(
      'still holds environments or folders',
    );
    expect(settingsFailureText(new ApiError(409, 'x'), 'delete-org')).toContain(
      'still holds projects or grants',
    );
  });

  it('maps retention statuses and preserves the server-safe cap detail', () => {
    const detail =
      'project retention exceeds the org retention cap keep-if-either(max_age=2160h0m0s,last_revisions=10)';
    expect(settingsFailureText(new ApiError(400, 'x', detail), 'set-project-retention')).toBe(
      detail,
    );
    expect(settingsFailureText(new ApiError(400, 'x'), 'set-org-retention')).toContain(
      'retention policy',
    );
    expect(settingsFailureText(new ApiError(404, 'x'), 'set-project-retention')).toContain(
      'project retention policy is unavailable or does not exist',
    );
  });

  it('maps environment-policy and token-rotation declared failures honestly', () => {
    expect(settingsFailureText(new ApiError(400, 'x'), 'set-environment-settings')).toContain(
      'environment policy is invalid',
    );
    expect(settingsFailureText(new ApiError(404, 'x'), 'rotate-token-key')).toContain(
      'change-token key rotation is unavailable',
    );
  });

  it('maps definitions governance failures as project policy', () => {
    expect(settingsFailureText(new ApiError(400, 'x'), 'set-definitions-settings')).toBe(
      'The definitions source is invalid.',
    );
    expect(settingsFailureText(new ApiError(403, 'x'), 'set-definitions-settings')).toContain(
      'change this project definitions source',
    );
    expect(settingsFailureText(new ApiError(404, 'x'), 'set-definitions-settings')).toBe(
      'This project definitions policy is unavailable or does not exist.',
    );
  });

  it('maps instance administration reads and credential-policy writes by operation', () => {
    expect(settingsFailureText(new ApiError(404, 'x'), 'get-retention-health')).toBe(
      'Retention health is unavailable.',
    );
    expect(settingsFailureText(new ApiError(404, 'x'), 'get-credential-policy')).toBe(
      'The machine-credential policy is unavailable.',
    );
    expect(settingsFailureText(new ApiError(400, 'x'), 'set-credential-policy')).toBe(
      'The machine-credential policy is invalid.',
    );
  });

  it('treats only 401 as a credential refusal', () => {
    expect(settingsFailureText(new ApiError(401, 'x'), 'rename-org')).toContain(
      'session ended',
    );
    expect(settingsFailureText(new ApiError(403, 'x'), 'rename-org')).not.toMatch(
      /sign in|credential/i,
    );
  });

  it('does not claim an unknown server failure left state unchanged', () => {
    expect(settingsFailureText(new ApiError(500, 'x'), 'set-org-retention')).toBe(
      'The server failed; whether the change applied is unknown — reload to check.',
    );
    expect(settingsFailureText(new Error('network'), 'set-org-retention')).toBe(
      'The server failed; whether the change applied is unknown — reload to check.',
    );
  });
});

describe('authoring refusals', () => {
  it('names manage-projects for a uniform 403/404 project refusal', () => {
    const forbidden = createProjectRefusalText(new ApiError(403, 'x'));
    expect(forbidden).toContain('manage-projects');
    expect(forbidden).toContain('organisation scope');
    expect(createProjectRefusalText(new ApiError(404, 'x'))).toBe(forbidden);
  });

  it('names definitions-edit for a uniform 403/404 environment refusal', () => {
    const forbidden = createEnvironmentRefusalText(new ApiError(403, 'x'));
    expect(forbidden).toContain('definitions-edit');
    expect(createEnvironmentRefusalText(new ApiError(404, 'x'))).toBe(forbidden);
  });

  it('quotes a caller-safe conflict detail and falls back when there is none', () => {
    expect(createProjectRefusalText(new ApiError(409, 'x', 'name taken'))).toBe('name taken');
    expect(createEnvironmentRefusalText(new ApiError(409, 'x'))).toContain('already in use');
  });

  it('does not claim an unknown failure created anything', () => {
    expect(createProjectRefusalText(new ApiError(500, 'x'))).toContain(
      'whether the project was created is unknown',
    );
    expect(createEnvironmentRefusalText(new Error('network'))).toContain(
      'whether the environment was created is unknown',
    );
  });
});
