import { describe, expect, it } from 'vitest';

import {
  dismissDecision,
  expiryLabel,
  grantWideningReach,
  lastUsedLabel,
  parseClaimNumber,
  postStateReach,
  pullRequestRefusal,
  scopeOf,
  setupJourney,
  type Grant,
  type MachineCredential,
} from './identities.ts';

/**
 * The machine-access surface's derivations (#67).
 *
 * These are the pieces where a wrong answer is a SECURITY statement rather than
 * a layout bug: which environments a service account reaches, whether the mint
 * needs a disclosure ceremony, and whether a pull-request identity is being
 * bound. Each is a pure function precisely so it can be pinned here rather than
 * inferred from a screenshot.
 */

const ENVS = [
  { id: 'env_dev', name: 'development' },
  { id: 'env_prod', name: 'production' },
];

const grant = (
  principal: string,
  capability: string,
  scope: { project_id?: string; environment_id?: string },
): Grant => ({
  id: 'gr_00000000-0000-0000-0000-000000000000',
  principal_id: principal,
  capability,
  scope: { org_id: 'org_x', project_id: 'prj_x', ...scope },
  origins: [],
  created_at: '2026-08-13T00:00:00Z',
});

describe('scopeOf', () => {
  it('reads one environment-scoped grant as reach on that environment only', () => {
    const scope = scopeOf([grant('mp_a', 'read', { environment_id: 'env_dev' })], 'mp_a', ENVS);
    expect(scope).toEqual([
      { id: 'env_dev', name: 'development', read: true, reveal: false },
      { id: 'env_prod', name: 'production', read: false, reveal: false },
    ]);
  });

  it('lets a project-scoped grant reach every environment beneath it', () => {
    // The ordinary downward inheritance. A listing confined to one project has
    // no wider row, so an absent environment_id can only mean project scope.
    const scope = scopeOf([grant('mp_a', 'read', {})], 'mp_a', ENVS);
    expect(scope.every((s) => s.read)).toBe(true);
  });

  it('never reads another principal\'s grant as this one\'s', () => {
    const scope = scopeOf([grant('mp_other', 'read', { environment_id: 'env_dev' })], 'mp_a', ENVS);
    expect(scope.some((s) => s.read)).toBe(false);
  });
});

describe('postStateReach', () => {
  it('is empty without reveal, however read is granted', () => {
    // The state every workload principal is in today: the permission model's
    // machine allowlist admits `read` and nothing else, so nothing this
    // account holds reaches plaintext and the mint's disclosure conjunct is
    // vacuous.
    const scope = scopeOf([grant('mp_a', 'read', { environment_id: 'env_dev' })], 'mp_a', ENVS);
    expect(postStateReach(scope)).toEqual([]);
  });

  it('is empty with reveal but no read: no delivery means no plaintext', () => {
    const scope = scopeOf([grant('mp_a', 'reveal', { environment_id: 'env_dev' })], 'mp_a', ENVS);
    expect(postStateReach(scope)).toEqual([]);
  });

  it('names the environment when both are held', () => {
    const scope = scopeOf(
      [
        grant('mp_a', 'read', { environment_id: 'env_dev' }),
        grant('mp_a', 'reveal', { environment_id: 'env_dev' }),
      ],
      'mp_a',
      ENVS,
    );
    expect(postStateReach(scope).map((s) => s.name)).toEqual(['development']);
  });
});

describe('grantWideningReach', () => {
  // The mint's conjunct for a GRANT is the DELTA, not the whole post-state:
  // `checkMachineWidening` computes exactly that server-side, so a client
  // asking for a ceremony over everything the account already reaches would
  // prompt for authority the server never consumes.
  it('is empty for a read grant on an account that cannot decrypt', () => {
    // The state of every workload principal today.
    expect(grantWideningReach(scopeOf([], 'mp_a', ENVS), 'env_dev', 'read')).toEqual([]);
  });

  it('names the environment when the read grant completes an existing reveal', () => {
    // `reveal` without `read` reaches nothing; adding `read` is what turns it
    // into a working path to plaintext, and that IS a widening.
    const scope = scopeOf([grant('mp_a', 'reveal', { environment_id: 'env_dev' })], 'mp_a', ENVS);
    expect(grantWideningReach(scope, 'env_dev', 'read').map((s) => s.name)).toEqual(['development']);
  });

  it('is empty when the environment was already reachable', () => {
    const scope = scopeOf(
      [
        grant('mp_a', 'read', { environment_id: 'env_dev' }),
        grant('mp_a', 'reveal', { environment_id: 'env_dev' }),
      ],
      'mp_a',
      ENVS,
    );
    expect(grantWideningReach(scope, 'env_dev', 'read')).toEqual([]);
  });

  it('never widens an environment the grant does not name', () => {
    const scope = scopeOf([grant('mp_a', 'reveal', {})], 'mp_a', ENVS);
    expect(grantWideningReach(scope, 'env_dev', 'read').map((s) => s.id)).toEqual(['env_dev']);
  });
});

describe('parseClaimNumber', () => {
  // An immutable repository id is what stops a renamed-and-reused path
  // inheriting a production binding. Every case below is a way `Number()`
  // silently binds the wrong repository.
  it('takes a plain integer', () => {
    expect(parseClaimNumber('4242')).toBe(4242);
    expect(parseClaimNumber(' 4242 ')).toBe(4242);
    expect(parseClaimNumber('-7')).toBe(-7);
  });

  it('refuses an empty field rather than binding repository 0', () => {
    expect(parseClaimNumber('')).toBeNull();
    expect(parseClaimNumber('   ')).toBeNull();
  });

  it('refuses anything that is not digits', () => {
    expect(parseClaimNumber('1e3')).toBeNull();
    expect(parseClaimNumber('4242.7')).toBeNull();
    expect(parseClaimNumber('0x10')).toBeNull();
    expect(parseClaimNumber('42abc')).toBeNull();
  });

  it('refuses a value past the range JSON carries exactly', () => {
    // 2^53 + 1 rounds to 2^53 — a DIFFERENT, existing repository id.
    expect(parseClaimNumber('9007199254740993')).toBeNull();
    expect(parseClaimNumber('9007199254740991')).toBe(9_007_199_254_740_991);
  });
});

describe('dismissDecision', () => {
  it('ignores a dismissal while the mint is in flight', () => {
    // Escape reaches a native <dialog> even when Cancel is disabled. Unmounting
    // here would lose a value the server may already have committed.
    expect(dismissDecision({ busy: true, hasValue: false, stored: false })).toBe('ignore');
    expect(dismissDecision({ busy: true, hasValue: true, stored: true })).toBe('ignore');
  });

  it('holds the dialog open until the value is confirmed stored', () => {
    expect(dismissDecision({ busy: false, hasValue: true, stored: false })).toBe('hold-back');
  });

  it('closes once there is nothing to lose', () => {
    expect(dismissDecision({ busy: false, hasValue: false, stored: false })).toBe('close');
    expect(dismissDecision({ busy: false, hasValue: true, stored: true })).toBe('close');
  });
});

describe('setupJourney', () => {
  it('has no journey for an automation principal', () => {
    expect(setupJourney('automation', [])).toBeNull();
  });

  it('waits on the read grant before anything else', () => {
    const steps = setupJourney('workload', scopeOf([], 'mp_a', ENVS)) ?? [];
    expect(steps.map((s) => s.state)).toEqual(['done', 'next', 'next', 'unavailable', 'unavailable']);
  });

  it('marks delivery done once read is granted, and never invents a refusal', () => {
    const scope = scopeOf([grant('mp_a', 'read', { environment_id: 'env_dev' })], 'mp_a', ENVS);
    const steps = setupJourney('workload', scope) ?? [];
    expect(steps[1]?.title).toBe('read granted — development');
    expect(steps[2]?.state).toBe('done');
    // The two steps this build cannot perform say so rather than offering a
    // control the server refuses every time.
    expect(steps[3]?.state).toBe('unavailable');
    expect(steps[4]?.state).toBe('unavailable');
  });
});

const credential = (over: Partial<MachineCredential>): MachineCredential => ({
  id: 'mcr_00000000-0000-0000-0000-000000000000',
  kind: 'hikyo-token',
  lifetime: 'finite',
  created_at: '2026-08-01T00:00:00Z',
  created_by: 'pr_00000000-0000-0000-0000-000000000000',
  expiring_soon: false,
  ...over,
});

describe('expiryLabel', () => {
  const now = new Date('2026-08-13T00:00:00Z');

  it('counts the days left', () => {
    expect(expiryLabel(credential({ expires_at: '2026-08-27T00:00:00Z' }), now)).toBe(
      'expires in 14 days',
    );
  });

  it('says expired rather than a negative count', () => {
    expect(expiryLabel(credential({ expires_at: '2026-08-01T00:00:00Z' }), now)).toBe('expired');
  });

  it('says revoked first, whatever the expiry says', () => {
    const dead = credential({ expires_at: '2026-12-01T00:00:00Z', revoked_at: '2026-08-02T00:00:00Z' });
    expect(expiryLabel(dead, now)).toBe('revoked');
  });

  it('states an indefinite lifetime as a fact, not as a large number', () => {
    expect(expiryLabel(credential({ lifetime: 'indefinite' }), now)).toBe('no expiry');
  });
});

describe('lastUsedLabel', () => {
  it('keeps never-used and used-at-the-epoch different facts', () => {
    expect(lastUsedLabel(credential({}))).toBe('never used');
    expect(lastUsedLabel(credential({ last_used_at: '1970-01-01T00:00:00Z' }))).toBe(
      'last used 1970-01-01',
    );
  });
});

describe('pullRequestRefusal', () => {
  it('refuses both pull-request events by name', () => {
    expect(pullRequestRefusal('pull_request')).toContain('pull_request');
    expect(pullRequestRefusal('pull_request_target')).toContain('pull_request_target');
  });

  it('passes the ordinary events', () => {
    expect(pullRequestRefusal('push')).toBeNull();
    expect(pullRequestRefusal('workflow_dispatch')).toBeNull();
  });

  it('is not fooled by an event that merely contains the word', () => {
    // The rule is about the pinned event being one of exactly two values, not
    // about the string looking pull-request-ish.
    expect(pullRequestRefusal('pull_request_review')).toBeNull();
  });
});
