import { describe, expect, it } from 'vitest';

import {
  idleMintLifecycle,
  mintLifecycleAtBoundary,
  transitionMintLifecycle,
  type MintLifecycle,
  type MintBoundary,
  type MintRequest,
} from './mintLifecycle.ts';

const SENTINEL = 'hik_1_wl_SENTINEL_PLAINTEXT';
const CLEAR_REASONS: ReadonlyArray<'close' | 'navigation' | 'session-transition'> = [
  'close',
  'navigation',
  'session-transition',
];
const OTHER_BOUNDARIES: ReadonlyArray<{ readonly label: string; readonly value: MintBoundary }> = [
  {
    label: 'session',
    value: { sessionId: 'ses_second', org: 'org_acme', project: 'prj_payments' },
  },
  {
    label: 'organisation route',
    value: { sessionId: 'ses_first', org: 'org_other', project: 'prj_payments' },
  },
  {
    label: 'project route',
    value: { sessionId: 'ses_first', org: 'org_acme', project: 'prj_other' },
  },
];

const request = (id: number, accountId = 'mch_first'): MintRequest => ({
  id,
  sessionId: 'ses_first',
  org: 'org_acme',
  project: 'prj_payments',
  accountId,
  accountName: accountId === 'mch_first' ? 'first worker' : 'second worker',
  rotating: false,
  reach: [{ id: 'env_prod', name: 'production' }],
});

function submitting(input: MintRequest): MintLifecycle {
  const reviewing = transitionMintLifecycle(idleMintLifecycle, { type: 'review', request: input });
  return transitionMintLifecycle(reviewing, { type: 'submit' });
}

function disclosed(input: MintRequest): MintLifecycle {
  return transitionMintLifecycle(submitting(input), {
    type: 'succeeded',
    requestId: input.id,
    result: { value: SENTINEL, clamped: false },
  });
}

describe('MintLifecycle', () => {
  it('makes plaintext reachable only from disclosed', () => {
    const reviewed = transitionMintLifecycle(idleMintLifecycle, {
      type: 'review',
      request: request(1),
    });
    const pending = transitionMintLifecycle(reviewed, { type: 'submit' });
    const shown = transitionMintLifecycle(pending, {
      type: 'succeeded',
      requestId: 1,
      result: { value: SENTINEL, clamped: true },
    });

    expect([idleMintLifecycle.kind, reviewed.kind, pending.kind, shown.kind]).toEqual([
      'idle',
      'reviewing',
      'submitting',
      'disclosed',
    ]);
    expect(JSON.stringify(idleMintLifecycle)).not.toContain(SENTINEL);
    expect(JSON.stringify(reviewed)).not.toContain(SENTINEL);
    expect(JSON.stringify(pending)).not.toContain(SENTINEL);
    expect(JSON.stringify(shown)).toContain(SENTINEL);
  });

  it.each(CLEAR_REASONS)(
    '%s clears disclosed plaintext without retaining transition history',
    (reason) => {
      const cleared = transitionMintLifecycle(disclosed(request(1)), { type: 'clear', reason });

      expect(cleared).toEqual({ kind: 'idle' });
      expect(JSON.stringify(cleared)).not.toContain(SENTINEL);
    },
  );

  it('a new mint replaces disclosed state with non-secret review fields', () => {
    const next = transitionMintLifecycle(disclosed(request(1)), {
      type: 'review',
      request: request(2, 'mch_second'),
    });

    expect(next).toEqual({ kind: 'reviewing', request: request(2, 'mch_second') });
    expect(JSON.stringify(next)).not.toContain(SENTINEL);
  });

  it.each(OTHER_BOUNDARIES)(
    'masks disclosed plaintext synchronously when the $label changes',
    ({ value }) => {
      const shown = disclosed(request(1));
      const masked = mintLifecycleAtBoundary(shown, value);

      expect(masked).toEqual({ kind: 'idle' });
      expect(JSON.stringify(masked)).not.toContain(SENTINEL);
    },
  );

  it('ignores double submit and a late response from an obsolete request', () => {
    const first = submitting(request(1));
    const duplicate = transitionMintLifecycle(first, { type: 'submit' });
    expect(duplicate).toBe(first);

    const secondReview = transitionMintLifecycle(first, {
      type: 'review',
      request: request(2, 'mch_second'),
    });
    const second = transitionMintLifecycle(secondReview, { type: 'submit' });
    const stale = transitionMintLifecycle(second, {
      type: 'succeeded',
      requestId: 1,
      result: { value: SENTINEL, clamped: false },
    });

    expect(stale).toBe(second);
    expect(JSON.stringify(stale)).not.toContain(SENTINEL);

    const current = transitionMintLifecycle(stale, {
      type: 'succeeded',
      requestId: 2,
      result: { value: 'hik_1_wl_CURRENT', clamped: false },
    });
    expect(current.kind).toBe('disclosed');
  });

  it('failure and retry preserve only the intended non-secret request', () => {
    const intended = request(1);
    const failed = transitionMintLifecycle(submitting(intended), {
      type: 'failed',
      requestId: intended.id,
      error: 'The credential may have been minted; check the list.',
    });

    expect(failed).toEqual({
      kind: 'failed',
      request: intended,
      error: 'The credential may have been minted; check the list.',
    });
    expect(JSON.stringify(failed)).not.toContain(SENTINEL);

    const retried = transitionMintLifecycle(failed, { type: 'submit' });
    expect(retried).toEqual({ kind: 'submitting', request: intended });
  });

  it('dismissal holds an unstored disclosure, then clears it after confirmation', () => {
    const pending = submitting(request(1));
    expect(transitionMintLifecycle(pending, { type: 'dismiss' })).toBe(pending);

    const shown = disclosed(request(1));
    const held = transitionMintLifecycle(shown, { type: 'dismiss' });
    expect(held.kind).toBe('disclosed');
    if (held.kind !== 'disclosed') {
      throw new Error('dismissal did not retain the disclosure');
    }
    expect(held.heldBack).toBe(true);
    expect(held.result.value).toBe(SENTINEL);

    const stored = transitionMintLifecycle(held, { type: 'confirm-stored', stored: true });
    const closed = transitionMintLifecycle(stored, { type: 'dismiss' });
    expect(closed).toEqual({ kind: 'idle' });
    expect(JSON.stringify(closed)).not.toContain(SENTINEL);
  });
});
