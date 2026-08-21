import { QueryClient } from '@tanstack/react-query';
import { describe, expect, it } from 'vitest';

import {
  copyInvalidationKeys,
  invalidateAfterCopy,
  pendingDraftsKey,
  pinsKey,
  revisionDetailKey,
  revisionDetailsKey,
  revisionsKey,
  signalsKey,
  valuesKey,
  windowKey,
  type EnvRef,
  type MatrixRef,
} from './keys.ts';

const ref: MatrixRef = { org: 'org', project: 'project' };
const source: EnvRef = { ...ref, environment: 'source' };
const destinationA: EnvRef = { ...ref, environment: 'dest-a' };
const destinationB: EnvRef = { ...ref, environment: 'dest-b' };
const other: EnvRef = { org: 'org', project: 'other', environment: 'dest-a' };

const destinationKeys = (env: EnvRef) => [
  valuesKey(env),
  windowKey(env),
  revisionsKey(env),
  pinsKey(env),
  revisionDetailsKey(env),
  signalsKey(env, env.environment),
  pendingDraftsKey(env, env.environment),
];

describe('copy invalidation', () => {
  it('names every destination cache without naming the source', () => {
    expect(copyInvalidationKeys(ref, ['dest-a', 'dest-b'])).toEqual([
      ...destinationKeys(destinationA),
      ...destinationKeys(destinationB),
    ]);
    expect(copyInvalidationKeys(ref, ['dest-a', 'dest-b'])).not.toContainEqual(valuesKey(source));
  });

  it('invalidates both destinations without touching another project or the source', async () => {
    const queries = new QueryClient();
    const affectedKeys = [
      ...destinationKeys(destinationA),
      ...destinationKeys(destinationB),
    ];
    const untouchedKeys = [
      valuesKey(source),
      ...destinationKeys(other),
    ];

    for (const queryKey of [...affectedKeys, ...untouchedKeys]) {
      const primedKey = queryKey[0] === 'revision-detail'
        ? revisionDetailKey(
            { org: queryKey[1], project: queryKey[2], environment: queryKey[3] },
            '7',
          )
        : queryKey;
      queries.setQueryData(primedKey, { primed: true });
    }

    await invalidateAfterCopy(queries, ref, ['dest-a', 'dest-b']);

    for (const queryKey of affectedKeys) {
      const primedKey = queryKey[0] === 'revision-detail'
        ? revisionDetailKey(
            { org: queryKey[1], project: queryKey[2], environment: queryKey[3] },
            '7',
          )
        : queryKey;
      expect(queries.getQueryState(primedKey)?.isInvalidated, JSON.stringify(primedKey)).toBe(true);
    }
    for (const queryKey of untouchedKeys) {
      const primedKey = queryKey[0] === 'revision-detail'
        ? revisionDetailKey(
            { org: queryKey[1], project: queryKey[2], environment: queryKey[3] },
            '7',
          )
        : queryKey;
      expect(queries.getQueryState(primedKey)?.isInvalidated, JSON.stringify(primedKey)).toBe(false);
    }
  });
});
