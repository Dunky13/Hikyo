/**
 * Pure state for the environment matrix.
 *
 * Kept free of React and API clients because these decisions are the matrix's
 * domain seam: presence is exactly set/absent, requiredness is evaluated per
 * environment, and the problems view is a projection over those facts. A UI
 * test that clicked enough cells to infer this would be slower and less exact.
 */

export type MatrixPresence =
  | { readonly mode: 'all' }
  | { readonly mode: 'none' }
  | { readonly mode: 'explicit'; readonly environmentIds: readonly string[] };

export type MatrixStateKey = {
  readonly id: string;
  readonly name: string;
  readonly groupId: string;
  readonly requiredIn: MatrixPresence;
};

export type MatrixStateValue = {
  readonly keyId: string;
  readonly environmentId: string;
  readonly set: boolean;
  readonly pendingOperation?: 'set' | 'unset';
};

export type MatrixValidationError = {
  readonly keyId: string;
  readonly environmentId: string;
  readonly message: string;
};

export type MatrixProblem = {
  readonly keyId: string;
  readonly keyName: string;
  readonly groupId: string;
  readonly environmentId: string;
  readonly kind: 'required-absent' | 'validation';
  readonly message: string;
};

export type MatrixFilter = 'all' | 'problems';

export function requiredInEnvironment(rule: MatrixPresence, environmentId: string): boolean {
  if (rule.mode === 'all') {
    return true;
  }
  if (rule.mode === 'none') {
    return false;
  }
  return rule.environmentIds.includes(environmentId);
}

export function computeMatrixProblems(input: {
  readonly keys: readonly MatrixStateKey[];
  readonly environmentIds: readonly string[];
  readonly values: readonly MatrixStateValue[];
  readonly validationErrors: readonly MatrixValidationError[];
}): readonly MatrixProblem[] {
  const cells = new Map<string, MatrixStateValue>();
  for (const value of input.values) {
    cells.set(`${value.keyId}/${value.environmentId}`, value);
  }
  const validationByCell = new Map<string, string>();
  for (const error of input.validationErrors) {
    validationByCell.set(`${error.keyId}/${error.environmentId}`, error.message);
  }
  const problems: MatrixProblem[] = [];

  for (const key of input.keys) {
    for (const environmentId of input.environmentIds) {
      const cellID = `${key.id}/${environmentId}`;
      const cell = cells.get(cellID);
      const effectivelySet =
        cell?.pendingOperation === 'set'
          ? true
          : cell?.pendingOperation === 'unset'
            ? false
            : cell?.set === true;
      if (requiredInEnvironment(key.requiredIn, environmentId) && !effectivelySet) {
        problems.push({
          keyId: key.id,
          keyName: key.name,
          groupId: key.groupId,
          environmentId,
          kind: 'required-absent',
          message: `${key.name} is required in ${environmentId} but is absent.`,
        });
      }
      const validation = validationByCell.get(cellID);
      if (validation !== undefined) {
        problems.push({
          keyId: key.id,
          keyName: key.name,
          groupId: key.groupId,
          environmentId,
          kind: 'validation',
          message: validation,
        });
      }
    }
  }
  return problems;
}

export function groupProblemCounts(
  problems: readonly MatrixProblem[],
): ReadonlyMap<string, number> {
  const counts = new Map<string, number>();
  for (const problem of problems) {
    counts.set(problem.groupId, (counts.get(problem.groupId) ?? 0) + 1);
  }
  return counts;
}

export function keysForMatrixFilter<T extends MatrixStateKey>(
  keys: readonly T[],
  problems: readonly MatrixProblem[],
  filter: MatrixFilter,
): readonly T[] {
  if (filter === 'all') {
    return keys;
  }
  const problemKeys = new Set(problems.map((problem) => problem.keyId));
  return keys.filter((key) => problemKeys.has(key.id));
}

/** Unsafe environments are excluded individually; clean selected environments remain publishable. */
export function blockedPublishEnvironmentIds(
  problems: readonly MatrixProblem[],
  environmentIds: readonly string[],
): ReadonlySet<string> {
  const addressed = new Set(environmentIds);
  return new Set(
    problems.flatMap((problem) =>
      addressed.has(problem.environmentId) ? [problem.environmentId] : [],
    ),
  );
}

/** Protected copy is a human decision, never an API boolean the UI silently supplies. */
export function copyRequiresProtectedConfirmation(
  destinationIds: readonly string[],
  protectedEnvironmentIds: readonly string[],
): boolean {
  const protectedIds = new Set(protectedEnvironmentIds);
  return destinationIds.some((id) => protectedIds.has(id));
}

export function toggleVisibleEnvironment(
  visibleEnvironmentIds: readonly string[],
  environmentId: string,
  allEnvironmentIds: readonly string[],
): readonly string[] {
  const visible = new Set(visibleEnvironmentIds);
  if (visible.has(environmentId)) {
    if (visible.size === 1) {
      return visibleEnvironmentIds;
    }
    visible.delete(environmentId);
  } else {
    visible.add(environmentId);
  }
  return allEnvironmentIds.filter((id) => visible.has(id));
}
