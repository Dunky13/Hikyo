import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SURFACES, type Surface, type SurfaceId } from '../src/app/navigation.ts';

/**
 * The closed flow registry (mvp-boundary S3).
 *
 * The 1.0 gate requires that every locked surface has a Playwright flow. That
 * only means something if it is CHECKED, and only stays true if the check
 * cannot be satisfied by editing the check — so the surface list is the
 * router's own (`src/app/navigation.ts`), which a new route has to touch, and
 * the closure test below fails when the two disagree in either direction:
 *
 *   - a surface with no flow  — the gate's actual requirement;
 *   - a flow naming a surface that does not exist — a rename that left a
 *     registry entry pointing at nothing, which would silently reduce
 *     coverage while looking complete;
 *   - a registry entry whose spec file is missing — same, one level down;
 *   - a claimed surface the pinned assertion set never actually RAN on. A
 *     declaration-only check is satisfied by adding three lines and asserting
 *     nothing, so the flows record what they execute and the run log below is
 *     compared against the claims at teardown.
 *
 * Adding a locked surface from here on therefore fails CI until its flow
 * lands. That is the point of the ticket.
 */

export type Flow = {
  readonly id: string;
  /** Path to the spec, relative to this directory. */
  readonly spec: string;
  readonly surfaces: readonly SurfaceId[];
};

export const FLOWS: readonly Flow[] = [
  { id: 'login', spec: 'flows/login.spec.ts', surfaces: ['login'] },
  { id: 'shell', spec: 'flows/shell.spec.ts', surfaces: ['overview', 'projects', 'settings'] },
  { id: 'reveal', spec: 'flows/reveal.spec.ts', surfaces: ['values'] },
  {
    id: 'machine-access',
    spec: 'flows/machine-access.spec.ts',
    surfaces: ['machine-access'],
  },
];

/**
 * ClosureCandidate is a flow as the CHECK sees it: surface ids are plain
 * strings here, not `SurfaceId`. That is deliberate — the check's whole job is
 * to catch a registry that names a surface the router does not have, and a
 * type that made that unrepresentable would only move the failure to a cast in
 * the test that proves the check works.
 */
export type ClosureCandidate = {
  readonly id: string;
  readonly spec: string;
  readonly surfaces: readonly string[];
};

export type ClosureInput = {
  readonly surfaceIds: readonly string[];
  readonly flows: readonly ClosureCandidate[];
  /** specExists is injected so the check itself is testable without a filesystem. */
  readonly specExists: (spec: string) => boolean;
};

/**
 * closureViolations returns one human-readable line per breach, empty when the
 * registry is closed.
 */
export function closureViolations(input: ClosureInput): string[] {
  const problems: string[] = [];
  const covered = new Set<string>();

  for (const flow of input.flows) {
    if (!input.specExists(flow.spec)) {
      problems.push(`flow "${flow.id}" names a spec that does not exist: ${flow.spec}`);
    }
    if (flow.surfaces.length === 0) {
      problems.push(`flow "${flow.id}" covers no surface — it is not a flow, it is a file`);
    }
    for (const surface of flow.surfaces) {
      if (!input.surfaceIds.includes(surface)) {
        problems.push(`flow "${flow.id}" covers unknown surface "${surface}"`);
      }
      covered.add(surface);
    }
  }

  for (const id of input.surfaceIds) {
    if (!covered.has(id)) {
      problems.push(
        `surface "${id}" has no flow — a locked surface without a flow is exactly what the ` +
          `S3 gate forbids; add one to e2e/flows and register it in e2e/registry.ts`,
      );
    }
  }

  return problems;
}

/** liveClosureViolations runs the declarative check against this repository. */
export function liveClosureViolations(): string[] {
  return closureViolations({
    surfaceIds: SURFACES.map((s) => s.id),
    flows: FLOWS,
    specExists: (spec) => existsSync(fileURLToPath(new URL(spec, import.meta.url))),
  });
}

/**
 * surfacesForFlow is what a flow claims, resolved to the router's own records.
 *
 * Flows ITERATE this rather than re-listing their surfaces: a second list is a
 * second thing to forget, and "claimed three, asserted one" is exactly the hole
 * a declarative registry leaves open. An unknown flow id throws — a typo must
 * not silently become an empty loop that passes.
 */
export function surfacesForFlow(flowID: string): readonly Surface[] {
  const flow = FLOWS.find((f) => f.id === flowID);
  if (flow === undefined) {
    throw new Error(`unknown flow ${flowID}: add it to FLOWS in e2e/registry.ts`);
  }
  return flow.surfaces.map((id) => {
    const surface = SURFACES.find((s) => s.id === id);
    if (surface === undefined) {
      throw new Error(`flow ${flowID} claims unknown surface ${id}`);
    }
    return surface;
  });
}

// --- the run log ------------------------------------------------------------
//
// The declarative half proves a claim EXISTS. This half proves it was KEPT.
// The pinned-set fixture appends one line per execution and teardown compares
// the set against the claims, so "claimed but never executed" is a hard
// failure rather than a code review question.
//
// A plain append-only file rather than anything cleverer: Playwright workers
// are separate processes, this suite runs with `workers: 1`, and a line per
// surface-and-theme is a few dozen bytes per run.
// ponytail: single-writer append; if the suite ever goes parallel, switch to
// one file per worker and merge at teardown.

export const RUN_LOG = fileURLToPath(new URL('.runs/pinned.log', import.meta.url));

/** recordPinnedRun notes that the pinned set executed on one surface. */
export function recordPinnedRun(entry: { flow: string; surface: string; theme: string }): void {
  mkdirSync(dirname(RUN_LOG), { recursive: true });
  // Append, not read-modify-write: every worker and every test adds to the
  // same log and none of them needs to see the others.
  writeFileSync(RUN_LOG, `${entry.flow}\t${entry.surface}\t${entry.theme}\n`, { flag: 'a' });
}

/** resetRunLog empties the log so a run is never judged on a previous one's. */
export function resetRunLog(): void {
  mkdirSync(dirname(RUN_LOG), { recursive: true });
  writeFileSync(RUN_LOG, '');
}

/**
 * unexecutedClaims returns one line per surface a flow claims and the pinned
 * set never ran on. `log` is the raw file contents, injected so the rule is
 * testable without a browser.
 */
export function unexecutedClaims(log: string, flows: readonly ClosureCandidate[] = FLOWS): string[] {
  const ran = new Set(
    log
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '')
      .map((line) => {
        const [flow = '', surface = ''] = line.split('\t');
        return `${flow}/${surface}`;
      }),
  );
  const missing: string[] = [];
  for (const flow of flows) {
    for (const surface of flow.surfaces) {
      if (!ran.has(`${flow.id}/${surface}`)) {
        missing.push(
          `flow "${flow.id}" claims surface "${surface}" but the pinned assertion set never ran ` +
            `on it — a claim nothing executes is a claim nothing checks`,
        );
      }
    }
  }
  return missing;
}

/** readRunLog returns the log, or empty when nothing ever ran. */
export function readRunLog(): string {
  try {
    return readFileSync(RUN_LOG, 'utf8');
  } catch {
    return '';
  }
}
