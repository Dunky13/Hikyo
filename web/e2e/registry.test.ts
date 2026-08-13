import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { SURFACES } from '../src/app/navigation.ts';
import {
  closureViolations,
  FLOWS,
  liveClosureViolations,
  surfacesForFlow,
  unexecutedClaims,
  type ClosureCandidate,
} from './registry.ts';

const always = () => true;

describe('the closed flow registry', () => {
  it('is closed for this build', () => {
    // The gate itself. If this fails, a locked surface shipped without a
    // Playwright flow — which is the thing the S3 criterion exists to stop.
    expect(liveClosureViolations()).toEqual([]);
  });

  // A check that cannot fail is not a check. These four prove it can.
  it('fails when a locked surface has no flow', () => {
    const problems = closureViolations({
      surfaceIds: [...SURFACES.map((s) => s.id), 'environment-matrix'],
      flows: FLOWS,
      specExists: always,
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('surface "environment-matrix" has no flow');
  });

  it('fails when a flow names a surface that no longer exists', () => {
    const stale: ClosureCandidate = {
      id: 'stale',
      spec: 'flows/login.spec.ts',
      surfaces: ['reveal'],
    };
    const problems = closureViolations({
      surfaceIds: SURFACES.map((s) => s.id),
      flows: [...FLOWS, stale],
      specExists: always,
    });
    expect(problems).toContain('flow "stale" covers unknown surface "reveal"');
  });

  it('fails when a registered spec file is missing', () => {
    const problems = closureViolations({
      surfaceIds: SURFACES.map((s) => s.id),
      flows: FLOWS,
      specExists: (spec) => spec !== 'flows/shell.spec.ts',
    });
    expect(problems).toContain('flow "shell" names a spec that does not exist: flows/shell.spec.ts');
  });

  // The last escape hatch in the router: the routes are generated from
  // SURFACES, but nothing stops someone typing a path back in — as a literal
  // OR as an expression that came from somewhere else. The rule this enforces
  // is narrow on purpose: every `path=` is either the catch-all or reads
  // `.path` off a Surface record, so a route can only exist for a surface the
  // table names.
  it('leaves no route that did not come from the surface table', () => {
    const app = readFileSync(fileURLToPath(new URL('../src/app/App.tsx', import.meta.url)), 'utf8');
    // Strip comments first: the file explains this rule, and the explanation
    // must not read as a violation of it.
    const code = app.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
    const expressions = [...code.matchAll(/path=(\{[^}]*\}|"[^"]*"|'[^']*'|`[^`]*`)/g)].map(
      (m) => m[1] ?? '',
    );
    expect(expressions.length, 'no routes found — did App.tsx move?').toBeGreaterThan(0);
    const offenders = expressions.filter((e) => e !== '"*"' && !e.includes('.path'));
    expect(offenders).toEqual([]);
  });

  it('fails when a flow covers nothing', () => {
    const empty: ClosureCandidate = { id: 'empty', spec: 'flows/login.spec.ts', surfaces: [] };
    const problems = closureViolations({
      surfaceIds: SURFACES.map((s) => s.id),
      flows: [...FLOWS, empty],
      specExists: always,
    });
    expect(problems).toContain('flow "empty" covers no surface — it is not a flow, it is a file');
  });
});

describe('surfacesForFlow', () => {
  it('resolves a flow\'s claims to the router\'s own records', () => {
    expect(surfacesForFlow('shell').map((s) => s.id)).toEqual(['overview', 'projects', 'settings']);
    expect(surfacesForFlow('login').map((s) => s.path)).toEqual(['/login']);
  });

  it('throws on an unknown flow rather than returning an empty loop', () => {
    // A typo that yielded [] would make a flow silently assert nothing.
    expect(() => surfacesForFlow('shel')).toThrow(/unknown flow/);
  });
});

describe('the execution half of closure', () => {
  const log = (...lines: string[]) => lines.map((l) => `${l}\n`).join('');

  it('is satisfied when every claim ran', () => {
    expect(
      unexecutedClaims(
        log(
          'login\tlogin\tdark',
          'shell\toverview\tdark',
          'shell\tprojects\tlight',
          'shell\tsettings\tdark',
          'reveal\tvalues\tdark',
        ),
      ),
    ).toEqual([]);
  });

  it('fails a surface that was claimed but never asserted', () => {
    const problems = unexecutedClaims(
      log('login\tlogin\tdark', 'shell\toverview\tdark', 'reveal\tvalues\tdark'),
    );
    expect(problems).toHaveLength(2);
    expect(problems.join(' ')).toContain('claims surface "projects" but the pinned assertion set never ran');
    expect(problems.join(' ')).toContain('claims surface "settings" but the pinned assertion set never ran');
  });

  it('fails everything when nothing ran at all', () => {
    expect(unexecutedClaims('')).toHaveLength(5);
  });

  it('does not accept another flow\'s execution as this one\'s', () => {
    // `shell/overview` is not `login/login`, however similar the surface ids.
    const problems = unexecutedClaims(log('shell\tlogin\tdark'), [
      { id: 'login', spec: 'flows/login.spec.ts', surfaces: ['login'] },
    ]);
    expect(problems).toHaveLength(1);
  });
});
