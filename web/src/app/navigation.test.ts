import { describe, expect, it } from 'vitest';

import { allowsAnonymousSession, routeRegistryViolations, SURFACES } from './navigation.ts';

describe('the route policy registry', () => {
  it('gives every current route one explicit access and chrome policy', () => {
    expect(SURFACES.map((surface) => `${surface.id}:${surface.mode}:${surface.chrome}`)).toEqual([
      'login:public:none',
      'overview:authenticated:shell',
      'projects:authenticated:shell',
      'remotes:authenticated:shell',
      'members:authenticated:shell',
      'org-settings:authenticated:shell',
      'project-settings:authenticated:shell',
      'instance-admin:authenticated:shell',
      'settings:authenticated:shell',
      'matrix:authenticated:shell',
      'history:authenticated:shell',
      'values:authenticated:shell',
      'machine-access:authenticated:shell',
      'cli-reauth:ceremony:none',
      'workspace-approve:ceremony:none',
      'workspace-callback:public:none',
    ]);
    expect(routeRegistryViolations(SURFACES)).toEqual([]);
  });

  it('makes only public and session-establishing ceremony routes anonymous-reachable', () => {
    expect(SURFACES.filter(allowsAnonymousSession).map((surface) => surface.id)).toEqual([
      'login',
      'cli-reauth',
      'workspace-approve',
      'workspace-callback',
    ]);
    expect(
      allowsAnonymousSession({
        id: 'required-ceremony',
        path: '/required-ceremony',
        label: 'Required ceremony',
        section: null,
        mode: 'ceremony',
        chrome: 'none',
        session: 'required',
      }),
    ).toBe(false);
  });

  it('rejects public routes with shell chrome', () => {
    expect(
      routeRegistryViolations([
        {
          id: 'bad-public',
          path: '/bad-public',
          label: 'Bad public route',
          section: null,
          mode: 'public',
          chrome: 'shell',
        },
      ]),
    ).toContain('route "bad-public" is public but uses shell chrome');
  });

  it('rejects authenticated routes without shell chrome', () => {
    expect(
      routeRegistryViolations([
        {
          id: 'bad-authenticated',
          path: '/bad-authenticated',
          label: 'Bad authenticated route',
          section: null,
          mode: 'authenticated',
          chrome: 'none',
        },
      ]),
    ).toContain('route "bad-authenticated" is authenticated but has no shell chrome');
  });

  it('rejects ceremonies whose session behavior is absent or inconsistent', () => {
    expect(
      routeRegistryViolations([
        {
          id: 'missing-session-policy',
          path: '/missing-session-policy',
          label: 'Missing session policy',
          section: null,
          mode: 'ceremony',
          chrome: 'none',
        },
        {
          id: 'chromed-ceremony',
          path: '/chromed-ceremony',
          label: 'Chromed ceremony',
          section: null,
          mode: 'ceremony',
          chrome: 'shell',
          session: 'required',
        },
        {
          id: 'public-session-policy',
          path: '/public-session-policy',
          label: 'Public session policy',
          section: null,
          mode: 'public',
          chrome: 'none',
          session: 'required',
        },
      ]),
    ).toEqual([
      'route "missing-session-policy" is a ceremony without an explicit session policy',
      'route "chromed-ceremony" is a ceremony but uses shell chrome',
      'route "public-session-policy" declares a ceremony session policy outside ceremony mode',
    ]);
  });

  it('rejects duplicate route ids and paths', () => {
    expect(
      routeRegistryViolations([
        {
          id: 'duplicate',
          path: '/duplicate',
          label: 'First',
          section: null,
          mode: 'public',
          chrome: 'none',
        },
        {
          id: 'duplicate',
          path: '/duplicate',
          label: 'Second',
          section: null,
          mode: 'public',
          chrome: 'none',
        },
      ]),
    ).toEqual([
      'route id "duplicate" is declared more than once',
      'route path "/duplicate" is declared more than once',
    ]);
  });

  it('rejects a chromeless route placed in shell navigation', () => {
    expect(
      routeRegistryViolations([
        {
          id: 'chromeless-navigation',
          path: '/chromeless-navigation',
          label: 'Chromeless navigation',
          section: 'Account',
          mode: 'public',
          chrome: 'none',
        },
      ]),
    ).toContain('route "chromeless-navigation" has no chrome but appears in section "Account"');
  });
});
