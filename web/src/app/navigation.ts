/**
 * The closed list of surfaces this build serves.
 *
 * This is not a convenience table. It is the SOURCE OF TRUTH the flow
 * registry closes over (e2e/registry.ts): every surface named here must be
 * covered by a Playwright flow, and the closure check fails the build when
 * one is not. Adding a route without adding it here would defeat that, so the
 * router is built FROM this list — there is no second place to declare a
 * route.
 *
 * `section` is null for surfaces that are not navigation destinations (the
 * login page is reached by not being signed in, never by choosing it).
 */

export type RouteMode = 'public' | 'ceremony' | 'authenticated';
export type ChromeMode = 'none' | 'shell';
export type CeremonySessionPolicy = 'establish-or-reuse' | 'required';

type SurfaceBase = {
  readonly id: string;
  readonly path: string;
  readonly label: string;
  readonly section: string | null;
};

export type RouteDefinition = SurfaceBase &
  (
    | { readonly mode: 'public'; readonly chrome: 'none' }
    | {
        readonly mode: 'ceremony';
        readonly chrome: 'none';
        readonly session: CeremonySessionPolicy;
      }
    | { readonly mode: 'authenticated'; readonly chrome: 'shell' }
  );

export type RouteCandidate = SurfaceBase & {
  readonly mode: string;
  readonly chrome: string;
  readonly session?: string;
};

/** Returns every invalid or ambiguous route-policy declaration. */
export function routeRegistryViolations(routes: readonly RouteCandidate[]): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  const paths = new Set<string>();

  for (const route of routes) {
    if (ids.has(route.id)) {
      problems.push(`route id "${route.id}" is declared more than once`);
    }
    ids.add(route.id);
    if (paths.has(route.path)) {
      problems.push(`route path "${route.path}" is declared more than once`);
    }
    paths.add(route.path);

    if (route.chrome === 'none' && route.section !== null) {
      problems.push(
        `route "${route.id}" has no chrome but appears in section "${route.section}"`,
      );
    }

    switch (route.mode) {
      case 'public':
        if (route.chrome !== 'none') {
          problems.push(`route "${route.id}" is public but uses shell chrome`);
        }
        if (route.session !== undefined) {
          problems.push(
            `route "${route.id}" declares a ceremony session policy outside ceremony mode`,
          );
        }
        break;
      case 'ceremony':
        if (route.chrome !== 'none') {
          problems.push(`route "${route.id}" is a ceremony but uses shell chrome`);
        }
        if (route.session !== 'establish-or-reuse' && route.session !== 'required') {
          problems.push(
            `route "${route.id}" is a ceremony without an explicit session policy`,
          );
        }
        break;
      case 'authenticated':
        if (route.chrome !== 'shell') {
          problems.push(`route "${route.id}" is authenticated but has no shell chrome`);
        }
        if (route.session !== undefined) {
          problems.push(
            `route "${route.id}" declares a ceremony session policy outside ceremony mode`,
          );
        }
        break;
      default:
        problems.push(`route "${route.id}" has unknown access mode "${route.mode}"`);
    }
  }

  return problems;
}

function defineSurfaceRegistry<const Routes extends readonly RouteDefinition[]>(
  routes: Routes,
): Routes {
  const problems = routeRegistryViolations(routes);
  if (problems.length !== 0) {
    throw new Error(`invalid route registry:\n${problems.join('\n')}`);
  }
  return routes;
}

export const SURFACES = defineSurfaceRegistry([
  {
    id: 'login',
    path: '/login',
    label: 'Sign in',
    section: null,
    mode: 'public',
    chrome: 'none',
  },
  {
    id: 'overview',
    path: '/',
    label: 'Overview',
    section: 'Organisation',
    mode: 'authenticated',
    chrome: 'shell',
  },
  {
    id: 'projects',
    path: '/projects',
    label: 'Projects',
    section: 'Organisation',
    mode: 'authenticated',
    chrome: 'shell',
  },
  {
    id: 'remotes',
    path: '/remotes',
    label: 'Remotes',
    section: 'Organisation',
    mode: 'authenticated',
    chrome: 'shell',
  },
  // The two org-scoped chrome surfaces (#60). Their org is ROUTE DATA, not
  // chrome state: a members page and a settings page each administer ONE
  // organisation, and a path that did not name it would make a deep link, a
  // reload and a shared URL depend on which circle the rail happened to have
  // active. They still appear in the sidebar — the rail's active organisation
  // is what fills the parameter, and the entry is absent while there is no
  // organisation to fill it with, which is the honest rendering of the
  // zero-organisation state rather than a link that resolves to nothing.
  {
    id: 'members',
    path: '/orgs/:org/members',
    label: 'Members',
    section: 'Organisation',
    mode: 'authenticated',
    chrome: 'shell',
  },
  {
    id: 'org-settings',
    path: '/orgs/:org/settings',
    label: 'Organisation settings',
    section: 'Organisation',
    mode: 'authenticated',
    chrome: 'shell',
  },
  // Project settings addresses ONE project, exactly like the matrix, so no
  // static sidebar entry could know which one to mean. It is reached from the
  // project list and by deep link.
  {
    id: 'project-settings',
    path: '/orgs/:org/projects/:project/settings',
    label: 'Project settings',
    section: null,
    mode: 'authenticated',
    chrome: 'shell',
  },
  {
    id: 'instance-admin',
    path: '/instance',
    label: 'Instance administration',
    section: 'Instance',
    mode: 'authenticated',
    chrome: 'shell',
  },
  {
    id: 'settings',
    path: '/settings',
    label: 'Account & security',
    section: 'Account',
    mode: 'authenticated',
    chrome: 'shell',
  },
  // The environment matrix addresses one whole project. Like the
  // environment-scoped value surface, its org and project are route data, so
  // no static sidebar destination can point at it honestly.
  {
    id: 'matrix',
    path: '/orgs/:org/projects/:project/matrix',
    label: 'Environment matrix',
    section: null,
    mode: 'authenticated',
    chrome: 'shell',
  },
  // The revision-history drawer (#59). It is the matrix WITH its history drawer
  // open — the locked prototype's list+detail panes render over the matrix, not
  // instead of it — so the path nests under the matrix and the element is the
  // same component. `section: null` for the matrix's own reason: it addresses
  // one project, and the environment and the per-key filter are query
  // parameters, because per-key history is a filter and not a second surface.
  {
    id: 'history',
    path: '/orgs/:org/projects/:project/matrix/history',
    label: 'Revision history',
    section: null,
    mode: 'authenticated',
    chrome: 'shell',
  },
  // The reveal / copy / write-only-edit surface (#58). `section: null` because
  // it is not a navigation destination: it addresses one environment of one
  // project, so it is reached from the matrix and by deep link, never from a
  // static sidebar entry that could not know which environment to mean.
  {
    id: 'values',
    path: '/orgs/:org/projects/:project/environments/:environment/values',
    label: 'Values',
    section: null,
    mode: 'authenticated',
    chrome: 'shell',
  },
  // The machine-access surface (#67). `section: null` for the same reason
  // `values` is: it addresses ONE project, and a static sidebar entry could not
  // know which. It is reached from the project and by deep link. The
  // project-scoped navigation the prototype draws around it is the shell's own
  // ticket, not this one.
  {
    id: 'machine-access',
    path: '/orgs/:org/projects/:project/machine-access',
    label: 'Machine access',
    section: null,
    mode: 'authenticated',
    chrome: 'shell',
  },
  // Browser half of the CLI's purpose-bound reauthentication handoff. The
  // opaque transaction state stays in the query string so login can render on
  // this same route without losing it.
  {
    id: 'cli-reauth',
    path: '/reauth/cli',
    label: 'Authorize CLI',
    section: null,
    mode: 'ceremony',
    chrome: 'none',
    session: 'establish-or-reuse',
  },
  // The two workspace handoff pages. Neither is a navigation destination and
  // neither wears the chrome: they are the two ends of the handoff's front
  // channel, and both are reached by a redirect, never by choosing them.
  //
  // `workspace-approve` is served by the SERVING instance and is where the
  // popup lands — the human authenticates there with that instance's own
  // ceremonies, on that instance's own origin, which is the whole architecture
  // in one route. `workspace-callback` is served by the VIEWING instance and
  // is the same-origin return path that exists because the popup is opened
  // with `noopener` and therefore has no `window.opener` to talk back through.
  {
    id: 'workspace-approve',
    path: '/workspace/approve',
    label: 'Authorize workspace',
    section: null,
    mode: 'ceremony',
    chrome: 'none',
    session: 'establish-or-reuse',
  },
  {
    id: 'workspace-callback',
    path: '/workspace/callback',
    label: 'Returning',
    section: null,
    mode: 'public',
    chrome: 'none',
  },
]);

export type Surface = (typeof SURFACES)[number];
export type SurfaceId = Surface['id'];

type Section = {
  readonly title: string;
  readonly items: readonly Surface[];
};

/** SECTIONS is the sidebar, derived so it cannot drift from the surface list. */
export const SECTIONS: readonly Section[] = Object.entries(
  SURFACES.filter((s) => s.section !== null).reduce<Record<string, Surface[]>>((acc, surface) => {
    const key = surface.section;
    (acc[key] ??= []).push(surface);
    return acc;
  }, {}),
).map(([title, items]) => ({ title, items }));

/** Whether a route may render before the SPA has a live session. */
export function allowsAnonymousSession(surface: RouteDefinition): boolean {
  switch (surface.mode) {
    case 'public':
      return true;
    case 'ceremony':
      // Establishing ceremonies render Login in place. This preserves their
      // state-bearing URL; required-session ceremonies instead follow the
      // ordinary anonymous fallback to /login.
      return surface.session === 'establish-or-reuse';
    case 'authenticated':
      return false;
  }
}

/**
 * needsOrg reports whether a surface's path carries the active organisation.
 *
 * Derived from the path rather than declared beside it: a second flag is a
 * second thing to forget, and the parameter is the fact.
 */
export function needsOrg(surface: Surface): boolean {
  return surface.path.includes(':org');
}

export function surfaceById(id: SurfaceId): Surface {
  const found = SURFACES.find((s) => s.id === id);
  if (found === undefined) {
    throw new Error(`unknown surface ${id}`);
  }
  return found;
}
